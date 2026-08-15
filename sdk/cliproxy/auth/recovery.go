package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

const (
	defaultAuthRecoveryConcurrency = 4
	authRecoveryRequestBuffer      = 256
	authRecoveryAttemptTimeout     = 30 * time.Second
	authRecoveryInitialBackoff     = 5 * time.Second
	authRecoveryMaxBackoff         = 5 * time.Minute
	authRecoveryPeerCooldown       = 30 * time.Minute
)

type authLifecycleKind string

const (
	authLifecycleInitialization authLifecycleKind = "initialization"
	authLifecycleRecovery       authLifecycleKind = "recovery"
)

var errStaleAuthLifecycle = errors.New("stale auth lifecycle generation")

type authRecoveryRequest struct {
	authID     string
	kind       authLifecycleKind
	generation string
	due        time.Time
}

type authRecoveryResult struct {
	request authRecoveryRequest
	retry   time.Duration
	stale   bool
}

type authRecoveryLoop struct {
	manager     *Manager
	concurrency int
	requests    chan authRecoveryRequest
	results     chan authRecoveryResult
	overflow    sync.Map
}

func newAuthRecoveryLoop(manager *Manager, concurrency int) *authRecoveryLoop {
	if concurrency <= 0 {
		concurrency = defaultAuthRecoveryConcurrency
	}
	return &authRecoveryLoop{
		manager:     manager,
		concurrency: concurrency,
		requests:    make(chan authRecoveryRequest, authRecoveryRequestBuffer),
		results:     make(chan authRecoveryResult, authRecoveryRequestBuffer),
	}
}

func (l *authRecoveryLoop) rebuild(now time.Time) {
	if l == nil || l.manager == nil {
		return
	}
	for _, auth := range l.manager.List() {
		request, ok := lifecycleRecoveryRequest(auth, now)
		if ok {
			l.enqueue(request)
		}
	}
}

func (l *authRecoveryLoop) enqueue(request authRecoveryRequest) {
	if l == nil || request.authID == "" || request.generation == "" {
		return
	}
	if request.due.IsZero() {
		request.due = time.Now()
	}
	select {
	case l.requests <- request:
	default:
		l.overflow.Store(request.authID, request)
	}
}

func (l *authRecoveryLoop) run(ctx context.Context) {
	if l == nil || l.manager == nil {
		return
	}
	pending := make(map[string]authRecoveryRequest)
	active := make(map[string]authRecoveryRequest)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	dispatch := func(now time.Time) {
		for len(active) < l.concurrency {
			var selected authRecoveryRequest
			for _, request := range pending {
				if request.due.After(now) {
					continue
				}
				if selected.authID == "" || request.due.Before(selected.due) {
					selected = request
				}
			}
			if selected.authID == "" {
				return
			}
			delete(pending, selected.authID)
			active[selected.authID] = selected
			go func(request authRecoveryRequest) {
				result := l.manager.runLifecycleRecovery(ctx, request)
				select {
				case <-ctx.Done():
				case l.results <- result:
				}
			}(selected)
		}
	}
	drainOverflow := func() {
		l.overflow.Range(func(key, value any) bool {
			request, ok := value.(authRecoveryRequest)
			if !ok {
				l.overflow.Delete(key)
				return true
			}
			if current, exists := pending[request.authID]; !exists || current.generation != request.generation || request.due.Before(current.due) {
				pending[request.authID] = request
			}
			l.overflow.Delete(key)
			return true
		})
	}

	for {
		drainOverflow()
		dispatch(time.Now())
		select {
		case <-ctx.Done():
			return
		case request := <-l.requests:
			if current, ok := active[request.authID]; ok && current.generation == request.generation && current.kind == request.kind {
				continue
			}
			if current, ok := pending[request.authID]; !ok || current.generation != request.generation || request.due.Before(current.due) {
				pending[request.authID] = request
			}
		case result := <-l.results:
			delete(active, result.request.authID)
			if result.retry > 0 && !result.stale {
				if current, ok := pending[result.request.authID]; !ok || current.generation == result.request.generation {
					result.request.due = time.Now().Add(result.retry)
					pending[result.request.authID] = result.request
				}
			}
		case <-ticker.C:
		}
	}
}

func (m *Manager) queueLifecycleRecovery(authID string) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return
	}
	m.mu.RLock()
	auth := m.auths[authID]
	loop := m.recoveryLoop
	var snapshot *Auth
	if auth != nil {
		snapshot = auth.Clone()
	}
	m.mu.RUnlock()
	if loop == nil || snapshot == nil {
		return
	}
	if request, ok := lifecycleRecoveryRequest(snapshot, time.Now()); ok {
		loop.enqueue(request)
	}
}

func lifecycleRecoveryRequest(auth *Auth, now time.Time) (authRecoveryRequest, bool) {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return authRecoveryRequest{}, false
	}
	if state := AuthInitializationState(auth); state == InitializationStateInitializing || state == InitializationStateRefreshingToken || state == InitializationStateRefreshingQuota || state == InitializationStateFailed {
		due := initializationMetadataTime(auth.Metadata, MetadataInitializationNextRetryAt)
		if due.IsZero() || state != InitializationStateFailed {
			due = now
		}
		return authRecoveryRequest{authID: auth.ID, kind: authLifecycleInitialization, generation: AuthInitializationGeneration(auth), due: due}, AuthInitializationGeneration(auth) != ""
	}
	if state := AuthRecoveryState(auth); state == RecoveryStateRefreshingToken || state == RecoveryStateRefreshingQuota || state == RecoveryStateFailed {
		due := initializationMetadataTime(auth.Metadata, MetadataRecoveryNextRetryAt)
		if due.IsZero() || state != RecoveryStateFailed {
			due = now
		}
		return authRecoveryRequest{authID: auth.ID, kind: authLifecycleRecovery, generation: AuthRecoveryGeneration(auth), due: due}, AuthRecoveryGeneration(auth) != ""
	}
	return authRecoveryRequest{}, false
}

func (m *Manager) runLifecycleRecovery(parent context.Context, request authRecoveryRequest) authRecoveryResult {
	result := authRecoveryResult{request: request}
	ctx, cancel := context.WithTimeout(parent, authRecoveryAttemptTimeout)
	defer cancel()

	if _, err := m.transitionLifecycle(request, true); err != nil {
		result.stale = errors.Is(err, errStaleAuthLifecycle)
		return result
	}
	refreshed, err := m.forceRefreshLifecycleToken(ctx, request)
	if err == nil {
		_, err = m.transitionLifecycle(request, false)
	}
	if err == nil {
		err = m.refreshLifecycleQuota(ctx, request, refreshed)
	}
	if err == nil {
		err = m.completeLifecycle(request)
	}
	if err == nil {
		return result
	}
	if errors.Is(err, errStaleAuthLifecycle) || errors.Is(err, context.Canceled) && parent.Err() != nil {
		result.stale = true
		return result
	}
	result.retry = m.failLifecycle(request, err)
	return result
}

func (m *Manager) transitionLifecycle(request authRecoveryRequest, tokenPhase bool) (*Auth, error) {
	now := time.Now().UTC()
	m.mu.Lock()
	auth := m.auths[request.authID]
	if !lifecycleGenerationMatches(auth, request) {
		m.mu.Unlock()
		return nil, errStaleAuthLifecycle
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if tokenPhase {
		if request.kind == authLifecycleInitialization {
			auth.Metadata[MetadataInitializationState] = string(InitializationStateRefreshingToken)
			auth.Metadata[MetadataInitializationAttempts] = AuthInitializationAttempts(auth) + 1
			auth.Metadata[MetadataInitializationUpdatedAt] = now.Format(time.RFC3339Nano)
			delete(auth.Metadata, MetadataInitializationError)
			delete(auth.Metadata, MetadataInitializationNextRetryAt)
			auth.Status = StatusRefreshingToken
			auth.StatusMessage = "refreshing token"
		} else {
			auth.Metadata[MetadataRecoveryState] = string(RecoveryStateRefreshingToken)
			auth.Metadata[MetadataRecoveryAttempts] = AuthRecoveryAttempts(auth) + 1
			auth.Metadata[MetadataRecoveryUpdatedAt] = now.Format(time.RFC3339Nano)
			delete(auth.Metadata, MetadataRecoveryError)
			delete(auth.Metadata, MetadataRecoveryNextRetryAt)
			auth.Status = StatusRecoveringToken
			auth.StatusMessage = "recovering token"
		}
	} else if request.kind == authLifecycleInitialization {
		auth.Metadata[MetadataInitializationState] = string(InitializationStateRefreshingQuota)
		auth.Metadata[MetadataInitializationUpdatedAt] = now.Format(time.RFC3339Nano)
		auth.Status = StatusRefreshingQuota
		auth.StatusMessage = "refreshing quota"
	} else {
		auth.Metadata[MetadataRecoveryState] = string(RecoveryStateRefreshingQuota)
		auth.Metadata[MetadataRecoveryUpdatedAt] = now.Format(time.RFC3339Nano)
		auth.Status = StatusRecoveringQuota
		auth.StatusMessage = "recovering quota"
	}
	auth.Unavailable = true
	auth.NextRetryAfter = time.Time{}
	auth.UpdatedAt = now
	stored := auth.Clone()
	snapshot := stored.Clone()
	m.auths[auth.ID] = stored
	m.mu.Unlock()
	m.publishLifecycleUpdate(snapshot)
	return snapshot.Clone(), nil
}

func (m *Manager) forceRefreshLifecycleToken(ctx context.Context, request authRecoveryRequest) (*Auth, error) {
	lockValue, _ := m.refreshLocks.LoadOrStore(request.authID, &authRefreshLock{})
	lock, _ := lockValue.(*authRefreshLock)
	if lock == nil {
		return nil, fmt.Errorf("auth refresh lock is unavailable")
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()

	m.mu.RLock()
	current := m.auths[request.authID]
	var exec ProviderExecutor
	if current != nil {
		exec = m.executors[executorKeyFromAuth(current)]
	}
	if !lifecycleGenerationMatches(current, request) {
		m.mu.RUnlock()
		return nil, errStaleAuthLifecycle
	}
	cloned := current.Clone()
	m.mu.RUnlock()
	if exec == nil {
		return nil, fmt.Errorf("provider executor is unavailable")
	}
	if !authHasRefreshCredential(cloned) {
		return nil, fmt.Errorf("refresh credential is unavailable")
	}
	updated, err := exec.Refresh(ctx, cloned)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = cloned
	}

	now := time.Now().UTC()
	m.mu.Lock()
	current = m.auths[request.authID]
	if !lifecycleGenerationMatches(current, request) {
		m.mu.Unlock()
		return nil, errStaleAuthLifecycle
	}
	merged := updated.Clone()
	merged.ID = current.ID
	merged.Index = current.Index
	merged.FileName = current.FileName
	merged.Storage = current.Storage
	if merged.Runtime == nil {
		merged.Runtime = current.Runtime
	}
	merged.Status = current.Status
	merged.StatusMessage = current.StatusMessage
	merged.Disabled = current.Disabled
	merged.Unavailable = true
	merged.Quota = current.Quota
	merged.LastError = cloneError(current.LastError)
	merged.NextRetryAfter = current.NextRetryAfter
	merged.ModelStates = current.ModelStates
	merged.Success = current.Success
	merged.Failed = current.Failed
	merged.recentRequests = current.recentRequests
	merged.runtimeLimits = current.runtimeLimits
	merged.LastRefreshedAt = now
	merged.NextRefreshAfter = time.Time{}
	merged.UpdatedAt = now
	merged.EnsureIndex()
	m.auths[request.authID] = merged
	snapshot := merged.Clone()
	m.mu.Unlock()
	m.publishLifecycleUpdate(snapshot)
	return snapshot.Clone(), nil
}

func (m *Manager) refreshLifecycleQuota(ctx context.Context, request authRecoveryRequest, auth *Auth) error {
	if auth == nil {
		return fmt.Errorf("refreshed auth is unavailable")
	}
	m.mu.RLock()
	exec := m.executors[executorKeyFromAuth(auth)]
	m.mu.RUnlock()
	refresher, ok := exec.(QuotaRefresher)
	if !ok || refresher == nil {
		return fmt.Errorf("provider quota refresher is unavailable")
	}
	snapshot, err := refresher.RefreshQuota(ctx, auth.Clone())
	if err != nil {
		return err
	}
	if _, accepted, errUpdate := m.UpdateCodexQuotaSnapshot(request.authID, "*", snapshot); errUpdate != nil {
		return errUpdate
	} else if !accepted {
		log.Debugf("auth lifecycle quota snapshot for %s was older than the active sample", request.authID)
	}
	return nil
}

func (m *Manager) completeLifecycle(request authRecoveryRequest) error {
	now := time.Now().UTC()
	modelsByAuth := make(map[string][]string)
	peerSnapshots := make([]*Auth, 0)
	m.mu.Lock()
	auth := m.auths[request.authID]
	if !lifecycleGenerationMatches(auth, request) {
		m.mu.Unlock()
		return errStaleAuthLifecycle
	}
	for model := range auth.ModelStates {
		modelsByAuth[auth.ID] = append(modelsByAuth[auth.ID], model)
	}
	auth.ModelStates = nil
	auth.Quota = QuotaState{}
	auth.LastError = nil
	auth.Status = StatusActive
	auth.StatusMessage = ""
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.NextRefreshAfter = time.Time{}
	auth.UpdatedAt = now
	if request.kind == authLifecycleInitialization {
		auth.Metadata[MetadataInitializationState] = string(InitializationStateReady)
		auth.Metadata[MetadataInitializationReadyAt] = now.Format(time.RFC3339Nano)
		auth.Metadata[MetadataInitializationQuotaAt] = now.Format(time.RFC3339Nano)
		delete(auth.Metadata, MetadataInitializationError)
		delete(auth.Metadata, MetadataInitializationNextRetryAt)
	} else {
		auth.Metadata[MetadataRecoveryState] = string(RecoveryStateReady)
		auth.Metadata[MetadataRecoveryReadyAt] = now.Format(time.RFC3339Nano)
		auth.Metadata[MetadataRecoveryQuotaAt] = now.Format(time.RFC3339Nano)
		delete(auth.Metadata, MetadataRecoveryError)
		delete(auth.Metadata, MetadataRecoveryNextRetryAt)
	}
	if request.kind == authLifecycleRecovery {
		for candidateID, candidate := range m.auths {
			if candidate == nil || candidateID == auth.ID || candidate.Disabled || candidate.Status == StatusDisabled || IsAuthLifecycleBlocking(candidate) || !codexSameMemberIdentity(auth, candidate) {
				continue
			}
			for model := range candidate.ModelStates {
				modelsByAuth[candidateID] = append(modelsByAuth[candidateID], model)
			}
			copyRefreshedCredentialMetadata(candidate, auth)
			candidate.ModelStates = nil
			candidate.Quota = QuotaState{}
			candidate.LastError = nil
			candidate.Status = StatusActive
			candidate.StatusMessage = ""
			candidate.Unavailable = false
			candidate.NextRetryAfter = time.Time{}
			candidate.NextRefreshAfter = time.Time{}
			candidate.LastRefreshedAt = auth.LastRefreshedAt
			candidate.UpdatedAt = now
			peerSnapshots = append(peerSnapshots, candidate.Clone())
		}
	}
	stored := auth.Clone()
	snapshot := stored.Clone()
	m.auths[auth.ID] = stored
	m.mu.Unlock()
	m.invalidateSessionAffinity(request.authID)
	for authID, models := range modelsByAuth {
		for _, model := range models {
			registry.GetGlobalRegistry().ClearModelQuotaExceeded(authID, model)
			registry.GetGlobalRegistry().ResumeClientModel(authID, model)
		}
	}
	m.persistCooldownStates(context.Background())
	m.publishLifecycleUpdate(snapshot)
	for _, peer := range peerSnapshots {
		m.invalidateSessionAffinity(peer.ID)
		m.publishLifecycleUpdate(peer)
	}
	return nil
}

func (m *Manager) failLifecycle(request authRecoveryRequest, lifecycleErr error) time.Duration {
	now := time.Now().UTC()
	m.mu.Lock()
	auth := m.auths[request.authID]
	if !lifecycleGenerationMatches(auth, request) {
		m.mu.Unlock()
		return 0
	}
	attempts := AuthRecoveryAttempts(auth)
	if request.kind == authLifecycleInitialization {
		attempts = AuthInitializationAttempts(auth)
	}
	retry := authRecoveryBackoff(attempts)
	nextRetry := now.Add(retry)
	message := strings.TrimSpace(lifecycleErr.Error())
	if request.kind == authLifecycleInitialization {
		auth.Metadata[MetadataInitializationState] = string(InitializationStateFailed)
		auth.Metadata[MetadataInitializationError] = message
		auth.Metadata[MetadataInitializationUpdatedAt] = now.Format(time.RFC3339Nano)
		auth.Metadata[MetadataInitializationNextRetryAt] = nextRetry.Format(time.RFC3339Nano)
		auth.Status = StatusInitializationFailed
		auth.StatusMessage = "initialization failed; retrying: " + message
	} else {
		auth.Metadata[MetadataRecoveryState] = string(RecoveryStateFailed)
		auth.Metadata[MetadataRecoveryError] = message
		auth.Metadata[MetadataRecoveryUpdatedAt] = now.Format(time.RFC3339Nano)
		auth.Metadata[MetadataRecoveryNextRetryAt] = nextRetry.Format(time.RFC3339Nano)
		auth.Status = StatusRecoveryFailed
		auth.StatusMessage = "recovery failed; retrying: " + message
	}
	auth.LastError = refreshErrorFromError(lifecycleErr)
	auth.Unavailable = true
	auth.NextRetryAfter = nextRetry
	auth.UpdatedAt = now
	stored := auth.Clone()
	snapshot := stored.Clone()
	m.auths[auth.ID] = stored
	m.mu.Unlock()
	m.publishLifecycleUpdate(snapshot)
	log.WithError(lifecycleErr).Warnf("auth lifecycle recovery failed for %s; retrying in %s", request.authID, retry)
	return retry
}

func (m *Manager) publishLifecycleUpdate(auth *Auth) {
	if m == nil || auth == nil {
		return
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(auth.Clone())
	}
	if err := m.persist(context.Background(), auth); err != nil {
		log.WithError(err).Warnf("persist auth lifecycle state for %s", auth.ID)
	}
	m.refreshCodexTailBurstCandidates()
	m.hook.OnAuthUpdated(context.Background(), auth.Clone())
}

func lifecycleGenerationMatches(auth *Auth, request authRecoveryRequest) bool {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled || request.generation == "" {
		return false
	}
	if request.kind == authLifecycleInitialization {
		return AuthInitializationGeneration(auth) == request.generation && IsAuthInitializationBlocking(auth)
	}
	return AuthRecoveryGeneration(auth) == request.generation && IsAuthRecoveryBlocking(auth)
}

func authRecoveryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	backoff := authRecoveryInitialBackoff
	for i := 1; i < attempts && backoff < authRecoveryMaxBackoff; i++ {
		backoff *= 2
	}
	if backoff > authRecoveryMaxBackoff {
		return authRecoveryMaxBackoff
	}
	return backoff
}

func shouldQueueRateLimitRecovery(auth *Auth, result Result) bool {
	if auth == nil || result.Success || result.Error == nil || statusCodeFromResult(result.Error) != http.StatusTooManyRequests {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") || isAgentIdentityAuth(auth) {
		return false
	}
	raw := strings.ToLower(strings.Join([]string{result.Error.Code, result.Error.Message}, " "))
	if strings.Contains(raw, "usage_limit_reached") || strings.Contains(raw, "websocket_connection_limit_reached") || strings.Contains(raw, "too many websocket") {
		return false
	}
	return strings.Contains(raw, "rate_limit_exceeded") || strings.Contains(raw, "rate limit exceeded")
}

func markRateLimitRecoveryQueuedLocked(auth *Auth, now time.Time) string {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return ""
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	generation := AuthRecoveryGeneration(auth)
	if generation == "" || !IsAuthRecoveryBlocking(auth) {
		generation = uuid.NewString()
		auth.Metadata[MetadataRecoveryAttempts] = int64(0)
	}
	auth.Metadata[MetadataRecoveryState] = string(RecoveryStateRefreshingToken)
	auth.Metadata[MetadataRecoveryGeneration] = generation
	auth.Metadata[MetadataRecoveryReason] = "rate_limit_exceeded"
	auth.Metadata[MetadataRecoveryUpdatedAt] = now.UTC().Format(time.RFC3339Nano)
	delete(auth.Metadata, MetadataRecoveryError)
	delete(auth.Metadata, MetadataRecoveryNextRetryAt)
	auth.Status = StatusRecoveringToken
	auth.StatusMessage = "rate limit exceeded; recovery queued"
	auth.Unavailable = true
	auth.NextRetryAfter = now
	auth.UpdatedAt = now
	return generation
}

func coordinateRateLimitPeerLocked(auth *Auth, model string, now time.Time) {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return
	}
	auth.Status = StatusError
	auth.StatusMessage = "rate limit exceeded; recovery coordinated"
	auth.Unavailable = true
	auth.UpdatedAt = now
	model = canonicalModelKey(model)
	if model == "" {
		auth.NextRetryAfter = now.Add(authRecoveryPeerCooldown)
		return
	}
	state := ensureModelState(auth, model)
	until := now.Add(authRecoveryPeerCooldown)
	state.Status = StatusError
	state.StatusMessage = auth.StatusMessage
	state.Unavailable = true
	state.NextRetryAfter = until
	state.Quota.Exceeded = true
	state.Quota.Reason = "rate_limit_recovery"
	state.Quota.NextRecoverAt = until
	state.UpdatedAt = now
	updateAggregatedAvailability(auth, now)
}

func copyRefreshedCredentialMetadata(target, source *Auth) {
	if target == nil || source == nil || source.Metadata == nil {
		return
	}
	if target.Metadata == nil {
		target.Metadata = make(map[string]any)
	}
	for _, key := range []string{
		"access_token", "refresh_token", "id_token", "expired", "last_refresh",
	} {
		if value, exists := source.Metadata[key]; exists {
			target.Metadata[key] = value
		}
	}
}
