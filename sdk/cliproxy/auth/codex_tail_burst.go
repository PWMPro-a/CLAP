package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	defaultCodexTailBurstRemainingRatio      = 0.02
	defaultCodexTailBurstSnapshotTTL         = 90 * time.Second
	defaultCodexTailBurstExpiryWindow        = 10 * time.Minute
	defaultCodexTailBurstFallbackConcurrency = 32
	defaultCodexTailBurstConcurrency         = 32

	codexTailBurstRequestedMetadataKey = "__cliproxy_codex_tail_burst_requested"
	codexTailBurstFallbackMetadataKey  = "__cliproxy_codex_tail_burst_fallback"
)

// CodexQuotaSnapshot is an externally sampled usage-window snapshot for a
// single Codex credential and model. It stays in process memory and is never
// fetched on the request path.
type CodexQuotaSnapshot struct {
	UsedRatio      float64   `json:"used_ratio"`
	RemainingRatio float64   `json:"remaining_ratio"`
	Window         string    `json:"window,omitempty"`
	SampledAt      time.Time `json:"sampled_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ResetAt        time.Time `json:"reset_at,omitempty"`
	Generation     uint64    `json:"generation"`
}

// CodexQuotaSnapshotUpdate is one collector-produced usage snapshot. Batching
// updates lets collectors publish a full polling round while rebuilding the
// request-time candidate index only once.
type CodexQuotaSnapshotUpdate struct {
	AuthID   string
	Model    string
	Snapshot CodexQuotaSnapshot
}

type codexQuotaSnapshotStore map[string]CodexQuotaSnapshot
type codexTailBurstCandidateIndex map[string][]string

type codexTailBurstExpiryCandidate struct {
	authID    string
	expiresAt time.Time
}

type codexTailBurstSettings struct {
	enabled                bool
	triggerRatio           float64
	snapshotTTL            time.Duration
	expiryWindow           time.Duration
	fallbackMaxConcurrency int
	maxConcurrency         int
}

func (m *Manager) codexTailBurstSettings() codexTailBurstSettings {
	settings := codexTailBurstSettings{
		triggerRatio:           1 - defaultCodexTailBurstRemainingRatio,
		snapshotTTL:            defaultCodexTailBurstSnapshotTTL,
		expiryWindow:           defaultCodexTailBurstExpiryWindow,
		fallbackMaxConcurrency: defaultCodexTailBurstFallbackConcurrency,
		maxConcurrency:         defaultCodexTailBurstConcurrency,
	}
	if m == nil {
		return settings
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return settings
	}
	tailCfg := cfg.Codex.TailBurst
	settings.enabled = tailCfg.Enabled
	if tailCfg.TriggerRemainingRatio > 0 && tailCfg.TriggerRemainingRatio < 1 {
		settings.triggerRatio = 1 - tailCfg.TriggerRemainingRatio
	} else if tailCfg.TriggerUsedRatio > 0 && tailCfg.TriggerUsedRatio < 1 {
		// Keep existing configurations compatible while the management UI writes
		// the clearer remaining-quota threshold going forward.
		settings.triggerRatio = tailCfg.TriggerUsedRatio
	}
	if parsed, errParse := time.ParseDuration(strings.TrimSpace(tailCfg.SnapshotTTL)); errParse == nil && parsed > 0 {
		settings.snapshotTTL = parsed
	}
	if parsed, errParse := time.ParseDuration(strings.TrimSpace(tailCfg.ExpiryWindow)); errParse == nil && parsed > 0 {
		settings.expiryWindow = parsed
	}
	if tailCfg.FallbackMaxConcurrency > 0 {
		settings.fallbackMaxConcurrency = tailCfg.FallbackMaxConcurrency
	}
	if tailCfg.MaxConcurrency > 0 {
		settings.maxConcurrency = tailCfg.MaxConcurrency
	}
	return settings
}

func codexTailBurstEnabledForAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if raw := runtimeLimitLookupAny(auth, "tail_burst_enabled"); raw != nil {
		if enabled, ok := parseBoolAny(raw); ok {
			return enabled
		}
	}
	if raw := runtimeLimitLookupAny(auth, "tail-burst-enabled"); raw != nil {
		if enabled, ok := parseBoolAny(raw); ok {
			return enabled
		}
	}
	return true
}

func normalizeCodexTailBurstModel(model string) string {
	model = canonicalModelKey(model)
	if model == "" {
		return "*"
	}
	return model
}

func cloneCodexQuotaSnapshots(store codexQuotaSnapshotStore) codexQuotaSnapshotStore {
	if len(store) == 0 {
		return nil
	}
	clone := make(codexQuotaSnapshotStore, len(store))
	for model, snapshot := range store {
		clone[model] = snapshot
	}
	return clone
}

// setCodexQuotaSnapshot atomically replaces a model snapshot when the supplied
// sample is newer than the one already in memory. Quota collectors may have
// overlapping polls, so an older response must not move a credential back out
// of (or into) tail drain after a newer sample has already been applied.
func (a *Auth) setCodexQuotaSnapshot(model string, snapshot CodexQuotaSnapshot) (CodexQuotaSnapshot, bool) {
	if a == nil {
		return CodexQuotaSnapshot{}, false
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return CodexQuotaSnapshot{}, false
	}
	model = normalizeCodexTailBurstModel(model)
	current, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if previous, exists := current[model]; exists && !codexQuotaSnapshotNewer(snapshot, previous) {
		return previous, false
	}
	next := cloneCodexQuotaSnapshots(current)
	if next == nil {
		next = make(codexQuotaSnapshotStore, 1)
	}
	next[model] = snapshot
	state.codexQuotaSnapshots.Store(next)
	return snapshot, true
}

func codexQuotaSnapshotNewer(next, previous CodexQuotaSnapshot) bool {
	if next.Generation > 0 && previous.Generation > 0 && next.Generation != previous.Generation {
		return next.Generation > previous.Generation
	}
	if !next.SampledAt.Equal(previous.SampledAt) {
		return next.SampledAt.After(previous.SampledAt)
	}
	// A collector may refresh the expiry for an otherwise identical sample. It
	// is safe to accept only a longer lifetime and keeps duplicate deliveries
	// idempotent.
	return next.ExpiresAt.After(previous.ExpiresAt)
}

func (a *Auth) codexQuotaSnapshot(model string, now time.Time) (CodexQuotaSnapshot, bool) {
	if a == nil {
		return CodexQuotaSnapshot{}, false
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return CodexQuotaSnapshot{}, false
	}
	store, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if len(store) == 0 {
		return CodexQuotaSnapshot{}, false
	}
	model = normalizeCodexTailBurstModel(model)
	snapshot, ok := store[model]
	if !ok && model != "*" {
		snapshot, ok = store["*"]
	}
	if !ok || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(now) {
		return CodexQuotaSnapshot{}, false
	}
	return snapshot, true
}

func (a *Auth) codexQuotaSnapshots(now time.Time) codexQuotaSnapshotStore {
	if a == nil {
		return nil
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return nil
	}
	store, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if len(store) == 0 {
		return nil
	}
	active := make(codexQuotaSnapshotStore, len(store))
	for model, snapshot := range store {
		if !snapshot.ExpiresAt.IsZero() && snapshot.ExpiresAt.After(now) {
			active[model] = snapshot
		}
	}
	return active
}

// UpdateCodexQuotaSnapshot stores one sampled quota snapshot and rebuilds the
// small in-memory tail candidate index. Callers run this from management or a
// collector, never from request execution.
func (m *Manager) UpdateCodexQuotaSnapshot(authID, model string, snapshot CodexQuotaSnapshot) (CodexQuotaSnapshot, bool, error) {
	if m == nil {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth manager is unavailable")
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth id is required")
	}
	if snapshot.UsedRatio < 0 || snapshot.UsedRatio > 1 {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("used ratio must be between 0 and 1")
	}
	now := time.Now()
	if snapshot.SampledAt.IsZero() {
		snapshot.SampledAt = now
	}
	if snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.SampledAt) {
		snapshot.ExpiresAt = snapshot.SampledAt.Add(m.codexTailBurstSettings().snapshotTTL)
	}
	snapshot.RemainingRatio = 1 - snapshot.UsedRatio

	m.mu.RLock()
	auth := m.auths[authID]
	m.mu.RUnlock()
	if auth == nil {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth %q was not found", authID)
	}
	if !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth %q is not a Codex credential", authID)
	}
	stored, accepted := auth.setCodexQuotaSnapshot(model, snapshot)
	if accepted {
		cacheSettings := m.cacheAffinitySettings()
		auth.updateQuotaPreempt(now, snapshot.ResetAt, cacheSettings.active && snapshot.UsedRatio >= cacheSettings.hardStopRatio)
		if m.scheduler != nil {
			m.scheduler.upsertAuth(auth.Clone())
		}
		m.refreshCodexTailBurstCandidates()
	}
	return stored, accepted, nil
}

// UpdateCodexQuotaSnapshots publishes a complete asynchronous collection round.
// It performs no network I/O and rebuilds the immutable request-time index once
// after all accepted updates, rather than once per credential.
func (m *Manager) UpdateCodexQuotaSnapshots(updates []CodexQuotaSnapshotUpdate) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("auth manager is unavailable")
	}
	if len(updates) == 0 {
		return 0, nil
	}
	settings := m.codexTailBurstSettings()
	now := time.Now()
	acceptedCount := 0
	updatedAuths := make(map[string]*Auth)
	for _, update := range updates {
		authID := strings.TrimSpace(update.AuthID)
		if authID == "" {
			continue
		}
		snapshot := update.Snapshot
		if snapshot.UsedRatio < 0 || snapshot.UsedRatio > 1 {
			continue
		}
		if snapshot.SampledAt.IsZero() {
			snapshot.SampledAt = now
		}
		if snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.SampledAt) {
			snapshot.ExpiresAt = snapshot.SampledAt.Add(settings.snapshotTTL)
		}
		snapshot.RemainingRatio = 1 - snapshot.UsedRatio

		m.mu.RLock()
		auth := m.auths[authID]
		m.mu.RUnlock()
		if auth == nil || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
			continue
		}
		if _, accepted := auth.setCodexQuotaSnapshot(strings.TrimSpace(update.Model), snapshot); accepted {
			cacheSettings := m.cacheAffinitySettings()
			auth.updateQuotaPreempt(now, snapshot.ResetAt, cacheSettings.active && snapshot.UsedRatio >= cacheSettings.hardStopRatio)
			updatedAuths[auth.ID] = auth
			acceptedCount++
		}
	}
	if acceptedCount > 0 {
		if m.scheduler != nil {
			for _, auth := range updatedAuths {
				m.scheduler.upsertAuth(auth.Clone())
			}
		}
		m.refreshCodexTailBurstCandidates()
	}
	return acceptedCount, nil
}

// CodexQuotaSnapshot returns the fresh quota snapshot used by tail routing.
func (m *Manager) CodexQuotaSnapshot(authID, model string) (CodexQuotaSnapshot, bool) {
	if m == nil {
		return CodexQuotaSnapshot{}, false
	}
	m.mu.RLock()
	auth := m.auths[strings.TrimSpace(authID)]
	m.mu.RUnlock()
	if auth == nil {
		return CodexQuotaSnapshot{}, false
	}
	return auth.codexQuotaSnapshot(model, time.Now())
}

// CodexQuotaSnapshots returns the active snapshots for management displays.
func (m *Manager) CodexQuotaSnapshots(authID string) map[string]CodexQuotaSnapshot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	auth := m.auths[strings.TrimSpace(authID)]
	m.mu.RUnlock()
	if auth == nil {
		return nil
	}
	snapshots := auth.codexQuotaSnapshots(time.Now())
	if len(snapshots) == 0 {
		return nil
	}
	return map[string]CodexQuotaSnapshot(snapshots)
}

func (m *Manager) codexTailBurstActive(auth *Auth, model string, now time.Time) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
		return false
	}
	if authQuotaExceeded(auth, model) {
		return false
	}
	settings := m.codexTailBurstSettings()
	if !settings.enabled || !codexTailBurstEnabledForAuth(auth) {
		return false
	}
	if expiresAt, okExpiry := authSupplyLeaseExpirationTime(auth); okExpiry && !expiresAt.After(now.Add(settings.expiryWindow)) {
		return true
	}
	snapshot, ok := auth.codexQuotaSnapshot(model, now)
	// The usage endpoint reports rounded percentages. Keep a sampled 100% in
	// the bounded tail lane until the upstream returns an actual quota error;
	// otherwise the last sub-percent capacity is stranded on every account.
	return ok && snapshot.UsedRatio >= settings.triggerRatio
}

func (m *Manager) refreshCodexTailBurstCandidates() {
	if m == nil {
		return
	}
	settings := m.codexTailBurstSettings()
	cacheSettings := m.cacheAffinitySettings()
	index := make(codexTailBurstCandidateIndex)
	expiryCandidates := make([]codexTailBurstExpiryCandidate, 0)
	now := time.Now()
	m.mu.RLock()
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		isCodex := strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex")
		normalLimit := 0
		if isCodex && cacheSettings.active {
			normalLimit = cacheSettings.maxConcurrency
		}
		auth.setCodexCacheAffinityMaxConcurrency(normalLimit)
		authTailBurstEnabled := isCodex && codexTailBurstEnabledForAuth(auth)
		if !settings.enabled || !authTailBurstEnabled || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		if expiresAt, okExpiry := authSupplyLeaseExpirationTime(auth); okExpiry {
			expiryCandidates = append(expiryCandidates, codexTailBurstExpiryCandidate{authID: auth.ID, expiresAt: expiresAt})
		}
		for model, snapshot := range auth.codexQuotaSnapshots(now) {
			if snapshot.UsedRatio < settings.triggerRatio || authQuotaExceeded(auth, model) {
				continue
			}
			key := normalizeCodexTailBurstModel(model)
			index[key] = append(index[key], auth.ID)
		}
	}
	m.mu.RUnlock()
	if settings.enabled {
		for key := range index {
			sort.Strings(index[key])
		}
		sort.Slice(expiryCandidates, func(i, j int) bool {
			if !expiryCandidates[i].expiresAt.Equal(expiryCandidates[j].expiresAt) {
				return expiryCandidates[i].expiresAt.Before(expiryCandidates[j].expiresAt)
			}
			return expiryCandidates[i].authID < expiryCandidates[j].authID
		})
	}
	m.codexTailBurstCandidates.Store(index)
	m.codexTailBurstExpiryCandidates.Store(expiryCandidates)
}

func activeCodexTailBurstExpiryCandidateCount(candidates []codexTailBurstExpiryCandidate, now time.Time, window time.Duration) int {
	if len(candidates) == 0 || window <= 0 {
		return 0
	}
	cutoff := now.Add(window)
	return sort.Search(len(candidates), func(i int) bool {
		return candidates[i].expiresAt.After(cutoff)
	})
}

func hasCodexProvider(providers []string) bool {
	for _, provider := range providers {
		if strings.EqualFold(strings.TrimSpace(provider), "codex") {
			return true
		}
	}
	return false
}

func codexTailBurstRequestEligible(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	if cliproxyexecutor.DownstreamWebsocket(ctx) || stringMetadataValue(opts.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey) != "" {
		return false
	}
	if requestPath := strings.ToLower(stringMetadataValue(opts.Metadata, cliproxyexecutor.RequestPathMetadataKey)); strings.Contains(requestPath, "/images/") {
		return false
	}
	// Existing tools, tool results and previous_response_id requests are safe to
	// route unchanged. The old body-shape gate excluded most real Codex traffic,
	// which made the switch appear enabled while requests stayed on the normal
	// scheduler. Tool injection remains independently conditional and does not
	// alter requests that already carry declarations.
	_ = req
	return true
}

func (m *Manager) withCodexTailBurstRequestMetadata(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if m == nil || !hasCodexProvider(providers) {
		return opts
	}
	settings := m.codexTailBurstSettings()
	if !settings.enabled {
		return opts
	}
	// Avoid parsing every request body when no credential is in its final quota
	// window. The candidate index is rebuilt only by config/auth/snapshot events,
	// so this is a lock-free constant-time fast path for normal traffic.
	index, _ := m.codexTailBurstCandidates.Load().(codexTailBurstCandidateIndex)
	model := normalizeCodexTailBurstModel(authSelectionModelFromOptions(opts, req.Model))
	expiryCandidates, _ := m.codexTailBurstExpiryCandidates.Load().([]codexTailBurstExpiryCandidate)
	if len(index[model]) == 0 && (model == "*" || len(index["*"]) == 0) && activeCodexTailBurstExpiryCandidateCount(expiryCandidates, time.Now(), settings.expiryWindow) == 0 {
		return opts
	}
	if !codexTailBurstRequestEligible(ctx, req, opts) {
		return opts
	}
	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[codexTailBurstRequestedMetadataKey] = true
	opts.Metadata = metadata
	return opts
}

func codexTailBurstRequested(opts cliproxyexecutor.Options) bool {
	if len(opts.Metadata) == 0 {
		return false
	}
	requested, _ := opts.Metadata[codexTailBurstRequestedMetadataKey].(bool)
	return requested
}

func withCodexTailBurstFallback(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[codexTailBurstFallbackMetadataKey] = true
	opts.Metadata = metadata
	return opts
}

func codexTailBurstFallbackRequested(opts cliproxyexecutor.Options) bool {
	if len(opts.Metadata) == 0 {
		return false
	}
	requested, _ := opts.Metadata[codexTailBurstFallbackMetadataKey].(bool)
	return requested
}

func codexTailBurstFallbackRetryBudget(configured int, opts cliproxyexecutor.Options) int {
	if !codexTailBurstRequested(opts) || configured <= 0 || configured >= 2 {
		return configured
	}
	// A burst credential consumes the first attempt. Always preserve one extra
	// credential attempt so its failure can be hidden by a healthy fallback.
	return 2
}

func withCodexTailBurstSelected(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[cliproxyexecutor.CodexTailBurstMetadataKey] = true
	opts.Metadata = metadata
	return opts
}

// codexTailBurstWarmAffinityAuth checks whether an existing session binding is
// already inside the active tail-burst pool before that pool performs normal
// round-robin selection.
//
// Normal-account bindings deliberately do not suppress tail-burst routing: the
// first successful burst request migrates the binding to the selected tail
// credential. Once migrated, this lookup keeps subsequent requests on that
// credential until its burst capacity or a hard availability gate is reached.
func (m *Manager) codexTailBurstWarmAffinityAuth(ctx context.Context, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, settings codexTailBurstSettings) (*Auth, bool) {
	if m == nil {
		return nil, false
	}
	lookup, ok := m.Selector().(sessionAffinityLookup)
	if !ok || lookup == nil {
		return nil, false
	}
	authID, ok := lookup.BoundAuthSession("codex", model, opts)
	if !ok || strings.TrimSpace(authID) == "" {
		return nil, false
	}
	if _, alreadyTried := tried[authID]; alreadyTried {
		return nil, false
	}

	var auth *Auth
	if m.newCandidateMode() && m.scheduler != nil {
		auth = m.scheduler.snapshotAuth(authID)
	} else {
		m.mu.RLock()
		auth = m.auths[authID]
		if auth != nil {
			auth = auth.Clone()
		}
		m.mu.RUnlock()
	}
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
		return nil, false
	}
	if !authSelectionEligibilityForRequest(ctx, opts).allows(auth) || !m.authSupportsRouteModel(registry.GetGlobalRegistry(), auth, model) {
		return nil, false
	}

	now := time.Now()
	if IsAuthLifecycleBlocking(auth) || authQuotaExceeded(auth, model) || runtimeAuthHasUsageLimitFreeze(auth, now) {
		return nil, false
	}
	cacheSettings := m.cacheAffinitySettings()
	if cacheSettings.active {
		if snapshot, okSnapshot := auth.codexQuotaSnapshot(model, now); okSnapshot && snapshot.UsedRatio >= cacheSettings.hardStopRatio {
			return nil, false
		}
	}
	if !m.codexTailBurstActive(auth, model, now) {
		return nil, false
	}
	auth.tailBurstMaxConcurrency = settings.maxConcurrency
	if blocked, _, _ := isAuthBlockedForModelWithTailBurst(auth, model, now, true); blocked {
		return nil, false
	}
	return auth.Clone(), true
}

func (m *Manager) pickCodexTailBurstAuth(ctx context.Context, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, bool) {
	if m == nil || m.HomeEnabled() || !codexTailBurstRequested(opts) || pinnedAuthIDFromMetadata(opts.Metadata) != "" || disallowFreeAuthFromMetadata(opts.Metadata) {
		return nil, nil, false
	}
	settings := m.codexTailBurstSettings()
	if warmAuth, protectWarm := m.codexTailBurstWarmAffinityAuth(ctx, model, opts, tried, settings); protectWarm {
		executor, okExecutor := m.Executor("codex")
		if !okExecutor || executor == nil {
			return nil, nil, false
		}
		return warmAuth, executor, true
	}
	index, _ := m.codexTailBurstCandidates.Load().(codexTailBurstCandidateIndex)
	key := normalizeCodexTailBurstModel(model)
	candidateIDs := make([]string, 0, len(index[key])+len(index["*"]))
	seen := make(map[string]struct{}, len(index[key])+len(index["*"]))
	appendCandidate := func(authID string) {
		if authID == "" {
			return
		}
		if _, exists := seen[authID]; exists {
			return
		}
		seen[authID] = struct{}{}
		candidateIDs = append(candidateIDs, authID)
	}
	expiryCandidates, _ := m.codexTailBurstExpiryCandidates.Load().([]codexTailBurstExpiryCandidate)
	expiryCount := activeCodexTailBurstExpiryCandidateCount(expiryCandidates, time.Now(), settings.expiryWindow)
	for i := 0; i < expiryCount; i++ {
		appendCandidate(expiryCandidates[i].authID)
	}
	for _, authID := range index[key] {
		appendCandidate(authID)
	}
	if key != "*" {
		for _, authID := range index["*"] {
			appendCandidate(authID)
		}
	}
	if len(candidateIDs) == 0 {
		return nil, nil, false
	}
	start := int(m.codexTailBurstSequence.Add(1)-1) % len(candidateIDs)
	now := time.Now()
	registryRef := registry.GetGlobalRegistry()
	eligibility := authSelectionEligibilityForRequest(ctx, opts)

	executor, okExecutor := m.Executor("codex")
	if !okExecutor || executor == nil {
		return nil, nil, false
	}
	for offset := 0; offset < len(candidateIDs); offset++ {
		authID := candidateIDs[(start+offset)%len(candidateIDs)]
		if _, alreadyTried := tried[authID]; alreadyTried {
			continue
		}
		var auth *Auth
		if m.newCandidateMode() && m.scheduler != nil {
			auth = m.scheduler.snapshotAuth(authID)
		} else {
			m.mu.RLock()
			auth = m.auths[authID]
			if auth != nil {
				auth = auth.Clone()
			}
			m.mu.RUnlock()
		}
		if auth == nil || auth.Disabled || !eligibility.allows(auth) || !m.authSupportsRouteModel(registryRef, auth, model) || !m.codexTailBurstActive(auth, model, now) {
			continue
		}
		auth.tailBurstMaxConcurrency = settings.maxConcurrency
		if blocked, _, _ := isAuthBlockedForModelWithTailBurst(auth, model, now, true); blocked {
			continue
		}
		return auth.Clone(), executor, true
	}
	return nil, nil, false
}

type codexTailBurstHealthScore struct {
	auth               *Auth
	successRate        float64
	recentSamples      int64
	recentSuccesses    int64
	currentConcurrency int
	tailBurstActive    bool
}

func recentCodexHealthScore(auth *Auth, now time.Time) (successRate float64, samples, successes int64) {
	const (
		windowBuckets = 6
		priorSuccess  = 8.0
		priorFailure  = 2.0
	)
	if auth == nil {
		return priorSuccess / (priorSuccess + priorFailure), 0, 0
	}
	currentBucketID := recentRequestBucketID(now)
	weightedSuccess := 0.0
	weightedFailure := 0.0
	for age := 0; age < windowBuckets; age++ {
		bucketID := currentBucketID - int64(age)
		bucket := auth.recentRequests.buckets[recentRequestBucketIndex(bucketID)]
		if bucket.bucketID != bucketID {
			continue
		}
		weight := float64(windowBuckets - age)
		weightedSuccess += float64(bucket.success) * weight
		weightedFailure += float64(bucket.failed) * weight
		successes += bucket.success
		samples += bucket.success + bucket.failed
	}
	successRate = (weightedSuccess + priorSuccess) / (weightedSuccess + weightedFailure + priorSuccess + priorFailure)
	return successRate, samples, successes
}

func (m *Manager) pickCodexTailBurstFallbackAuth(ctx context.Context, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, bool) {
	if m == nil || m.HomeEnabled() || !codexTailBurstFallbackRequested(opts) || pinnedAuthIDFromMetadata(opts.Metadata) != "" || disallowFreeAuthFromMetadata(opts.Metadata) {
		return nil, nil, false
	}
	executor, okExecutor := m.Executor("codex")
	if !okExecutor || executor == nil {
		return nil, nil, false
	}

	var candidates []*Auth
	if m.newCandidateMode() && m.scheduler != nil {
		candidates = m.scheduler.snapshotCandidates([]string{"codex"}, model)
	} else {
		m.mu.RLock()
		candidates = make([]*Auth, 0, len(m.auths))
		for _, auth := range m.auths {
			if auth != nil && strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
				candidates = append(candidates, auth.Clone())
			}
		}
		m.mu.RUnlock()
	}

	now := time.Now()
	settings := m.codexTailBurstSettings()
	cacheSettings := m.cacheAffinitySettings()
	registryRef := registry.GetGlobalRegistry()
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	scores := make([]codexTailBurstHealthScore, 0, len(candidates))
	for _, auth := range candidates {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled || !eligibility.allows(auth) {
			continue
		}
		if _, alreadyTried := tried[auth.ID]; alreadyTried {
			continue
		}
		if !m.authSupportsRouteModel(registryRef, auth, model) || authQuotaExceeded(auth, model) {
			continue
		}
		if cacheSettings.active {
			if snapshot, okSnapshot := auth.codexQuotaSnapshot(model, now); okSnapshot && snapshot.UsedRatio >= cacheSettings.hardStopRatio {
				continue
			}
		}
		auth.tailBurstFallbackMaxConcurrency = settings.fallbackMaxConcurrency
		if blocked, _, _ := isAuthBlockedForModel(auth, model, now); blocked {
			continue
		}
		successRate, samples, successes := recentCodexHealthScore(auth, now)
		scores = append(scores, codexTailBurstHealthScore{
			auth:               auth,
			successRate:        successRate,
			recentSamples:      samples,
			recentSuccesses:    successes,
			currentConcurrency: auth.RuntimeLimitSnapshot(now).CurrentConcurrency,
			tailBurstActive:    m.codexTailBurstActive(auth, model, now),
		})
	}
	if len(scores) == 0 {
		return nil, nil, false
	}
	sort.SliceStable(scores, func(i, j int) bool {
		left, right := scores[i], scores[j]
		if left.tailBurstActive != right.tailBurstActive {
			return !left.tailBurstActive
		}
		if left.currentConcurrency != right.currentConcurrency {
			return left.currentConcurrency < right.currentConcurrency
		}
		if left.successRate != right.successRate {
			return left.successRate > right.successRate
		}
		if left.recentSamples != right.recentSamples {
			return left.recentSamples > right.recentSamples
		}
		if left.recentSuccesses != right.recentSuccesses {
			return left.recentSuccesses > right.recentSuccesses
		}
		return left.auth.ID < right.auth.ID
	})
	selected := scores[0].auth.Clone()
	selected.tailBurstFallbackMaxConcurrency = settings.fallbackMaxConcurrency
	return selected, executor, true
}
