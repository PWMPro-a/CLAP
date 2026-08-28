package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type recoveryStateHook struct {
	NoopHook
	mu     sync.Mutex
	states []RecoveryState
}

func (h *recoveryStateHook) OnAuthUpdated(_ context.Context, auth *Auth) {
	if auth == nil {
		return
	}
	state := AuthRecoveryState(auth)
	if state == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.states) == 0 || h.states[len(h.states)-1] != state {
		h.states = append(h.states, state)
	}
}

func (h *recoveryStateHook) snapshot() []RecoveryState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]RecoveryState(nil), h.states...)
}

type recoveryTestExecutor struct {
	refreshStarted chan struct{}
	refreshRelease chan struct{}
	refreshErr     error
	quotaErr       error
	refreshCalls   atomic.Int32
	quotaCalls     atomic.Int32
	probeCalls     atomic.Int32
	quotaToken     atomic.Value
	probeToken     atomic.Value
}

func (e *recoveryTestExecutor) Identifier() string { return "codex" }

func (e *recoveryTestExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *recoveryTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *recoveryTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	e.refreshCalls.Add(1)
	if e.refreshStarted != nil {
		select {
		case e.refreshStarted <- struct{}{}:
		default:
		}
	}
	if e.refreshRelease != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.refreshRelease:
		}
	}
	if e.refreshErr != nil {
		return nil, e.refreshErr
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "new-access-token"
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339Nano)
	return auth, nil
}

func (e *recoveryTestExecutor) RefreshQuota(_ context.Context, auth *Auth) (CodexQuotaSnapshot, error) {
	e.quotaCalls.Add(1)
	if e.quotaErr != nil {
		return CodexQuotaSnapshot{}, e.quotaErr
	}
	if auth != nil && auth.Metadata != nil {
		e.quotaToken.Store(auth.Metadata["access_token"])
	}
	now := time.Now().UTC()
	return CodexQuotaSnapshot{UsedRatio: 0.25, SampledAt: now, ExpiresAt: now.Add(time.Minute), AccessTokenSHA256: AccessTokenSHA256(auth)}, nil
}

func (e *recoveryTestExecutor) ProbeUsage(_ context.Context, auth *Auth, evidence CodexQuotaSnapshot) error {
	e.probeCalls.Add(1)
	if auth != nil && auth.Metadata != nil {
		e.probeToken.Store(auth.Metadata["access_token"])
	}
	if auth == nil || evidence.AccessTokenSHA256 != AccessTokenSHA256(auth) {
		return errors.New("probe evidence mismatch")
	}
	return nil
}

func TestRateLimitProbeFailureDoesNotDisableCredential(t *testing.T) {
	executor := &recoveryTestExecutor{quotaErr: terminalCredentialTestError{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "probe-failure",
		Provider: "codex",
		Status:   StatusRecoveringToken,
		Metadata: map[string]any{
			"type":                     "codex",
			"access_token":             "existing-access-token",
			"refresh_token":            "refresh-token",
			MetadataRecoveryState:      string(RecoveryStateRefreshingToken),
			MetadataRecoveryGeneration: "probe-generation",
			MetadataRecoveryReason:     "rate_limit_exceeded",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	result := manager.runLifecycleRecovery(context.Background(), authRecoveryRequest{
		authID:            auth.ID,
		kind:              authLifecycleRecovery,
		generation:        "probe-generation",
		rateLimitRecovery: true,
	})
	if result.stale || result.retry != authRecoveryInitialBackoff {
		t.Fatalf("probe failure result = %+v, want initial retry %s", result, authRecoveryInitialBackoff)
	}
	updated, _ := manager.GetByID(auth.ID)
	if updated.Disabled || updated.Status == StatusDisabled {
		t.Fatalf("probe failure disabled credential: %+v", updated)
	}
	if got := AuthRecoveryAttempts(updated); got != 1 {
		t.Fatalf("recovery attempts = %d, want 1", got)
	}
	if got := executor.refreshCalls.Load(); got != 0 {
		t.Fatalf("refresh calls = %d, want 0 for a 429 recovery", got)
	}
	if got := executor.probeCalls.Load(); got != 0 {
		t.Fatalf("probe calls = %d, want 0 after quota failure", got)
	}

	result = manager.runLifecycleRecovery(context.Background(), authRecoveryRequest{
		authID:            auth.ID,
		kind:              authLifecycleRecovery,
		generation:        "probe-generation",
		rateLimitRecovery: true,
	})
	if result.stale || result.retry != 2*authRecoveryInitialBackoff {
		t.Fatalf("second probe failure result = %+v, want exponential retry %s", result, 2*authRecoveryInitialBackoff)
	}
	updated, _ = manager.GetByID(auth.ID)
	if got := AuthRecoveryAttempts(updated); got != 2 {
		t.Fatalf("recovery attempts = %d, want 2", got)
	}
}

func (e *recoveryTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *recoveryTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestLifecycleTerminalRefreshFailureDisablesCredentialWithoutRetry(t *testing.T) {
	executor := &recoveryTestExecutor{refreshErr: terminalCredentialTestError{}}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "terminal-initialization",
		Provider: "codex",
		Status:   StatusInitializing,
		Metadata: map[string]any{
			"type":                           "codex",
			"email":                          "terminal@example.com",
			"refresh_token":                  "invalid-refresh-token",
			MetadataInitializationState:      string(InitializationStateInitializing),
			MetadataInitializationGeneration: "generation-terminal",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}

	request := authRecoveryRequest{
		authID:     auth.ID,
		kind:       authLifecycleInitialization,
		generation: "generation-terminal",
	}
	result := manager.runLifecycleRecovery(context.Background(), request)
	if result.retry != 0 || result.stale {
		t.Fatalf("terminal result = %+v, want no retry", result)
	}
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("terminal credential disappeared")
	}
	if !updated.Disabled || updated.Status != StatusDisabled || !updated.Unavailable {
		t.Fatalf("terminal lifecycle state = disabled:%t status:%s unavailable:%t", updated.Disabled, updated.Status, updated.Unavailable)
	}
	if updated.StatusMessage != "credential invalidated" || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("terminal lifecycle status = %q retry=%v", updated.StatusMessage, updated.NextRetryAfter)
	}
	if _, queued := lifecycleRecoveryRequest(updated, time.Now()); queued {
		t.Fatal("terminal lifecycle credential remained in the recovery queue")
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
}

func TestManagerRateLimitExceededQueuesRecoveryAndRestoresAuth(t *testing.T) {
	executor := &recoveryTestExecutor{
		refreshStarted: make(chan struct{}, 1),
	}
	hook := &recoveryStateHook{}
	manager := NewManager(nil, &RoundRobinSelector{}, hook)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:              "codex-recovery",
		Provider:        "codex",
		Status:          StatusActive,
		LastRefreshedAt: time.Now(),
		Metadata: map[string]any{
			"type":          "codex",
			"access_token":  "old-access-token",
			"refresh_token": "refresh-token",
			"expired":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.StartAutoRefresh(ctx, time.Hour)
	defer manager.StopAutoRefresh()

	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    "gpt-5.3-codex",
		Error: &Error{
			Code:       "retry_after",
			Message:    "Rate limit exceeded",
			HTTPStatus: http.StatusTooManyRequests,
		},
	})

	// Runtime 429 recovery must remain in cooldown and must not rotate the
	// refresh token while the upstream Retry-After window is active.
	select {
	case <-executor.refreshStarted:
		t.Fatal("429 recovery unexpectedly started a token refresh")
	case <-time.After(250 * time.Millisecond):
	}
	blocked, ok := manager.GetByID(auth.ID)
	if !ok || blocked.Status != StatusProbingUsage || !blocked.Unavailable || !IsAuthRecoveryBlocking(blocked) {
		t.Fatalf("blocked auth = %+v", blocked)
	}
	if _, err := manager.pickNextIndexed(context.Background(), "codex", []string{"codex"}, "gpt-5.3-codex", cliproxyexecutor.Options{}, nil); err == nil {
		t.Fatal("recovering auth remained schedulable")
	}

	// Run the due probe directly in the test; the production recovery loop
	// dispatches the same request once the cooldown deadline is reached.
	blocked, _ = manager.GetByID(auth.ID)
	result := manager.runLifecycleRecovery(context.Background(), authRecoveryRequest{
		authID:            auth.ID,
		kind:              authLifecycleRecovery,
		generation:        AuthRecoveryGeneration(blocked),
		rateLimitRecovery: true,
	})
	if result.stale || result.retry != 0 {
		t.Fatalf("probe result = %+v", result)
	}
	eventuallyAuth(t, manager, auth.ID, func(current *Auth) bool {
		return current.Status == StatusActive && !current.Unavailable && AuthRecoveryState(current) == RecoveryStateReady
	})
	if got := executor.refreshCalls.Load(); got != 0 {
		t.Fatalf("refresh calls = %d, want 0 after cooldown", got)
	}
	if got := executor.quotaCalls.Load(); got != 1 {
		t.Fatalf("quota calls = %d, want 1", got)
	}
	if got, _ := executor.quotaToken.Load().(string); got != "old-access-token" {
		t.Fatalf("quota token = %q, want existing access token", got)
	}
	if got := executor.probeCalls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	if got, _ := executor.probeToken.Load().(string); got != "old-access-token" {
		t.Fatalf("probe token = %q, want existing access token", got)
	}
	wantStates := []RecoveryState{RecoveryStateProbingUsage, RecoveryStateReady}
	gotStates := hook.snapshot()
	if len(gotStates) != len(wantStates) {
		t.Fatalf("recovery states = %v, want %v", gotStates, wantStates)
	}
	for i := range wantStates {
		if gotStates[i] != wantStates[i] {
			t.Fatalf("recovery states = %v, want %v", gotStates, wantStates)
		}
	}
	restored, _ := manager.GetByID(auth.ID)
	if len(restored.ModelStates) != 0 || restored.LastError != nil || restored.Quota.Exceeded {
		t.Fatalf("recovery did not clear cooldown state: %+v", restored)
	}
	now := time.Now()
	runtimeSnapshot := restored.RuntimeLimitSnapshot(now)
	if runtimeSnapshot.LastSkipReason != runtimeSkipReasonUpstreamRateLimit ||
		runtimeSnapshot.RateLimitedUntil.Before(now.Add(10*time.Second)) ||
		!runtimeSnapshot.FrozenUntil.Equal(runtimeSnapshot.RateLimitedUntil) {
		t.Fatalf("recovery did not retain the upstream Retry-After guard: %#v", runtimeSnapshot)
	}
	if blocked, reason, retryAt := runtimeAuthBlockedForModelWithTailBurst(restored, "gpt-5.4", now, false); !blocked || reason != blockReasonCooldown || retryAt.Before(now.Add(10*time.Second)) {
		t.Fatalf("recovered credential ignored Retry-After: blocked=%t reason=%v retryAt=%v", blocked, reason, retryAt)
	}
}

func TestRateLimitRecoveryClassificationExcludesQuotaAndWebsocketLimits(t *testing.T) {
	auth := &Auth{Provider: "codex", Metadata: map[string]any{"type": "codex"}}
	for _, testCase := range []struct {
		name       string
		code       string
		message    string
		httpStatus int
		want       bool
	}{
		{name: "retry after code", code: "retry_after", message: "Rate limit exceeded", httpStatus: http.StatusTooManyRequests, want: true},
		{name: "rate limit code", code: "rate_limit", httpStatus: http.StatusTooManyRequests, want: true},
		{name: "rate limited code", code: "rate_limited", httpStatus: http.StatusTooManyRequests, want: true},
		{name: "too many requests code", code: "too_many_requests", httpStatus: http.StatusTooManyRequests, want: true},
		{name: "legacy rate limit", message: "rate_limit_exceeded: Rate limit exceeded", httpStatus: http.StatusTooManyRequests, want: true},
		{name: "quota", code: "retry_after", message: "usage_limit_reached", httpStatus: http.StatusTooManyRequests, want: false},
		{name: "weekly quota", code: "rate_limit", message: "weekly quota reached", httpStatus: http.StatusTooManyRequests, want: false},
		{name: "quota json", code: "rate_limit", message: `{"error":"quota"}`, httpStatus: http.StatusTooManyRequests, want: false},
		{name: "websocket", code: "retry_after", message: "websocket_connection_limit_reached", httpStatus: http.StatusTooManyRequests, want: false},
		{name: "generic 429", message: "too many requests", httpStatus: http.StatusTooManyRequests, want: false},
		{name: "marker without 429", code: "retry_after", message: "Rate limit exceeded", httpStatus: http.StatusBadRequest, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := shouldQueueRateLimitRecovery(auth, Result{Error: &Error{
				Code:       testCase.code,
				HTTPStatus: testCase.httpStatus,
				Message:    testCase.message,
			}})
			if got != testCase.want {
				t.Fatalf("shouldQueueRateLimitRecovery() = %v, want %v", got, testCase.want)
			}
		})
	}

	agent := &Auth{Provider: "codex", Metadata: map[string]any{
		"type":             "codex",
		"agent_runtime_id": "agent-1",
	}}
	if shouldQueueRateLimitRecovery(agent, Result{Error: &Error{
		Code:       "retry_after",
		Message:    "Rate limit exceeded",
		HTTPStatus: http.StatusTooManyRequests,
	}}) {
		t.Fatal("agent identity entered OAuth rate-limit recovery")
	}
}

func TestRateLimitRecoveryProbesCanonicalCredentialOnce(t *testing.T) {
	executor := &recoveryTestExecutor{}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	now := time.Now()
	for _, id := range []string{"canonical-a", "canonical-b"} {
		_, err := manager.Register(context.Background(), &Auth{
			ID:              id,
			Provider:        "codex",
			Status:          StatusActive,
			LastRefreshedAt: now,
			Metadata: map[string]any{
				"type":               "codex",
				"email":              "same-member@example.com",
				"chatgpt_account_id": "workspace-1",
				"access_token":       "shared-old-access",
				"refresh_token":      "shared-refresh",
				"expired":            now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
			},
		})
		if err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.StartAutoRefresh(ctx, time.Hour)
	defer manager.StopAutoRefresh()
	manager.MarkResult(context.Background(), Result{
		AuthID: "canonical-a",
		Model:  "gpt-5.3-codex",
		Error:  &Error{Code: "rate_limit_exceeded", Message: "Rate limit exceeded", HTTPStatus: http.StatusTooManyRequests},
	})

	// Run the due probe directly in the test; the production loop waits for
	// the account-wide cooldown before dispatching it.
	live, _ := manager.GetByID("canonical-a")
	result := manager.runLifecycleRecovery(context.Background(), authRecoveryRequest{
		authID:            "canonical-a",
		kind:              authLifecycleRecovery,
		generation:        AuthRecoveryGeneration(live),
		rateLimitRecovery: true,
	})
	if result.stale || result.retry != 0 {
		t.Fatalf("canonical probe result = %+v", result)
	}

	for _, id := range []string{"canonical-a", "canonical-b"} {
		eventuallyAuth(t, manager, id, func(current *Auth) bool {
			token, _ := current.Metadata["access_token"].(string)
			return current.Status == StatusActive && !current.Unavailable && token == "shared-old-access"
		})
		restored, _ := manager.GetByID(id)
		now := time.Now()
		if blocked, reason, retryAt := runtimeAuthBlockedForModelWithTailBurst(restored, "gpt-5.4", now, false); !blocked || reason != blockReasonCooldown || !retryAt.After(now) {
			t.Fatalf("canonical peer %s did not retain Retry-After: blocked=%t reason=%v retryAt=%v", id, blocked, reason, retryAt)
		}
	}
	if got := executor.refreshCalls.Load(); got != 0 {
		t.Fatalf("canonical refresh calls = %d, want 0 after cooldown", got)
	}
	if got := executor.quotaCalls.Load(); got != 1 {
		t.Fatalf("canonical quota calls = %d, want 1 usage probe", got)
	}
	if got := executor.probeCalls.Load(); got != 1 {
		t.Fatalf("canonical probe calls = %d, want 1", got)
	}
}

func TestLifecycleRefreshGenerationGuardPreservesReimport(t *testing.T) {
	executor := &recoveryTestExecutor{
		refreshStarted: make(chan struct{}, 1),
		refreshRelease: make(chan struct{}),
	}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "team-reimport",
		Provider: "codex",
		Status:   StatusInitializing,
		Metadata: map[string]any{
			"type":                           "codex",
			"access_token":                   "old-import-token",
			"refresh_token":                  "refresh-token",
			MetadataInitializationState:      string(InitializationStateInitializing),
			MetadataInitializationGeneration: "generation-old",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	request := authRecoveryRequest{authID: auth.ID, kind: authLifecycleInitialization, generation: "generation-old"}
	resultCh := make(chan error, 1)
	go func() {
		_, err := manager.forceRefreshLifecycleToken(context.Background(), request)
		resultCh <- err
	}()

	select {
	case <-executor.refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("initialization refresh did not start")
	}
	reimported, _ := manager.GetByID(auth.ID)
	reimported.Metadata["access_token"] = "reimport-token"
	reimported.Metadata[MetadataInitializationGeneration] = "generation-new"
	reimported.Metadata[MetadataInitializationState] = string(InitializationStateInitializing)
	reimported.Status = StatusInitializing
	reimported.Unavailable = true
	if _, err := manager.Update(context.Background(), reimported); err != nil {
		t.Fatalf("Update reimport: %v", err)
	}
	close(executor.refreshRelease)
	select {
	case err := <-resultCh:
		if err != errStaleAuthLifecycle {
			t.Fatalf("old refresh error = %v, want stale generation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old refresh did not finish")
	}
	current, _ := manager.GetByID(auth.ID)
	if got, _ := current.Metadata["access_token"].(string); got != "reimport-token" {
		t.Fatalf("access token = %q, old generation overwrote reimport", got)
	}
}

func eventuallyAuth(t *testing.T, manager *Manager, authID string, predicate func(*Auth) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if auth, ok := manager.GetByID(authID); ok && predicate(auth) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	auth, _ := manager.GetByID(authID)
	t.Fatalf("auth condition was not met: %+v", auth)
}
