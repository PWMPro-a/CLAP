package auth

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type recoveryTestExecutor struct {
	refreshStarted chan struct{}
	refreshRelease chan struct{}
	refreshCalls   atomic.Int32
	quotaCalls     atomic.Int32
	quotaToken     atomic.Value
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
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "new-access-token"
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339Nano)
	return auth, nil
}

func (e *recoveryTestExecutor) RefreshQuota(_ context.Context, auth *Auth) (CodexQuotaSnapshot, error) {
	e.quotaCalls.Add(1)
	if auth != nil && auth.Metadata != nil {
		e.quotaToken.Store(auth.Metadata["access_token"])
	}
	now := time.Now().UTC()
	return CodexQuotaSnapshot{UsedRatio: 0.25, SampledAt: now, ExpiresAt: now.Add(time.Minute)}, nil
}

func (e *recoveryTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *recoveryTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManagerRateLimitExceededQueuesRecoveryAndRestoresAuth(t *testing.T) {
	executor := &recoveryTestExecutor{
		refreshStarted: make(chan struct{}, 1),
		refreshRelease: make(chan struct{}),
	}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
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

	select {
	case <-executor.refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery token refresh did not start")
	}
	blocked, ok := manager.GetByID(auth.ID)
	if !ok || blocked.Status != StatusRecoveringToken || !blocked.Unavailable || !IsAuthRecoveryBlocking(blocked) {
		t.Fatalf("blocked auth = %+v", blocked)
	}
	if _, err := manager.pickNextIndexed(context.Background(), "codex", []string{"codex"}, "gpt-5.3-codex", cliproxyexecutor.Options{}, nil); err == nil {
		t.Fatal("recovering auth remained schedulable")
	}

	close(executor.refreshRelease)
	eventuallyAuth(t, manager, auth.ID, func(current *Auth) bool {
		return current.Status == StatusActive && !current.Unavailable && AuthRecoveryState(current) == RecoveryStateReady
	})
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
	if got := executor.quotaCalls.Load(); got != 1 {
		t.Fatalf("quota calls = %d, want 1", got)
	}
	if got, _ := executor.quotaToken.Load().(string); got != "new-access-token" {
		t.Fatalf("quota token = %q, want refreshed token", got)
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

func TestRateLimitRecoveryRefreshesCanonicalCredentialOnce(t *testing.T) {
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

	for _, id := range []string{"canonical-a", "canonical-b"} {
		eventuallyAuth(t, manager, id, func(current *Auth) bool {
			token, _ := current.Metadata["access_token"].(string)
			return current.Status == StatusActive && !current.Unavailable && token == "new-access-token"
		})
		restored, _ := manager.GetByID(id)
		now := time.Now()
		if blocked, reason, retryAt := runtimeAuthBlockedForModelWithTailBurst(restored, "gpt-5.4", now, false); !blocked || reason != blockReasonCooldown || !retryAt.After(now) {
			t.Fatalf("canonical peer %s did not retain Retry-After: blocked=%t reason=%v retryAt=%v", id, blocked, reason, retryAt)
		}
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("canonical refresh calls = %d, want 1", got)
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
