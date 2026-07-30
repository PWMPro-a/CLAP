package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type schedulerProviderTestExecutor struct {
	provider string
}

func (e schedulerProviderTestExecutor) Identifier() string { return e.provider }

func (e schedulerProviderTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e schedulerProviderTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e schedulerProviderTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e schedulerProviderTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e schedulerProviderTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

type unauthorizedRefreshTestExecutor struct {
	schedulerProviderTestExecutor
}

func (e unauthorizedRefreshTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return nil, errors.New("token refresh failed with status 401: invalid_grant")
}

type terminalCredentialTestError struct{}

func (terminalCredentialTestError) Error() string { return "refresh_token_invalidated" }

func (terminalCredentialTestError) TerminalCredentialFailure() bool { return true }

type terminalRefreshTestExecutor struct {
	schedulerProviderTestExecutor
}

func (e terminalRefreshTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return nil, terminalCredentialTestError{}
}

type inactiveTokenTestError struct{}

func (inactiveTokenTestError) Error() string {
	return `{"error":{"message":"Personal access token owner is inactive.","code":"biscuit_baker_service_auth_credential_error_status"}}`
}

func (inactiveTokenTestError) StatusCode() int { return http.StatusForbidden }

type deactivatedWorkspaceTestError struct{}

func (deactivatedWorkspaceTestError) Error() string {
	return `{"detail":{"code":"deactivated_workspace"}}`
}

func (deactivatedWorkspaceTestError) StatusCode() int { return http.StatusPaymentRequired }

func TestManager_RefreshAuthUnauthorizedFailureStopsAutoRefreshRetry(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(unauthorizedRefreshTestExecutor{
		schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "codex"},
	})

	auth := &Auth{
		ID:       "unauthorized-refresh",
		Provider: "codex",
		Metadata: map[string]any{
			"email": "x@example.com",
		},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	manager.refreshAuth(ctx, auth.ID)

	updated, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatalf("expected auth %q after refresh", auth.ID)
	}
	if updated.LastError == nil {
		t.Fatal("expected unauthorized refresh failure to be recorded")
	}
	if got := updated.LastError.StatusCode(); got != http.StatusUnauthorized {
		t.Fatalf("LastError.StatusCode() = %d, want %d", got, http.StatusUnauthorized)
	}
	if updated.LastError.Code != "unauthorized" {
		t.Fatalf("LastError.Code = %q, want unauthorized", updated.LastError.Code)
	}
	if !updated.NextRefreshAfter.IsZero() {
		t.Fatalf("NextRefreshAfter = %s, want zero for unauthorized refresh failure", updated.NextRefreshAfter)
	}
	now := time.Now()
	if manager.shouldRefresh(updated, now) {
		t.Fatal("expected unauthorized auth to stop refresh attempts")
	}
	if _, shouldSchedule := nextRefreshCheckAt(now, updated, time.Second); shouldSchedule {
		t.Fatal("expected unauthorized auth to be removed from the auto-refresh schedule")
	}
}

func TestManager_TerminalRefreshFailureDisablesAuth(t *testing.T) {
	ctx := context.Background()
	store := &requestPrepareStore{}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(terminalRefreshTestExecutor{
		schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "codex"},
	})

	auth := &Auth{
		ID:       "terminal-refresh",
		Provider: "codex",
		Metadata: map[string]any{
			"email": "x@example.com",
		},
	}
	if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	manager.refreshAuth(ctx, auth.ID)

	updated, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatalf("expected auth %q after refresh", auth.ID)
	}
	if !updated.Disabled || updated.Status != StatusDisabled || !updated.Unavailable {
		t.Fatalf("terminal auth state = disabled:%t status:%s unavailable:%t", updated.Disabled, updated.Status, updated.Unavailable)
	}
	if got, _ := updated.Metadata["disabled"].(bool); !got {
		t.Fatalf("metadata disabled = %#v, want true", updated.Metadata["disabled"])
	}
	if updated.StatusMessage != "credential invalidated" {
		t.Fatalf("StatusMessage = %q, want credential invalidated", updated.StatusMessage)
	}
	if manager.shouldRefresh(updated, time.Now()) {
		t.Fatal("terminal auth should not remain in auto-refresh schedule")
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("terminal auth persistence calls = %d, want 1", got)
	}
	persisted := store.lastAuth()
	if persisted == nil || !persisted.Disabled || persisted.Status != StatusDisabled {
		t.Fatalf("persisted terminal auth = %#v, want disabled", persisted)
	}
}

func TestManager_InactiveTokenExecutionFailureDisablesAuth(t *testing.T) {
	ctx := context.Background()
	store := &requestPrepareStore{}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "inactive-token",
		Provider: "codex",
		Metadata: map[string]any{"email": "x@example.com"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	resultErr := resultErrorFromError(inactiveTokenTestError{})
	if resultErr.Code != terminalCredentialErrorCode {
		t.Fatalf("result error code = %q, want %q", resultErr.Code, terminalCredentialErrorCode)
	}
	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5.6-sol",
		Error:    resultErr,
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || !updated.Disabled || updated.Status != StatusDisabled {
		t.Fatalf("inactive token auth = %#v, want disabled", updated)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("inactive token persistence calls = %d, want 1", got)
	}
}

func TestManager_DeactivatedWorkspaceExecutionFailureDisablesAuth(t *testing.T) {
	ctx := context.Background()
	store := &requestPrepareStore{}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	auth := &Auth{
		ID:       "deactivated-workspace",
		Provider: "codex",
		Metadata: map[string]any{"email": "x@example.com"},
	}
	if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	resultErr := resultErrorFromError(deactivatedWorkspaceTestError{})
	manager.MarkResult(ctx, Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "gpt-5.6-sol",
		Error:    resultErr,
	})

	updated, ok := manager.GetByID(auth.ID)
	if !ok || !updated.Disabled || updated.Status != StatusDisabled {
		t.Fatalf("deactivated workspace auth = %#v, want disabled", updated)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("deactivated workspace persistence calls = %d, want 1", got)
	}
}

func TestManager_RefreshSchedulerEntry_RebuildsSupportedModelSetAfterModelRegistration(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name  string
		prime func(*Manager, *Auth) error
	}{
		{
			name: "register",
			prime: func(manager *Manager, auth *Auth) error {
				_, errRegister := manager.Register(ctx, auth)
				return errRegister
			},
		},
		{
			name: "update",
			prime: func(manager *Manager, auth *Auth) error {
				_, errRegister := manager.Register(ctx, auth)
				if errRegister != nil {
					return errRegister
				}
				updated := auth.Clone()
				updated.Metadata = map[string]any{"updated": true}
				_, errUpdate := manager.Update(ctx, updated)
				return errUpdate
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			manager := NewManager(nil, &RoundRobinSelector{}, nil)
			auth := &Auth{
				ID:       "refresh-entry-" + testCase.name,
				Provider: "gemini",
			}
			if errPrime := testCase.prime(manager, auth); errPrime != nil {
				t.Fatalf("prime auth %s: %v", testCase.name, errPrime)
			}

			registerSchedulerModels(t, "gemini", "scheduler-refresh-model", auth.ID)

			got, errPick := manager.scheduler.pickSingle(ctx, "gemini", "scheduler-refresh-model", cliproxyexecutor.Options{}, nil)
			var authErr *Error
			if !errors.As(errPick, &authErr) || authErr == nil {
				t.Fatalf("pickSingle() before refresh error = %v, want auth_not_found", errPick)
			}
			if authErr.Code != "auth_not_found" {
				t.Fatalf("pickSingle() before refresh code = %q, want %q", authErr.Code, "auth_not_found")
			}
			if got != nil {
				t.Fatalf("pickSingle() before refresh auth = %v, want nil", got)
			}

			manager.RefreshSchedulerEntry(auth.ID)

			got, errPick = manager.scheduler.pickSingle(ctx, "gemini", "scheduler-refresh-model", cliproxyexecutor.Options{}, nil)
			if errPick != nil {
				t.Fatalf("pickSingle() after refresh error = %v", errPick)
			}
			if got == nil || got.ID != auth.ID {
				t.Fatalf("pickSingle() after refresh auth = %v, want %q", got, auth.ID)
			}
		})
	}
}

func TestManager_PickNext_RebuildsSchedulerAfterModelCooldownError(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "gemini"})

	registerSchedulerModels(t, "gemini", "scheduler-cooldown-rebuild-model", "cooldown-stale-old")

	oldAuth := &Auth{
		ID:       "cooldown-stale-old",
		Provider: "gemini",
	}
	if _, errRegister := manager.Register(ctx, oldAuth); errRegister != nil {
		t.Fatalf("register old auth: %v", errRegister)
	}

	manager.MarkResult(ctx, Result{
		AuthID:   oldAuth.ID,
		Provider: "gemini",
		Model:    "scheduler-cooldown-rebuild-model",
		Success:  false,
		Error:    &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	newAuth := &Auth{
		ID:       "cooldown-stale-new",
		Provider: "gemini",
	}
	if _, errRegister := manager.Register(ctx, newAuth); errRegister != nil {
		t.Fatalf("register new auth: %v", errRegister)
	}

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(newAuth.ID, "gemini", []*registry.ModelInfo{{ID: "scheduler-cooldown-rebuild-model"}})
	t.Cleanup(func() {
		reg.UnregisterClient(newAuth.ID)
	})

	got, errPick := manager.scheduler.pickSingle(ctx, "gemini", "scheduler-cooldown-rebuild-model", cliproxyexecutor.Options{}, nil)
	var cooldownErr *modelCooldownError
	if !errors.As(errPick, &cooldownErr) {
		t.Fatalf("pickSingle() before sync error = %v, want modelCooldownError", errPick)
	}
	if got != nil {
		t.Fatalf("pickSingle() before sync auth = %v, want nil", got)
	}

	got, executor, errPick := manager.pickNext(ctx, "gemini", "scheduler-cooldown-rebuild-model", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickNext() error = %v", errPick)
	}
	if executor == nil {
		t.Fatal("pickNext() executor = nil")
	}
	if got == nil || got.ID != newAuth.ID {
		t.Fatalf("pickNext() auth = %v, want %q", got, newAuth.ID)
	}
}
