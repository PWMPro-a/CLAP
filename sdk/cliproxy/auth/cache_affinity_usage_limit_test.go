package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCacheAffinityUsageLimitFreezeStopsConcurrentReselection(t *testing.T) {
	const (
		provider    = "codex"
		model       = "gpt-5.6-sol"
		concurrency = 64
	)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	manager.SetRetryConfig(3, time.Second, 8)
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:             true,
			MaxRetryCredentials: 2,
			MaxConcurrency:      concurrency + 1,
		},
	}})

	depleted := &Auth{ID: "depleted", Provider: provider, Status: StatusActive}
	available := &Auth{ID: "available", Provider: provider, Status: StatusActive}
	for _, auth := range []*Auth{depleted, available} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", auth.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
		manager.RefreshSchedulerEntry(auth.ID)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}

	executor := &usageLimitStormExecutor{provider: provider, depletedID: depleted.ID}
	manager.RegisterExecutor(executor)
	opts := activeCacheAffinityOptions("usage-limit-storm")
	selector.BindAuthSession("mixed", model, "cache-affinity:usage-limit-storm", depleted.ID)
	req := cliproxyexecutor.Request{Model: model, Payload: []byte(`{"model":"gpt-5.6-sol","input":"hello"}`)}

	if _, errExecute := manager.Execute(context.Background(), []string{provider}, req, opts); errExecute != nil {
		t.Fatalf("priming execute: %v", errExecute)
	}
	if got := executor.Calls(depleted.ID); got != 1 {
		t.Fatalf("depleted calls after priming = %d, want 1", got)
	}
	if got := executor.Calls(available.ID); got != 1 {
		t.Fatalf("available calls after priming = %d, want 1", got)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errExecute := manager.Execute(context.Background(), []string{provider}, req, opts)
			errCh <- errExecute
		}()
	}
	wg.Wait()
	close(errCh)
	for errExecute := range errCh {
		if errExecute != nil {
			t.Errorf("concurrent execute: %v", errExecute)
		}
	}
	if got := executor.Calls(depleted.ID); got != 1 {
		t.Fatalf("depleted auth was selected after freeze: calls=%d", got)
	}
	if got := executor.Calls(available.ID); got != concurrency+1 {
		t.Fatalf("available calls = %d, want %d", got, concurrency+1)
	}
	snapshot, ok := manager.GetByID(depleted.ID)
	if !ok || snapshot == nil {
		t.Fatal("depleted auth missing")
	}
	limits := snapshot.RuntimeLimitSnapshot(time.Now())
	if limits.LastSkipReason == "" || !limits.FrozenUntil.After(time.Now()) {
		t.Fatalf("depleted runtime limits = %#v, want active freeze", limits)
	}
}

func TestCacheAffinityShadowDoesNotFreezeUsageLimit(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true, Shadow: true},
	}})
	auth := &Auth{ID: "shadow-auth", Provider: "codex", Status: StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	retryAfter := 30 * time.Minute
	manager.MarkResult(context.Background(), Result{
		AuthID:     auth.ID,
		Provider:   auth.Provider,
		Model:      "gpt-5.6-sol",
		RetryAfter: &retryAfter,
		Error: &Error{
			HTTPStatus: http.StatusTooManyRequests,
			Message:    "usage_limit_reached",
		},
	})
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("shadow auth missing")
	}
	if limits := updated.RuntimeLimitSnapshot(time.Now()); !limits.FrozenUntil.IsZero() {
		t.Fatalf("shadow mode froze runtime selection until %v", limits.FrozenUntil)
	}
}

type usageLimitStormExecutor struct {
	provider   string
	depletedID string

	mu    sync.Mutex
	calls map[string]int
}

func (e *usageLimitStormExecutor) Identifier() string { return e.provider }

func (e *usageLimitStormExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth.ID)
	if auth.ID == e.depletedID {
		return cliproxyexecutor.Response{}, &usageLimitTestError{retryAfter: 30 * time.Minute}
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
}

func (e *usageLimitStormExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *usageLimitStormExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *usageLimitStormExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *usageLimitStormExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *usageLimitStormExecutor) record(authID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.calls == nil {
		e.calls = make(map[string]int)
	}
	e.calls[authID]++
}

func (e *usageLimitStormExecutor) Calls(authID string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[authID]
}

type usageLimitTestError struct {
	retryAfter time.Duration
}

func (e *usageLimitTestError) Error() string {
	return `{"error":{"type":"usage_limit_reached","message":"usage limit reached"}}`
}
func (e *usageLimitTestError) StatusCode() int            { return http.StatusTooManyRequests }
func (e *usageLimitTestError) RetryAfter() *time.Duration { return &e.retryAfter }
