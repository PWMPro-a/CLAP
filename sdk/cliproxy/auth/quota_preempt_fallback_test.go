package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const quotaFallbackTestModel = ""

func newQuotaPreemptFallbackManager(t *testing.T, executor *runtimeLimitTestExecutor, auths ...*Auth) *Manager {
	t.Helper()
	mgr := newRuntimeLimitManager(t, executor, auths...)
	mgr.SetConfig(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:                true,
			QuotaPreemptUsedRatio:  0.97,
			QuotaHardStopUsedRatio: 0.99,
		},
	}})
	mgr.SetSelector(NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:               &FillFirstSelector{},
		CacheAffinityEnabled:   true,
		QuotaPreemptUsedRatio:  0.97,
		QuotaHardStopUsedRatio: 0.99,
	}))
	return mgr
}

func freezeQuotaFallbackAuth(t *testing.T, mgr *Manager, authID string, usedRatio float64, now time.Time) {
	t.Helper()
	_, accepted, err := mgr.UpdateCodexQuotaSnapshot(authID, quotaFallbackTestModel, CodexQuotaSnapshot{
		UsedRatio: usedRatio,
		SampledAt: now,
		ExpiresAt: now.Add(time.Hour),
		ResetAt:   now.Add(time.Hour),
	})
	if err != nil || !accepted {
		t.Fatalf("UpdateCodexQuotaSnapshot(%s) = accepted:%t err:%v", authID, accepted, err)
	}
}

func TestQuotaPreemptFallbackSelectsLowestFreshSnapshotAndExecutes(t *testing.T) {
	now := time.Now()
	executor := &runtimeLimitTestExecutor{}
	mgr := newQuotaPreemptFallbackManager(t, executor,
		&Auth{ID: "hot", Provider: "codex", Status: StatusActive},
		&Auth{ID: "lower", Provider: "codex", Status: StatusActive},
	)
	freezeQuotaFallbackAuth(t, mgr, "hot", 1.0, now)
	freezeQuotaFallbackAuth(t, mgr, "lower", 0.995, now)

	resp, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: quotaFallbackTestModel}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := string(resp.Payload); got != "lower" {
		t.Fatalf("Execute() payload = %q, want lower", got)
	}
	if auth, ok := mgr.GetByID("lower"); !ok || auth.quotaPreemptFallback {
		t.Fatal("fallback marker leaked into registered auth")
	}
}

func TestQuotaPreemptFallbackDoesNotCrossOtherBlockReasons(t *testing.T) {
	tests := []struct {
		name  string
		block func(*Auth, time.Time)
	}{
		{
			name: "usage limit",
			block: func(auth *Auth, now time.Time) {
				retry := time.Hour
				auth.freezeUsageLimit(now, &retry)
			},
		},
		{
			name: "generic freeze",
			block: func(auth *Auth, now time.Time) {
				state := auth.ensureRuntimeLimits()
				state.mu.Lock()
				state.frozenUntil = now.Add(time.Hour)
				state.mu.Unlock()
			},
		},
		{
			name: "model unavailable",
			block: func(auth *Auth, now time.Time) {
				auth.Unavailable = true
				auth.Quota = QuotaState{Exceeded: true}
				auth.NextRetryAfter = now.Add(time.Hour)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			executor := &runtimeLimitTestExecutor{}
			a := &Auth{ID: "a", Provider: "codex", Status: StatusActive}
			b := &Auth{ID: "b", Provider: "codex", Status: StatusActive}
			mgr := newQuotaPreemptFallbackManager(t, executor, a, b)
			freezeQuotaFallbackAuth(t, mgr, "a", 0.995, now)
			freezeQuotaFallbackAuth(t, mgr, "b", 0.996, now)

			mgr.mu.RLock()
			registered := mgr.auths["b"]
			mgr.mu.RUnlock()
			test.block(registered, now)

			mgr.mu.RLock()
			candidates := []*Auth{mgr.auths["a"], mgr.auths["b"]}
			mgr.mu.RUnlock()
			if got := mgr.quotaPreemptFallbackAuth(candidates, quotaFallbackTestModel, now.Add(time.Second)); got != nil {
				t.Fatalf("quotaPreemptFallbackAuth() = %s, want nil", got.ID)
			}
		})
	}
}

func TestQuotaPreemptFallbackRequiresFreshSnapshotForEveryCandidate(t *testing.T) {
	now := time.Now()
	executor := &runtimeLimitTestExecutor{}
	a := &Auth{ID: "a", Provider: "codex", Status: StatusActive}
	b := &Auth{ID: "b", Provider: "codex", Status: StatusActive}
	mgr := newQuotaPreemptFallbackManager(t, executor, a, b)
	freezeQuotaFallbackAuth(t, mgr, "a", 0.995, now)
	freezeQuotaFallbackAuth(t, mgr, "b", 0.996, now)

	mgr.mu.RLock()
	registeredB := mgr.auths["b"]
	mgr.mu.RUnlock()
	state := registeredB.ensureRuntimeLimits()
	state.codexQuotaSnapshots.Store(codexQuotaSnapshotStore{})

	mgr.mu.RLock()
	candidates := []*Auth{mgr.auths["a"], mgr.auths["b"]}
	mgr.mu.RUnlock()
	if got := mgr.quotaPreemptFallbackAuth(candidates, quotaFallbackTestModel, now.Add(time.Second)); got != nil {
		t.Fatalf("quotaPreemptFallbackAuth() = %s, want nil without a full fresh snapshot set", got.ID)
	}
}

func TestQuotaPreemptFallbackAllowsOneConcurrentRequestPerCredential(t *testing.T) {
	now := time.Now()
	executor := &runtimeLimitTestExecutor{
		blockAuth: "a",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	a := &Auth{ID: "a", Provider: "codex", Status: StatusActive}
	b := &Auth{ID: "b", Provider: "codex", Status: StatusActive}
	mgr := newQuotaPreemptFallbackManager(t, executor, a, b)
	freezeQuotaFallbackAuth(t, mgr, "a", 0.995, now)
	freezeQuotaFallbackAuth(t, mgr, "b", 0.996, now)

	var wg sync.WaitGroup
	wg.Add(1)
	firstDone := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: quotaFallbackTestModel}, cliproxyexecutor.Options{})
		firstDone <- err
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("first fallback request did not start")
	}

	second, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: quotaFallbackTestModel}, cliproxyexecutor.Options{})
	if err != nil {
		close(executor.release)
		t.Fatalf("second Execute() error = %v", err)
	}
	if got := string(second.Payload); got != "b" {
		close(executor.release)
		t.Fatalf("second payload = %q, want b", got)
	}
	close(executor.release)
	wg.Wait()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}
}
