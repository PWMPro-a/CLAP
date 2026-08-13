package auth

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func enableNewCandidateMode(manager *Manager) {
	cfg, _ := manager.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		cfg = &internalconfig.Config{}
	} else {
		cfg = cfg.CloneForRuntime()
	}
	cfg.Routing.NewCandidateMode = true
	manager.SetConfig(cfg)
}

func TestNewCandidateModeUsesOnlyIndexedSingleCandidates(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "indexed", Provider: "gemini", Status: StatusActive}); errRegister != nil {
		t.Fatal(errRegister)
	}

	manager.mu.Lock()
	manager.auths["legacy-only"] = &Auth{ID: "legacy-only", Provider: "gemini", Status: StatusActive}
	manager.mu.Unlock()
	enableNewCandidateMode(manager)

	want := []string{"indexed", "indexed"}
	for index, wantID := range want {
		got, _, errPick := manager.pickNext(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pick #%d: %v", index, errPick)
		}
		if got == nil || got.ID != wantID {
			t.Fatalf("pick #%d = %#v, want %s", index, got, wantID)
		}
	}
}

func TestLegacyCandidateModeUsesOnlyAuthMap(t *testing.T) {
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "indexed-only", Provider: "gemini", Status: StatusActive}); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.mu.Lock()
	delete(manager.auths, "indexed-only")
	manager.auths["legacy"] = &Auth{ID: "legacy", Provider: "gemini", Status: StatusActive}
	manager.mu.Unlock()
	manager.SetConfig(&internalconfig.Config{})

	got, _, errPick := manager.pickNext(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if got == nil || got.ID != "legacy" {
		t.Fatalf("pick = %#v, want legacy", got)
	}
}

func TestNewCandidateModeUsesOnlyIndexedMixedCandidates(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "gemini"})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "gemini-indexed", Provider: "gemini", Status: StatusActive}); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.mu.Lock()
	manager.auths["claude-legacy"] = &Auth{ID: "claude-legacy", Provider: "claude", Status: StatusActive}
	manager.mu.Unlock()
	enableNewCandidateMode(manager)

	got, _, provider, errPick := manager.pickNextMixed(context.Background(), []string{"gemini", "claude"}, "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if got == nil || got.ID != "gemini-indexed" || provider != "gemini" {
		t.Fatalf("pick = %#v provider=%s, want gemini-indexed", got, provider)
	}
}

func TestNewCandidateModeRouteAliasStaysIndexed(t *testing.T) {
	const (
		provider = "gemini"
		alias    = "alias-model"
		upstream = "upstream-model"
	)
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})
	manager.SetOAuthModelAlias(map[string][]internalconfig.OAuthModelAlias{provider: {{Name: upstream, Alias: alias}}})
	auth := &Auth{ID: "alias-auth", Provider: provider, Status: StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: alias}, {ID: upstream}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	manager.RefreshSchedulerEntry(auth.ID)
	enableNewCandidateMode(manager)

	got, _, errPick := manager.pickNext(context.Background(), provider, alias, cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if got == nil || got.ID != auth.ID {
		t.Fatalf("pick = %#v, want %s", got, auth.ID)
	}
}

func TestNewCandidateModeQuotaFallbackStaysIndexed(t *testing.T) {
	now := time.Now()
	executor := &runtimeLimitTestExecutor{}
	manager := newQuotaPreemptFallbackManager(t, executor,
		&Auth{ID: "higher", Provider: "codex", Status: StatusActive},
		&Auth{ID: "lower", Provider: "codex", Status: StatusActive},
	)
	freezeQuotaFallbackAuth(t, manager, "higher", 1.0, now)
	freezeQuotaFallbackAuth(t, manager, "lower", 0.995, now)
	enableNewCandidateMode(manager)

	manager.mu.Lock()
	manager.auths["legacy-only"] = &Auth{ID: "legacy-only", Provider: "codex", Status: StatusActive}
	manager.mu.Unlock()

	got, _, errPick := manager.pickNext(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if got == nil || got.ID != "lower" || !got.quotaPreemptFallback {
		t.Fatalf("pick = %#v, want indexed quota fallback lower", got)
	}
}
