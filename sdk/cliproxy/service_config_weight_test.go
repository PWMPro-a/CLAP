package cliproxy

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestWeightedRoundRobinRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "wrr"},
	})
	if state.strategy != "weighted-round-robin" {
		t.Fatalf("strategy = %q, want weighted-round-robin", state.strategy)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.WeightedRoundRobinSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.WeightedRoundRobinSelector", newRoutingSelector(state))
	}
}

func TestPrefixHeatHotReloadPreservesSessionAffinitySelector(t *testing.T) {
	shadow := true
	initialCfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:              true,
		PrefixHeatEnabled:    true,
		PrefixHeatShadow:     &shadow,
		PrefixHeatTTL:        "10m",
		PrefixHeatMaxEntries: 128,
		PrefixHeatMinBytes:   4096,
	}}}
	initialState := normalizedRoutingRuntimeState(initialCfg)
	selector, ok := newRoutingSelector(initialState).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(initialState))
	}
	t.Cleanup(selector.Stop)
	selector.BindAuthSession("codex", "gpt-5.6-sol", "cache-affinity:preserved-route", "preserved-auth")

	manager := coreauth.NewManager(nil, selector, nil)
	service := &Service{coreManager: manager, appliedRoutingState: &initialState}
	shadow = false
	updatedCfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:              true,
		PrefixHeatEnabled:    true,
		PrefixHeatShadow:     &shadow,
		PrefixHeatTTL:        "20m",
		PrefixHeatMaxEntries: 256,
		PrefixHeatMinBytes:   8192,
	}}}
	if !service.applyManagerConfig(context.Background(), configCommit{cfg: updatedCfg}) {
		t.Fatal("apply prefix heat config update failed")
	}
	if got := manager.Selector(); got != selector {
		t.Fatalf("prefix-only config update replaced selector: got %T %p, want %p", got, got, selector)
	}
	authID, found := selector.BoundAuthSession("codex", "gpt-5.6-sol", coreauthOptionsForRoute("preserved-route"))
	if !found || authID != "preserved-auth" {
		t.Fatalf("preserved affinity binding = %q, %t; want preserved-auth, true", authID, found)
	}
}

func coreauthOptionsForRoute(routeKey string) executor.Options {
	return executor.Options{Metadata: map[string]any{
		executor.CacheAffinityActiveMetadataKey:   true,
		executor.CacheAffinityRouteKeyMetadataKey: routeKey,
	}}
}

func TestHighCacheRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{HighCacheMode: true},
	})
	selector, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(state))
	}
	if !selector.HighCacheMode() {
		t.Fatal("selector did not enable high cache mode")
	}
	defer selector.Stop()
}

func TestCacheAffinityBuildsSessionSelectorWithoutLegacyHighCacheMode(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:               true,
			MaxEntries:            4096,
			QuotaPreemptUsedRatio: 0.96,
		}},
	})
	selector, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(state))
	}
	if selector.HighCacheMode() {
		t.Fatal("cache affinity unexpectedly enabled legacy high-cache caller fallback")
	}
	defer selector.Stop()
}

func TestExpiryDrainIgnoreAffinityConfigFlowsIntoRoutingState(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:                   true,
			ExpiryDrainIgnoreAffinity: true,
		}},
	})
	if !state.expiryDrainIgnoreAffinity {
		t.Fatal("expiry drain ignore-affinity switch was not preserved")
	}
	selector, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(state))
	}
	defer selector.Stop()
}

func TestPrefixHeatConfigFlowsIntoRoutingState(t *testing.T) {
	shadow := true
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:              true,
			PrefixHeatEnabled:    true,
			PrefixHeatShadow:     &shadow,
			PrefixHeatTTL:        "17m",
			PrefixHeatMaxEntries: 321,
		}},
	})
	if !state.prefixHeatEnabled || !state.prefixHeatShadow {
		t.Fatalf("prefix heat switches = enabled:%t shadow:%t, want true/true", state.prefixHeatEnabled, state.prefixHeatShadow)
	}
	if state.prefixHeatTTL != 17*time.Minute {
		t.Fatalf("prefix heat TTL = %s, want 17m", state.prefixHeatTTL)
	}
	if state.prefixHeatMaxEntries != 321 {
		t.Fatalf("prefix heat max entries = %d, want 321", state.prefixHeatMaxEntries)
	}
	if state.prefixHeatMinBytes != 4096 {
		t.Fatalf("prefix heat minimum bytes = %d, want 4096", state.prefixHeatMinBytes)
	}
	selector, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(state))
	}
	defer selector.Stop()
}

func TestServiceRejectsInvalidCredentialWeightConfigCommit(t *testing.T) {
	originalCfg := &internalconfig.Config{}
	service := &Service{cfg: originalCfg}
	invalidWeight := internalconfig.MaxCredentialWeight + 1
	newCfg := &internalconfig.Config{
		VertexCompatAPIKey: []internalconfig.VertexCompatKey{{
			APIKey: "vertex-key",
			Weight: &invalidWeight,
		}},
	}

	if service.applyConfigUpdateWithAuthSynthesis(nil, newCfg, true) {
		t.Fatal("hot config application accepted an invalid credential weight")
	}
	if service.cfg != originalCfg {
		t.Fatal("invalid hot config replaced the active config")
	}
	if service.configSequence != 0 {
		t.Fatalf("config sequence = %d, want 0", service.configSequence)
	}
}
