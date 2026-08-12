package auth

import (
	"context"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestSessionAffinityCacheCoordinatorPreemptsNewButKeepsWarmSession(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:               &RoundRobinSelector{},
		TTL:                    time.Hour,
		CacheAffinityEnabled:   true,
		QuotaPreemptUsedRatio:  0.97,
		QuotaHardStopUsedRatio: 0.99,
	})
	defer selector.Stop()
	now := time.Now()
	hot := &Auth{ID: "hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "cold", Provider: "codex", Status: StatusActive}
	_, _ = hot.setCodexQuotaSnapshot("gpt-5.6-sol", CodexQuotaSnapshot{UsedRatio: 0.98, SampledAt: now, ExpiresAt: now.Add(time.Hour)})

	warmOpts := activeCacheAffinityOptions("warm-route")
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:warm-route", "gpt-5.6-sol"), hot.ID)
	warm, errWarm := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", warmOpts, []*Auth{hot, cold})
	if errWarm != nil || warm.ID != hot.ID {
		t.Fatalf("warm pick = %v, %v; want hot", warm, errWarm)
	}

	newPick, errNew := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", activeCacheAffinityOptions("new-route"), []*Auth{hot, cold})
	if errNew != nil || newPick.ID != cold.ID {
		t.Fatalf("new pick = %v, %v; want cold", newPick, errNew)
	}
}

func TestSessionAffinityCacheCoordinatorHardStopsWarmSession(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:               &RoundRobinSelector{},
		TTL:                    time.Hour,
		CacheAffinityEnabled:   true,
		QuotaPreemptUsedRatio:  0.97,
		QuotaHardStopUsedRatio: 0.99,
	})
	defer selector.Stop()
	now := time.Now()
	hot := &Auth{ID: "hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "cold", Provider: "codex", Status: StatusActive}
	_, _ = hot.setCodexQuotaSnapshot("gpt-5.6-sol", CodexQuotaSnapshot{UsedRatio: 0.995, SampledAt: now, ExpiresAt: now.Add(time.Hour)})
	opts := activeCacheAffinityOptions("warm-route-hard-stop")
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:warm-route-hard-stop", "gpt-5.6-sol"), hot.ID)

	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", opts, []*Auth{hot, cold})
	if errPick != nil || selected.ID != cold.ID {
		t.Fatalf("hard-stop pick = %v, %v; want cold", selected, errPick)
	}
}

func activeCacheAffinityOptions(routeKey string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.CacheAffinityActiveMetadataKey:   true,
		cliproxyexecutor.CacheAffinityRouteKeyMetadataKey: routeKey,
	}}
}
