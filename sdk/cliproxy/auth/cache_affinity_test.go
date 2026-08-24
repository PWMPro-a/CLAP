package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCacheAffinityNewSessionConcurrencyCapsConcurrentFirstRequests(t *testing.T) {
	const (
		newSessionLimit = 8
		requests        = 100
	)
	auth := &Auth{ID: "concurrent-first-requests", Provider: "codex", Status: StatusActive}
	auth.setCodexCacheAffinityMaxConcurrency(newSessionLimit)
	release := make(chan struct{})
	results := make(chan bool, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			releaseSlot, acquired, _, _ := auth.acquireRuntimeSlotForModel(time.Now(), "gpt-5.6-sol", false)
			results <- acquired
			if !acquired {
				return
			}
			<-release
			releaseSlot()
		}()
	}

	acquired := 0
	for range requests {
		if <-results {
			acquired++
		}
	}
	if acquired != newSessionLimit {
		t.Fatalf("concurrent acquired slots = %d, want new-session limit %d", acquired, newSessionLimit)
	}
	if current := auth.RuntimeLimitSnapshot(time.Now()).CurrentConcurrency; current != newSessionLimit {
		t.Fatalf("current concurrency = %d, want %d while requests are held", current, newSessionLimit)
	}

	close(release)
	wg.Wait()
	if current := auth.RuntimeLimitSnapshot(time.Now()).CurrentConcurrency; current != 0 {
		t.Fatalf("current concurrency after release = %d, want 0", current)
	}
}

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

func TestSessionAffinityWarmBindingBypassesNormalConcurrencyCap(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()
	now := time.Now()
	hot := &Auth{ID: "hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "cold", Provider: "codex", Status: StatusActive}
	hot.setCodexCacheAffinityMaxConcurrency(1)

	occupiedRelease, occupied, reason, _ := hot.acquireRuntimeSlotForModel(now, "", false)
	if !occupied {
		t.Fatalf("occupy normal slot: %s", reason)
	}
	defer occupiedRelease()

	warmOpts := activeCacheAffinityOptions("warm-normal-cap")
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:warm-normal-cap", "gpt-5.6-sol"), hot.ID)
	warm, errWarm := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", warmOpts, []*Auth{hot, cold})
	if errWarm != nil || warm == nil || warm.ID != hot.ID {
		t.Fatalf("warm pick = %v, %v; want hot", warm, errWarm)
	}
	warmRelease, acquired, reason, _ := warm.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
	if !acquired {
		t.Fatalf("warm affinity slot was blocked by normal cap: %s", reason)
	}
	defer warmRelease()

	newPick, errNew := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", activeCacheAffinityOptions("cold-normal-cap"), []*Auth{hot, cold})
	if errNew != nil || newPick == nil || newPick.ID != cold.ID {
		t.Fatalf("cold pick = %v, %v; want cold", newPick, errNew)
	}
}

func TestSessionAffinityWarmBindingBypassesCacheAffinityNewSessionCap(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()
	now := time.Now()
	hot := &Auth{ID: "hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "cold", Provider: "codex", Status: StatusActive}
	hot.setCodexCacheAffinityMaxConcurrency(1)

	occupiedRelease, occupied, reason, _ := hot.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
	if !occupied {
		t.Fatalf("occupy new-session slot: %s", reason)
	}
	defer occupiedRelease()

	routeKey := "warm-soft-cap"
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:"+routeKey, "gpt-5.6-sol"), hot.ID)
	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", activeCacheAffinityOptions(routeKey), []*Auth{hot, cold})
	if errPick != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("warm soft-cap pick = %v, %v; want hot", selected, errPick)
	}
	warmRelease, acquired, reason, _ := selected.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
	if !acquired {
		t.Fatalf("warm affinity slot was blocked by new-session cap: %s", reason)
	}
	defer warmRelease()

	newPick, errNew := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", activeCacheAffinityOptions("cold-soft-cap"), []*Auth{hot, cold})
	if errNew != nil || newPick == nil || newPick.ID != cold.ID {
		t.Fatalf("cold soft-cap pick = %v, %v; want cold", newPick, errNew)
	}
}

func TestSessionAffinityCacheShareCapSkipsOnlyColdBinding(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:                   &RoundRobinSelector{},
		TTL:                        time.Hour,
		CacheAffinityEnabled:       true,
		CacheAffinityMaxShareRatio: 0.5,
	})
	defer selector.Stop()
	model := "gpt-share-selector-cold"
	first := &Auth{ID: "share-first", Provider: "codex", Status: StatusActive}
	second := &Auth{ID: "share-second", Provider: "codex", Status: StatusActive}

	firstOpts := activeCacheAffinityOptionsWithDecision("share-cold-1", "share-cold-decision-1")
	firstPick, errFirst := selector.Pick(context.Background(), "codex", model, firstOpts, []*Auth{first, second})
	if errFirst != nil || firstPick == nil || firstPick.ID != first.ID {
		t.Fatalf("first cold pick = %v, %v; want first auth", firstPick, errFirst)
	}
	if cached, ok := selector.cache.GetAndRefresh(sessionAffinityCacheKey("codex", "cache-affinity:share-cold-1", model)); !ok || cached != first.ID {
		t.Fatalf("first cold binding = %q, %t; want %s, true", cached, ok, first.ID)
	}

	secondOpts := activeCacheAffinityOptionsWithDecision("share-cold-2", "share-cold-decision-2")
	secondPick, errSecond := selector.Pick(context.Background(), "codex", model, secondOpts, []*Auth{first, second})
	if errSecond != nil || secondPick == nil || secondPick.ID != second.ID {
		t.Fatalf("share-limited cold pick = %v, %v; want second auth", secondPick, errSecond)
	}
	if cached, ok := selector.cache.GetAndRefresh(sessionAffinityCacheKey("codex", "cache-affinity:share-cold-2", model)); ok {
		t.Fatalf("share-limited cold request was bound to %q", cached)
	}
	if got := secondOpts.Metadata[cliproxyexecutor.CacheAffinityShareLimitedMetadataKey]; got != true {
		t.Fatalf("share-limited metadata = %v, want true", got)
	}
}

func TestSessionAffinityCacheShareCapKeepsWarmBinding(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:                   &RoundRobinSelector{},
		TTL:                        time.Hour,
		CacheAffinityEnabled:       true,
		CacheAffinityMaxShareRatio: 0.5,
	})
	defer selector.Stop()
	model := "gpt-share-selector-warm"
	hot := &Auth{ID: "share-warm-hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "share-warm-cold", Provider: "codex", Status: StatusActive}
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:share-warm-route", model), hot.ID)

	// Consume the cold-binding share window so the next cold route would be
	// limited. Warm bindings are looked up before the share cap and remain sticky.
	_, errFirst := selector.Pick(context.Background(), "codex", model, activeCacheAffinityOptionsWithDecision("share-warm-cold-1", "share-warm-cold-decision-1"), []*Auth{hot, cold})
	if errFirst != nil {
		t.Fatalf("prime first cold route: %v", errFirst)
	}
	_, errSecond := selector.Pick(context.Background(), "codex", model, activeCacheAffinityOptionsWithDecision("share-warm-cold-2", "share-warm-cold-decision-2"), []*Auth{hot, cold})
	if errSecond != nil {
		t.Fatalf("prime share-limited cold route: %v", errSecond)
	}

	warm, errWarm := selector.Pick(context.Background(), "codex", model, activeCacheAffinityOptionsWithDecision("share-warm-route", "share-warm-decision"), []*Auth{hot, cold})
	if errWarm != nil || warm == nil || warm.ID != hot.ID {
		t.Fatalf("warm pick under share cap = %v, %v; want hot", warm, errWarm)
	}
}

func TestManagerKeepsWarmAffinityAboveCacheAffinityNewSessionCap(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "only-hot", Provider: "codex", Status: StatusActive},
	)
	manager.SetSelector(selector)
	cfg := newTailBurstConfig()
	cfg.Codex.CacheAffinity.Enabled = true
	cfg.Codex.CacheAffinity.MaxConcurrency = 4
	manager.SetConfig(cfg)

	hot := tailBurstAuthForTest(t, manager, "only-hot")
	now := time.Now()
	occupiedReleases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		occupiedRelease, occupied, reason, _ := hot.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
		if !occupied {
			t.Fatalf("occupy cache-affinity slot %d: %s", i+1, reason)
		}
		occupiedReleases = append(occupiedReleases, occupiedRelease)
	}
	defer func() {
		for _, release := range occupiedReleases {
			release()
		}
	}()

	opts := activeCacheAffinityOptions("manager-warm-soft-cap")
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:manager-warm-soft-cap", ""), hot.ID)
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", "", opts)
	if errSelect != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("manager warm selection = %v, %v; want only-hot", selected, errSelect)
	}
	warmRelease, acquired, reason, _ := selected.acquireRuntimeSlotForModel(now, "", false)
	if !acquired {
		t.Fatalf("manager warm affinity slot was blocked by new-session cap: %s", reason)
	}
	defer warmRelease()

	if _, errCold := manager.SelectAuth(context.Background(), "codex", "", activeCacheAffinityOptions("manager-cold-soft-cap")); errCold == nil {
		t.Fatal("cold manager selection exceeded the cache-affinity new-session cap")
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
	return activeCacheAffinityOptionsWithDecision(routeKey, fmt.Sprintf("decision-%s", routeKey))
}

func activeCacheAffinityOptionsWithDecision(routeKey, decisionID string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.CacheAffinityActiveMetadataKey:     true,
		cliproxyexecutor.CacheAffinityRouteKeyMetadataKey:   routeKey,
		cliproxyexecutor.CacheAffinityDecisionIDMetadataKey: decisionID,
	}}
}
