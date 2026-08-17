package auth

import (
	"context"
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

func TestSessionAffinityWarmBindingBypassesTailBurstNormalConcurrencyCap(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()
	now := time.Now()
	hot := &Auth{ID: "hot", Provider: "codex", Status: StatusActive}
	cold := &Auth{ID: "cold", Provider: "codex", Status: StatusActive}
	hot.setCodexTailBurstNormalMaxConcurrency(1)

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
	cfg.Codex.TailBurst.Enabled = false
	cfg.Codex.CacheAffinity.Enabled = true
	cfg.Codex.CacheAffinity.MaxConcurrency = 1
	manager.SetConfig(cfg)

	hot := tailBurstAuthForTest(t, manager, "only-hot")
	now := time.Now()
	occupiedRelease, occupied, reason, _ := hot.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
	if !occupied {
		t.Fatalf("occupy new-session slot: %s", reason)
	}
	defer occupiedRelease()

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

func TestManagerKeepsOnlyWarmAffinityRequestAboveTailBurstNormalConcurrencyCap(t *testing.T) {
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
	cfg.Codex.TailBurst.NormalMaxConcurrency = 1
	manager.SetConfig(cfg)

	hot := tailBurstAuthForTest(t, manager, "only-hot")
	now := time.Now()
	occupiedRelease, occupied, reason, _ := hot.acquireRuntimeSlotForModel(now, "gpt-5.6-sol", false)
	if !occupied {
		t.Fatalf("occupy normal slot: %s", reason)
	}
	defer occupiedRelease()

	opts := activeCacheAffinityOptions("manager-warm-normal-cap")
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:manager-warm-normal-cap", ""), hot.ID)
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", "", opts)
	if errSelect != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("manager warm selection = %v, %v; want only-hot", selected, errSelect)
	}
	warmRelease, acquired, reason, _ := selected.acquireRuntimeSlotForModel(now, "", false)
	if !acquired {
		t.Fatalf("manager warm affinity slot was blocked by normal cap: %s", reason)
	}
	defer warmRelease()

	if _, errCold := manager.SelectAuth(context.Background(), "codex", "", activeCacheAffinityOptions("manager-cold-normal-cap")); errCold == nil {
		t.Fatal("cold manager selection exceeded the normal concurrency cap")
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
