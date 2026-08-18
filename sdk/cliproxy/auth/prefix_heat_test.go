package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestPrefixHeatTrackerTTLCapacityAndInvalidation(t *testing.T) {
	tracker := newPrefixHeatTracker(time.Minute, 2)
	started := time.Unix(1_700_000_000, 0)
	authA := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	authB := &Auth{ID: "auth-b", Provider: "codex", Status: StatusActive}

	prefixes := prefixHeatPrefixesForSameShard(3)
	tracker.Record(prefixes[0], authA.ID, started)
	tracker.Record(prefixes[1], authA.ID, started.Add(time.Second))
	tracker.Record(prefixes[2], authB.ID, started.Add(2*time.Second))

	if hot := tracker.HotAuths(prefixes[0], []*Auth{authA}, started.Add(3*time.Second)); len(hot) != 0 {
		t.Fatalf("evicted prefix returned %d hot auths, want 0", len(hot))
	}
	if hot := tracker.HotAuths(prefixes[1], []*Auth{authA}, started.Add(3*time.Second)); len(hot) != 0 {
		t.Fatalf("second evicted prefix returned %d hot auths, want 0", len(hot))
	}
	assertPrefixHeatAuthIDs(t, tracker.HotAuths(prefixes[2], []*Auth{authB}, started.Add(3*time.Second)), authB.ID)

	checkAt := started.Add(62*time.Second + 500*time.Millisecond)
	if hot := tracker.HotAuths(prefixes[1], []*Auth{authA}, checkAt); len(hot) != 0 {
		t.Fatalf("expired prefix returned %d hot auths, want 0", len(hot))
	}
	if hot := tracker.HotAuths(prefixes[2], []*Auth{authB}, checkAt); len(hot) != 0 {
		t.Fatalf("expired latest prefix returned %d hot auths, want 0", len(hot))
	}

	tracker.Record(prefixes[2], authB.ID, checkAt)
	tracker.InvalidateAuth(authB.ID)
	if hot := tracker.HotAuths(prefixes[2], []*Auth{authB}, checkAt); len(hot) != 0 {
		t.Fatalf("invalidated auth returned %d hot auths, want 0", len(hot))
	}
}

func prefixHeatPrefixesForSameShard(count int) []string {
	if count <= 0 {
		return nil
	}
	byShard := make(map[int][]string)
	for index := 0; ; index++ {
		prefix := fmt.Sprintf("same-shard-prefix-%d", index)
		shard := prefixHeatShardIndex(prefix)
		byShard[shard] = append(byShard[shard], prefix)
		if len(byShard[shard]) >= count {
			return byShard[shard]
		}
	}
}

func TestPrefixHeatNewSessionPrefersHotAuthWithoutChangingWarmBinding(t *testing.T) {
	selector := newPrefixHeatTestSelector(false)
	defer selector.Stop()
	hot := &Auth{ID: "a-hot", Provider: "codex", Status: StatusActive}
	defaultAuth := &Auth{ID: "z-default", Provider: "codex", Status: StatusActive}
	auths := []*Auth{hot, defaultAuth}

	selector.RecordCacheAffinitySuccess(hot.ID, prefixHeatOptions("recorded-route", "shared-prefix").Metadata)
	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("new-route", "shared-prefix"), auths)
	if errPick != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("cold prefix-heat pick = %#v, %v; want %q", selected, errPick, hot.ID)
	}

	warmRoute := "existing-warm-route"
	selector.cache.Set(sessionAffinityCacheKey("codex", "cache-affinity:"+warmRoute, "gpt-5.6-sol"), defaultAuth.ID)
	selected, errPick = selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions(warmRoute, "shared-prefix"), auths)
	if errPick != nil || selected == nil || selected.ID != defaultAuth.ID {
		t.Fatalf("existing warm binding = %#v, %v; want %q", selected, errPick, defaultAuth.ID)
	}
}

func TestPrefixHeatChoosesLowestConcurrencyAmongHotAuths(t *testing.T) {
	selector := newPrefixHeatTestSelector(false)
	defer selector.Stop()
	lowConcurrency := &Auth{ID: "a-low-concurrency", Provider: "codex", Status: StatusActive}
	highConcurrency := &Auth{ID: "z-high-concurrency", Provider: "codex", Status: StatusActive}
	for _, auth := range []*Auth{lowConcurrency, highConcurrency} {
		selector.RecordCacheAffinitySuccess(auth.ID, prefixHeatOptions("record-"+auth.ID, "balanced-prefix").Metadata)
	}

	releaseFirst, acquired, reason, _ := highConcurrency.acquireRuntimeSlotForModel(time.Now(), "gpt-5.6-sol", false)
	if !acquired {
		t.Fatalf("acquire first high-concurrency slot: %s", reason)
	}
	defer releaseFirst()
	releaseSecond, acquired, reason, _ := highConcurrency.acquireRuntimeSlotForModel(time.Now(), "gpt-5.6-sol", false)
	if !acquired {
		t.Fatalf("acquire second high-concurrency slot: %s", reason)
	}
	defer releaseSecond()

	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("balanced-new-route", "balanced-prefix"), []*Auth{lowConcurrency, highConcurrency})
	if errPick != nil || selected == nil || selected.ID != lowConcurrency.ID {
		t.Fatalf("balanced prefix-heat pick = %#v, %v; want %q", selected, errPick, lowConcurrency.ID)
	}
}

func TestPrefixHeatRespectsExistingCandidateFilters(t *testing.T) {
	t.Run("priority", func(t *testing.T) {
		selector := newPrefixHeatTestSelector(false)
		defer selector.Stop()
		lowPriorityHot := &Auth{ID: "a-low-priority-hot", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "0"}}
		highPriority := &Auth{ID: "z-high-priority", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "1"}}
		selector.RecordCacheAffinitySuccess(lowPriorityHot.ID, prefixHeatOptions("record-low", "priority-prefix").Metadata)

		selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("priority-new-route", "priority-prefix"), []*Auth{lowPriorityHot, highPriority})
		if errPick != nil || selected == nil || selected.ID != highPriority.ID {
			t.Fatalf("priority-filtered pick = %#v, %v; want %q", selected, errPick, highPriority.ID)
		}
	})

	t.Run("normal concurrency cap", func(t *testing.T) {
		selector := newPrefixHeatTestSelector(false)
		defer selector.Stop()
		hotAtLimit := &Auth{ID: "a-hot-at-limit", Provider: "codex", Status: StatusActive}
		fallback := &Auth{ID: "z-fallback", Provider: "codex", Status: StatusActive}
		hotAtLimit.setCodexCacheAffinityMaxConcurrency(1)
		release, acquired, reason, _ := hotAtLimit.acquireRuntimeSlotForModel(time.Now(), "gpt-5.6-sol", false)
		if !acquired {
			t.Fatalf("occupy hot auth normal slot: %s", reason)
		}
		defer release()
		selector.RecordCacheAffinitySuccess(hotAtLimit.ID, prefixHeatOptions("record-limit", "limit-prefix").Metadata)

		selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("limit-new-route", "limit-prefix"), []*Auth{hotAtLimit, fallback})
		if errPick != nil || selected == nil || selected.ID != fallback.ID {
			t.Fatalf("concurrency-filtered pick = %#v, %v; want %q", selected, errPick, fallback.ID)
		}
	})

	t.Run("quota preemption", func(t *testing.T) {
		selector := newPrefixHeatTestSelector(false)
		defer selector.Stop()
		now := time.Now()
		hotNearQuota := &Auth{ID: "a-hot-near-quota", Provider: "codex", Status: StatusActive}
		fallback := &Auth{ID: "z-fallback", Provider: "codex", Status: StatusActive}
		_, _ = hotNearQuota.setCodexQuotaSnapshot("gpt-5.6-sol", CodexQuotaSnapshot{UsedRatio: 0.98, SampledAt: now, ExpiresAt: now.Add(time.Hour)})
		selector.RecordCacheAffinitySuccess(hotNearQuota.ID, prefixHeatOptions("record-quota", "quota-prefix").Metadata)

		selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("quota-new-route", "quota-prefix"), []*Auth{hotNearQuota, fallback})
		if errPick != nil || selected == nil || selected.ID != fallback.ID {
			t.Fatalf("quota-filtered pick = %#v, %v; want %q", selected, errPick, fallback.ID)
		}
	})
}

func TestPrefixHeatShadowAndNoMatchPreserveFallbackSelection(t *testing.T) {
	hot := &Auth{ID: "a-hot", Provider: "codex", Status: StatusActive}
	defaultAuth := &Auth{ID: "z-default", Provider: "codex", Status: StatusActive}
	auths := []*Auth{hot, defaultAuth}

	shadow := newPrefixHeatTestSelector(true)
	defer shadow.Stop()
	shadow.RecordCacheAffinitySuccess(hot.ID, prefixHeatOptions("shadow-record", "shadow-prefix").Metadata)
	selected, errPick := shadow.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("shadow-new-route", "shadow-prefix"), auths)
	if errPick != nil || selected == nil || selected.ID != defaultAuth.ID {
		t.Fatalf("shadow pick = %#v, %v; want unchanged fallback %q", selected, errPick, defaultAuth.ID)
	}

	activeNoMatch := newPrefixHeatTestSelector(false)
	defer activeNoMatch.Stop()
	selected, errPick = activeNoMatch.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("no-match-route", "unknown-prefix"), auths)
	if errPick != nil || selected == nil || selected.ID != defaultAuth.ID {
		t.Fatalf("no-match pick = %#v, %v; want unchanged fallback %q", selected, errPick, defaultAuth.ID)
	}
}

func TestPrefixHeatConfigUpdatePreservesRecordedHeat(t *testing.T) {
	selector := newPrefixHeatTestSelector(true)
	defer selector.Stop()
	hot := &Auth{ID: "a-hot", Provider: "codex", Status: StatusActive}
	defaultAuth := &Auth{ID: "z-default", Provider: "codex", Status: StatusActive}
	selector.RecordCacheAffinitySuccess(hot.ID, prefixHeatOptions("recorded-route", "updated-prefix").Metadata)

	selector.ConfigurePrefixHeat(true, false, 2*time.Minute, 256)
	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("updated-route", "updated-prefix"), []*Auth{hot, defaultAuth})
	if errPick != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("pick after in-place prefix heat update = %#v, %v; want %q", selected, errPick, hot.ID)
	}
}

func TestManagerRecordsPrefixHeatOnlyOnSuccessfulConfirmation(t *testing.T) {
	selector := newPrefixHeatTestSelector(false)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	hot := &Auth{ID: "a-hot", Provider: "codex", Status: StatusActive}
	defaultAuth := &Auth{ID: "z-default", Provider: "codex", Status: StatusActive}
	auths := []*Auth{hot, defaultAuth}
	metadata := prefixHeatOptions("successful-route", "confirmed-prefix").Metadata

	if hotBefore := selector.prefixHeat.HotAuths("confirmed-prefix", auths, time.Now()); len(hotBefore) != 0 {
		t.Fatalf("prefix heat existed before success confirmation: %v", hotBefore)
	}
	beforeStats := cacheaffinity.Snapshot()
	manager.confirmCacheAffinityBinding("codex", "gpt-5.6-sol", hot.ID, metadata)
	afterStats := cacheaffinity.Snapshot()
	if afterStats.PrefixHeatRecords-beforeStats.PrefixHeatRecords != 1 {
		t.Fatalf("prefix heat record delta = %d, want 1", afterStats.PrefixHeatRecords-beforeStats.PrefixHeatRecords)
	}
	assertPrefixHeatAuthIDs(t, selector.prefixHeat.HotAuths("confirmed-prefix", auths, time.Now()), hot.ID)

	selected, errPick := selector.Pick(context.Background(), "codex", "gpt-5.6-sol", prefixHeatOptions("next-route", "confirmed-prefix"), auths)
	if errPick != nil || selected == nil || selected.ID != hot.ID {
		t.Fatalf("post-confirmation pick = %#v, %v; want %q", selected, errPick, hot.ID)
	}
}

func TestPrefixHeatSkipsTailBurstSuccessRecording(t *testing.T) {
	selector := newPrefixHeatTestSelector(false)
	defer selector.Stop()
	metadata := prefixHeatOptions("tail-route", "tail-prefix").Metadata
	metadata[cliproxyexecutor.CodexTailBurstMetadataKey] = true
	selector.RecordCacheAffinitySuccess("tail-auth", metadata)
	if hot := selector.prefixHeat.HotAuths("tail-prefix", []*Auth{{ID: "tail-auth", Provider: "codex", Status: StatusActive}}, time.Now()); len(hot) != 0 {
		t.Fatalf("tail-burst success recorded %d hot auths, want 0", len(hot))
	}
}

func TestManagerStopsOnlyReplacedSessionAffinitySelector(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	first := newPrefixHeatTestSelector(true)
	manager.SetSelector(first)
	manager.SetSelector(first)
	select {
	case <-first.cache.stopCh:
		t.Fatal("setting the same selector stopped its session cache")
	default:
	}

	second := newPrefixHeatTestSelector(true)
	manager.SetSelector(second)
	select {
	case <-first.cache.stopCh:
	default:
		t.Fatal("replaced selector session cache was not stopped")
	}
	second.Stop()
}

func newPrefixHeatTestSelector(shadow bool) *SessionAffinitySelector {
	return NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:               lastAuthSelector{},
		TTL:                    time.Hour,
		CacheAffinityEnabled:   true,
		PrefixHeatEnabled:      true,
		PrefixHeatShadow:       shadow,
		PrefixHeatTTL:          time.Minute,
		PrefixHeatMaxEntries:   128,
		QuotaPreemptUsedRatio:  0.97,
		QuotaHardStopUsedRatio: 0.99,
	})
}

func prefixHeatOptions(routeKey, prefixFingerprint string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.CacheAffinityActiveMetadataKey:            true,
		cliproxyexecutor.CacheAffinityRouteKeyMetadataKey:          routeKey,
		cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey: prefixFingerprint,
	}}
}

func assertPrefixHeatAuthIDs(t *testing.T, auths []*Auth, want ...string) {
	t.Helper()
	if len(auths) != len(want) {
		t.Fatalf("hot auth count = %d, want %d", len(auths), len(want))
	}
	for index, auth := range auths {
		if auth == nil || auth.ID != want[index] {
			t.Fatalf("hot auth[%d] = %#v, want %q", index, auth, want[index])
		}
	}
}
