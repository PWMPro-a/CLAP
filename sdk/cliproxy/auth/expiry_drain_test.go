package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func authWithExpiry(id string, expiry time.Time) *Auth {
	return &Auth{
		ID:       id,
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{"expires_at": expiry.Format(time.RFC3339Nano)},
	}
}

func authWithSupplyLeaseExpiry(id string, leaseExpiry, tokenExpiry time.Time) *Auth {
	auth := authWithExpiry(id, tokenExpiry)
	auth.Metadata["supply_lease_expires_at_ms"] = leaseExpiry.UnixMilli()
	auth.Metadata["supply_lease_expires_at"] = leaseExpiry.Format(time.RFC3339)
	return auth
}

func TestExpiryPriorityAuthsKeepsClosestExpiryLane(t *testing.T) {
	now := time.Now().UTC()
	far := authWithExpiry("far", now.Add(48*time.Hour))
	sooner := authWithExpiry("sooner", now.Add(30*time.Minute))
	noExpiry := &Auth{ID: "no-expiry", Provider: "codex", Status: StatusActive}

	got := expiryPriorityAuths([]*Auth{far, noExpiry, sooner}, now)
	if len(got) != 1 {
		t.Fatalf("closest-expiry candidates = %d, want 1", len(got))
	}
	if got[0] != sooner {
		t.Fatalf("closest-expiry candidate = %s, want sooner", got[0].ID)
	}

	unchanged := []*Auth{far, noExpiry}
	if got := expiryPriorityAuths(unchanged, now); len(got) != len(unchanged) || got[0] != unchanged[0] || got[1] != unchanged[1] {
		t.Fatalf("non-expiring candidates were reordered or filtered: %#v", got)
	}
}

func TestExpiryPriorityAuthsKeepsMinimumCandidatesAndBoundaryCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	auths := make([]*Auth, 0, 10)
	for i := 0; i < 10; i++ {
		expiresAt := now.Add(time.Duration(20+i*2) * time.Minute)
		if i == 8 {
			// The ninth candidate belongs to the eighth candidate's batch and
			// must not be split off at the minimum-size boundary.
			expiresAt = now.Add(34*time.Minute + 30*time.Second)
		}
		auths = append(auths, authWithSupplyLeaseExpiry(string(rune('a'+i)), expiresAt, tokenExpiry))
	}

	got := expiryPriorityAuths(auths, now)
	if len(got) != 9 {
		t.Fatalf("expiry priority candidates = %d, want 9", len(got))
	}
	for i := 0; i < 9; i++ {
		if got[i].ID != string(rune('a'+i)) {
			t.Fatalf("expiry priority candidate %d = %s, want %s", i, got[i].ID, string(rune('a'+i)))
		}
	}
}

func TestSchedulingExpiryPrefersSupplyLeaseWithoutChangingTokenExpiry(t *testing.T) {
	now := time.Now().UTC()
	leaseExpiry := now.Add(15 * time.Minute)
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	auth := authWithSupplyLeaseExpiry("leased", leaseExpiry, tokenExpiry)

	gotScheduling, okScheduling := authSchedulingExpirationTime(auth)
	if !okScheduling || !gotScheduling.Equal(time.UnixMilli(leaseExpiry.UnixMilli())) {
		t.Fatalf("scheduling expiry = %v/%t, want supplier lease %v", gotScheduling, okScheduling, leaseExpiry)
	}
	gotToken, okToken := auth.ExpirationTime()
	if !okToken || !gotToken.Equal(tokenExpiry) {
		t.Fatalf("token expiry = %v/%t, want OAuth expiry %v", gotToken, okToken, tokenExpiry)
	}
}

func TestExpiredSupplyLeaseRemainsSelectableUntilRuntimeHealthRejectsIt(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithSupplyLeaseExpiry("expired-lease", now.Add(-time.Second), now.Add(10*24*time.Hour))
	blocked, reason, _ := isAuthBlockedForModel(auth, "gpt-5", now)
	if blocked || reason != blockReasonNone {
		t.Fatalf("expired supply lease blocked=%t reason=%v, want false/none", blocked, reason)
	}
	remaining, urgent := authExpiryRemaining(auth, now)
	if !urgent || remaining >= 0 {
		t.Fatalf("expired supply lease urgency = %s/%t, want overdue/true", remaining, urgent)
	}
}

func TestSelectorsPreferNearExpiryForColdRequests(t *testing.T) {
	now := time.Now().UTC()
	near := authWithExpiry("near", now.Add(2*time.Hour))
	long := authWithExpiry("long", now.Add(48*time.Hour))
	auths := []*Auth{long, near}
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "cold-session",
	}}

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer selector.Stop()
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", opts, auths)
	if errPick != nil {
		t.Fatalf("session-affinity cold pick: %v", errPick)
	}
	if got == nil || got.ID != near.ID {
		t.Fatalf("cold session picked %v, want %s", got, near.ID)
	}

	for _, fallback := range []Selector{&RoundRobinSelector{}, &WeightedRoundRobinSelector{}, &FillFirstSelector{}} {
		got, errPick := fallback.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("%T pick: %v", fallback, errPick)
		}
		if got == nil || got.ID != near.ID {
			t.Fatalf("%T picked %v, want %s", fallback, got, near.ID)
		}
	}
}

func TestSessionAffinityKeepsEstablishedBindingAgainstExpiryLane(t *testing.T) {
	now := time.Now().UTC()
	bound := authWithExpiry("bound", now.Add(48*time.Hour))
	near := authWithExpiry("near", now.Add(time.Hour))
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer selector.Stop()

	selector.cache.Set(sessionAffinityCacheKey("codex", "derived:stable-session", "gpt-5"), bound.ID)
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "stable-session",
	}}, []*Auth{near, bound})
	if errPick != nil {
		t.Fatalf("established session pick: %v", errPick)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("established session picked %v, want bound auth %s", got, bound.ID)
	}
}

func TestSessionAffinityPreservesWarmBindingDuringFinalExpiryDrainByDefault(t *testing.T) {
	now := time.Now().UTC()
	bound := authWithSupplyLeaseExpiry("bound", now.Add(50*time.Minute), now.Add(10*24*time.Hour))
	drain := authWithSupplyLeaseExpiry("drain", now.Add(4*time.Minute), now.Add(10*24*time.Hour))
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()

	cacheKey := sessionAffinityCacheKey("codex", "derived:stable-session", "gpt-5")
	selector.cache.Set(cacheKey, bound.ID)
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "stable-session",
	}}, []*Auth{bound, drain})
	if errPick != nil {
		t.Fatalf("final expiry affinity pick: %v", errPick)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("final expiry affinity picked %v, want warm binding %s", got, bound.ID)
	}
	if _, ok := selector.failoverCache.Get(cacheKey); ok {
		t.Fatal("default final expiry drain created a temporary affinity binding")
	}
}

func TestSessionAffinityTemporarilyFailsOverDuringConfiguredFinalExpiryDrain(t *testing.T) {
	now := time.Now().UTC()
	bound := authWithSupplyLeaseExpiry("bound", now.Add(50*time.Minute), now.Add(10*24*time.Hour))
	drain := authWithSupplyLeaseExpiry("drain", now.Add(4*time.Minute), now.Add(10*24*time.Hour))
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:                  &RoundRobinSelector{},
		TTL:                       time.Hour,
		CacheAffinityEnabled:      true,
		ExpiryDrainIgnoreAffinity: true,
	})
	defer selector.Stop()

	cacheKey := sessionAffinityCacheKey("codex", "derived:stable-session", "gpt-5")
	selector.cache.Set(cacheKey, bound.ID)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "stable-session",
	}}
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", opts, []*Auth{bound, drain})
	if errPick != nil {
		t.Fatalf("final expiry drain pick: %v", errPick)
	}
	if got == nil || got.ID != drain.ID {
		t.Fatalf("final expiry drain picked %v, want %s", got, drain.ID)
	}
	if primary, ok := selector.cache.Get(cacheKey); !ok || primary != bound.ID {
		t.Fatalf("primary cache binding = %q/%t, want preserved %s", primary, ok, bound.ID)
	}
	if temporary, ok := selector.failoverCache.Get(cacheKey); !ok || temporary != drain.ID {
		t.Fatalf("temporary drain binding = %q/%t, want %s", temporary, ok, drain.ID)
	}

	drain.ModelStates = map[string]*ModelState{
		"gpt-5": {Quota: QuotaState{Exceeded: true}},
	}
	got, errPick = selector.Pick(context.Background(), "codex", "gpt-5", opts, []*Auth{bound, drain})
	if errPick != nil {
		t.Fatalf("post-drain affinity pick: %v", errPick)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("post-drain affinity picked %v, want primary %s", got, bound.ID)
	}
	if _, ok := selector.failoverCache.Get(cacheKey); ok {
		t.Fatal("temporary drain binding was retained after quota exhaustion")
	}
}

func TestSessionAffinityKeepsCachedAuthWhenItIsInOldestDrainCohort(t *testing.T) {
	now := time.Now().UTC()
	bound := authWithSupplyLeaseExpiry("bound", now.Add(3*time.Minute), now.Add(10*24*time.Hour))
	peer := authWithSupplyLeaseExpiry("peer", now.Add(3*time.Minute+30*time.Second), now.Add(10*24*time.Hour))
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()

	cacheKey := sessionAffinityCacheKey("codex", "derived:drain-session", "gpt-5")
	selector.cache.Set(cacheKey, bound.ID)
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "drain-session",
	}}, []*Auth{peer, bound})
	if errPick != nil {
		t.Fatalf("same-cohort affinity pick: %v", errPick)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("same-cohort affinity picked %v, want bound auth %s", got, bound.ID)
	}
}

func TestSessionAffinityTemporarilySpillsPastBusyExpiryCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	bound := authWithSupplyLeaseExpiry("bound", now.Add(20*time.Minute), tokenExpiry)
	next := authWithSupplyLeaseExpiry("next", now.Add(23*time.Minute), tokenExpiry)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	defer selector.Stop()

	releases := make([]func(), 0, authExpiryPriorityDefaultConcurrency)
	for i := 0; i < authExpiryPriorityDefaultConcurrency; i++ {
		release, acquired, reason, _ := bound.acquireRuntimeSlotForModel(now, "gpt-5", false)
		if !acquired {
			t.Fatalf("bound slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
	}()

	cacheKey := sessionAffinityCacheKey("codex", "derived:busy-expiry-session", "gpt-5")
	selector.cache.Set(cacheKey, bound.ID)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DerivedSessionIDMetadataKey: "busy-expiry-session",
	}}
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", opts, []*Auth{bound, next})
	if errPick != nil {
		t.Fatalf("busy expiry failover pick: %v", errPick)
	}
	if got == nil || got.ID != next.ID {
		t.Fatalf("busy expiry failover pick = %v, want %s", got, next.ID)
	}
	if primary, ok := selector.cache.Get(cacheKey); !ok || primary != bound.ID {
		t.Fatalf("primary cache binding = %q/%t, want preserved %s", primary, ok, bound.ID)
	}
	if temporary, ok := selector.failoverCache.Get(cacheKey); !ok || temporary != next.ID {
		t.Fatalf("temporary overflow binding = %q/%t, want %s", temporary, ok, next.ID)
	}

	releases[len(releases)-1]()
	releases[len(releases)-1] = nil
	got, errPick = selector.Pick(context.Background(), "codex", "gpt-5", opts, []*Auth{bound, next})
	if errPick != nil {
		t.Fatalf("restored expiry affinity pick: %v", errPick)
	}
	if got == nil || got.ID != bound.ID {
		t.Fatalf("restored expiry affinity pick = %v, want %s", got, bound.ID)
	}
	if _, ok := selector.failoverCache.Get(cacheKey); ok {
		t.Fatal("temporary overflow binding remained after the primary had capacity")
	}
}

func TestSchedulerPrefersNearExpiryWithoutPerRequestSorting(t *testing.T) {
	now := time.Now().UTC()
	near := authWithExpiry("near", now.Add(2*time.Hour))
	long := authWithExpiry("long", now.Add(48*time.Hour))
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, long, near)

	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("scheduler pick: %v", errPick)
	}
	if got == nil || got.ID != near.ID {
		t.Fatalf("scheduler picked %v, want %s", got, near.ID)
	}
}

func TestSchedulerUsesSupplierLeaseAcrossEarliestHealthyCandidates(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	oldest := authWithSupplyLeaseExpiry("oldest", now.Add(20*time.Minute), tokenExpiry)
	next := authWithSupplyLeaseExpiry("next", now.Add(23*time.Minute), tokenExpiry)
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, next, oldest)

	want := []string{oldest.ID, next.ID, oldest.ID, next.ID}
	for i, wantID := range want {
		got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("scheduler pick %d: %v", i, errPick)
		}
		if got == nil || got.ID != wantID {
			t.Fatalf("scheduler pick %d = %v, want %s", i, got, wantID)
		}
	}

	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, map[string]struct{}{oldest.ID: {}})
	if errPick != nil {
		t.Fatalf("retry scheduler pick: %v", errPick)
	}
	if got == nil || got.ID != next.ID {
		t.Fatalf("retry scheduler pick = %v, want next after oldest was tried", got)
	}
}

func TestSchedulerExpiryLaneKeepsMinimumCandidatesAndBoundaryCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	auths := make([]*Auth, 0, 10)
	for i := 0; i < 10; i++ {
		expiresAt := now.Add(time.Duration(20+i*2) * time.Minute)
		if i == 8 {
			expiresAt = now.Add(34*time.Minute + 30*time.Second)
		}
		auths = append(auths, authWithSupplyLeaseExpiry(string(rune('a'+i)), expiresAt, tokenExpiry))
	}
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)

	seen := make(map[string]int)
	for i := 0; i < 18; i++ {
		got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("scheduler pick %d: %v", i, errPick)
		}
		seen[got.ID]++
	}
	for i := 0; i < 9; i++ {
		id := string(rune('a' + i))
		if seen[id] == 0 {
			t.Fatalf("expiry lane did not schedule candidate %s: %#v", id, seen)
		}
	}
	if seen["j"] != 0 {
		t.Fatalf("expiry lane scheduled later candidate j: %#v", seen)
	}
}

func BenchmarkSchedulerExpiryLaneLargePool(b *testing.B) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	auths := make([]*Auth, 0, 1000)
	for i := 0; i < cap(auths); i++ {
		auths = append(auths, authWithSupplyLeaseExpiry(
			fmt.Sprintf("auth-%04d", i),
			now.Add(time.Duration(1+i)*time.Minute),
			tokenExpiry,
		))
	}
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil); errPick != nil {
			b.Fatal(errPick)
		}
	}
}

func TestSchedulerKeepsExpiredSupplierLeaseInHighestPriorityLane(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	expiring := authWithSupplyLeaseExpiry("a-expiring", now.Add(20*time.Minute), tokenExpiry)
	valid := authWithSupplyLeaseExpiry("z-valid", now.Add(48*time.Hour), tokenExpiry)
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, expiring, valid)
	first, errFirst := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errFirst != nil || first == nil || first.ID != expiring.ID {
		t.Fatalf("initial scheduler pick = %v, err=%v, want expiring supplier lease", first, errFirst)
	}

	// Simulate the supplier timestamp passing without an auth-file update. The
	// account remains healthy, so it must stay in the highest-priority lane.
	entry := scheduler.providers["codex"].modelShards[""].entries[expiring.ID]
	entry.expiresAt = now.Add(-time.Second)
	entry.supplyLeaseExpiresAt = entry.expiresAt

	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("scheduler pick: %v", errPick)
	}
	if got == nil || got.ID != expiring.ID {
		t.Fatalf("scheduler pick = %v, want still-healthy expired supplier lease", got)
	}
}

func TestMixedSchedulerPrefersNearExpiryAcrossProviders(t *testing.T) {
	now := time.Now().UTC()
	long := authWithExpiry("long", now.Add(48*time.Hour))
	long.Provider = "codex"
	near := authWithExpiry("near", now.Add(2*time.Hour))
	near.Provider = "gemini"

	for _, selector := range []Selector{&RoundRobinSelector{}, &FillFirstSelector{}, &WeightedRoundRobinSelector{}} {
		scheduler := newSchedulerForTest(selector, long, near)
		got, provider, errPick := scheduler.pickMixed(context.Background(), []string{"codex", "gemini"}, "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("%T mixed pick: %v", selector, errPick)
		}
		if got == nil || got.ID != near.ID || provider != near.Provider {
			t.Fatalf("%T mixed pick = %v/%q, want %s/%s", selector, got, provider, near.ID, near.Provider)
		}
	}
}

func TestExpiryDrainConcurrencyBoostIsBoundedAndModelAware(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithExpiry("drain", now.Add(4*time.Minute))
	auth.Metadata["max_concurrency"] = 1
	for configured, want := range map[int]int{1: 2, 2: 4, 4: 8, 7: 10, 8: 10, 10: 10, 12: 12} {
		if got := expiryDrainConcurrencyLimit(auth, "gpt-5", now, configured); got != want {
			t.Fatalf("configured concurrency %d boosted to %d, want %d", configured, got, want)
		}
	}

	firstRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatalf("first drain slot not acquired: %s", reason)
	}
	secondRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		firstRelease()
		t.Fatalf("second drain slot not acquired: %s", reason)
	}
	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		firstRelease()
		secondRelease()
		t.Fatalf("third drain slot acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}
	firstRelease()
	secondRelease()

	far := authWithExpiry("far", now.Add(10*time.Minute))
	far.Metadata["max_concurrency"] = 1
	firstRelease, acquired, _, _ = far.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatal("far-expiry first slot not acquired")
	}
	defer firstRelease()
	if _, acquired, reason, _ := far.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		t.Fatalf("far-expiry second slot acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}
}

func TestExpiryPriorityDefaultConcurrencySpillsIntoNextCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	oldest := authWithSupplyLeaseExpiry("oldest", now.Add(20*time.Minute), tokenExpiry)
	next := authWithSupplyLeaseExpiry("next", now.Add(23*time.Minute), tokenExpiry)

	if got := oldest.runtimeLimitConfigForModel("gpt-5", now).maxConcurrency; got != authExpiryPriorityDefaultConcurrency {
		t.Fatalf("oldest default max concurrency = %d, want %d", got, authExpiryPriorityDefaultConcurrency)
	}
	releases := make([]func(), 0, authExpiryPriorityDefaultConcurrency)
	for i := 0; i < authExpiryPriorityDefaultConcurrency; i++ {
		release, acquired, reason, _ := oldest.acquireRuntimeSlotForModel(now, "gpt-5", false)
		if !acquired {
			t.Fatalf("oldest slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	if _, acquired, reason, _ := oldest.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		t.Fatalf("oldest overflow acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}

	selector := &RoundRobinSelector{}
	got, errPick := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, []*Auth{oldest, next})
	if errPick != nil {
		t.Fatalf("next-cohort pick: %v", errPick)
	}
	if got == nil || got.ID != next.ID {
		t.Fatalf("next-cohort pick = %v, want %s", got, next.ID)
	}
}

func TestExpiryPriorityDefaultConcurrencyKeepsFarUnconfiguredAuthUnlimited(t *testing.T) {
	now := time.Now().UTC()
	far := authWithExpiry("far", now.Add(48*time.Hour))
	if got := far.runtimeLimitConfigForModel("gpt-5", now).maxConcurrency; got != 0 {
		t.Fatalf("far unconfigured max concurrency = %d, want 0", got)
	}
}

func TestExpiryDrainDefaultConcurrencyUsesRemainingQuota(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name      string
		usedRatio float64
		want      int
	}{
		{name: "large remainder", usedRatio: 0.20, want: authExpiryDrainUrgentConcurrency},
		{name: "medium remainder", usedRatio: 0.60, want: authExpiryDrainNormalConcurrency},
		{name: "small remainder", usedRatio: 0.90, want: authExpiryDrainMinConcurrency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := authWithExpiry("drain", now.Add(4*time.Minute))
			auth.ensureRuntimeLimits().codexQuotaSnapshots.Store(codexQuotaSnapshotStore{
				"gpt-5": {
					UsedRatio: tc.usedRatio,
					SampledAt: now,
					ExpiresAt: now.Add(time.Minute),
				},
			})
			if got := auth.runtimeLimitConfigForModel("gpt-5", now).maxConcurrency; got != tc.want {
				t.Fatalf("drain max concurrency = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestExpiryDrainDoesNotBoostExhaustedQuota(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithExpiry("exhausted", now.Add(4*time.Minute))
	auth.Metadata["max_concurrency"] = 1
	auth.ModelStates = map[string]*ModelState{
		"gpt-5": {Quota: QuotaState{Exceeded: true}},
	}

	firstRelease, acquired, _, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatal("exhausted-quota first slot not acquired")
	}
	defer firstRelease()
	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		t.Fatalf("exhausted-quota second slot acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}
}

func TestExpiryDrainContinuesPastRoundedHundredPercent(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithSupplyLeaseExpiry("rounded", now.Add(4*time.Minute), now.Add(10*24*time.Hour))
	auth.Metadata["max_concurrency"] = 1
	auth.ensureRuntimeLimits().codexQuotaSnapshots.Store(codexQuotaSnapshotStore{
		"gpt-5": {
			UsedRatio: 1,
			SampledAt: now,
			ExpiresAt: now.Add(time.Minute),
		},
	})

	firstRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatalf("first rounded tail slot not acquired: %s", reason)
	}
	secondRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		firstRelease()
		t.Fatalf("second rounded tail slot not acquired: %s", reason)
	}
	firstRelease()
	secondRelease()
}

func TestExpiryDrainBoostAppliesToTailBurstLane(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithExpiry("tail-drain", now.Add(4*time.Minute))
	auth.Metadata["max_concurrency"] = 1

	firstRelease, acquired, _, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", true)
	if !acquired {
		t.Fatal("first tail-drain slot not acquired")
	}
	secondRelease, acquired, _, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", true)
	if !acquired {
		firstRelease()
		t.Fatal("second tail-drain slot not acquired")
	}
	defer firstRelease()
	defer secondRelease()
	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", true); acquired || reason != "tail_burst_concurrency_limit" {
		t.Fatalf("third tail-drain slot acquired=%t reason=%q, want false/tail_burst_concurrency_limit", acquired, reason)
	}
}
