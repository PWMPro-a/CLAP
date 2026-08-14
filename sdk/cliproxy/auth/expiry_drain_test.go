package auth

import (
	"context"
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
	later := authWithExpiry("later", now.Add(3*time.Hour))
	sooner := authWithExpiry("sooner", now.Add(30*time.Minute))
	noExpiry := &Auth{ID: "no-expiry", Provider: "codex", Status: StatusActive}

	got := expiryPriorityAuths([]*Auth{far, later, noExpiry, sooner}, now)
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

func TestExpiryPriorityAuthsKeepsOnlyOldestSupplierCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	oldestA := authWithSupplyLeaseExpiry("oldest-a", now.Add(20*time.Minute), tokenExpiry)
	oldestB := authWithSupplyLeaseExpiry("oldest-b", now.Add(20*time.Minute+30*time.Second), tokenExpiry)
	nextBatch := authWithSupplyLeaseExpiry("next", now.Add(22*time.Minute), tokenExpiry)

	got := expiryPriorityAuths([]*Auth{nextBatch, oldestB, oldestA}, now)
	if len(got) != 2 || got[0].ID != "oldest-a" || got[1].ID != "oldest-b" {
		t.Fatalf("oldest supplier cohort = %#v, want [oldest-a oldest-b]", got)
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

func TestExpiredSupplyLeaseIsNotSelectable(t *testing.T) {
	now := time.Now().UTC()
	auth := authWithSupplyLeaseExpiry("expired-lease", now.Add(-time.Second), now.Add(10*24*time.Hour))
	blocked, reason, _ := isAuthBlockedForModel(auth, "gpt-5", now)
	if !blocked || reason != blockReasonDisabled {
		t.Fatalf("expired supply lease blocked=%t reason=%v, want true/disabled", blocked, reason)
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

func TestSchedulerUsesSupplierLeaseAndStaysOnOldestCohort(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	oldest := authWithSupplyLeaseExpiry("oldest", now.Add(20*time.Minute), tokenExpiry)
	next := authWithSupplyLeaseExpiry("next", now.Add(23*time.Minute), tokenExpiry)
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, next, oldest)

	for i := 0; i < 4; i++ {
		got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("scheduler pick %d: %v", i, errPick)
		}
		if got == nil || got.ID != oldest.ID {
			t.Fatalf("scheduler pick %d = %v, want oldest supplier cohort", i, got)
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

func TestSchedulerSkipsExpiredSupplierLeaseFromNormalReadyLane(t *testing.T) {
	now := time.Now().UTC()
	tokenExpiry := now.Add(10 * 24 * time.Hour)
	expiring := authWithSupplyLeaseExpiry("a-expiring", now.Add(20*time.Minute), tokenExpiry)
	valid := authWithSupplyLeaseExpiry("z-valid", now.Add(48*time.Hour), tokenExpiry)
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, expiring, valid)
	first, errFirst := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errFirst != nil || first == nil || first.ID != expiring.ID {
		t.Fatalf("initial scheduler pick = %v, err=%v, want expiring supplier lease", first, errFirst)
	}

	// Simulate the fixed supplier deadline passing without an auth-file update.
	// The entry remains in the ready view, so request-time filtering must keep it
	// out of both the expiry lane and the normal round-robin fallback.
	entry := scheduler.providers["codex"].modelShards[""].entries[expiring.ID]
	entry.expiresAt = now.Add(-time.Second)
	entry.supplyLeaseExpiresAt = entry.expiresAt

	got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("scheduler pick: %v", errPick)
	}
	if got == nil || got.ID != valid.ID {
		t.Fatalf("scheduler pick = %v, want unexpired supplier lease", got)
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
	for configured, want := range map[int]int{1: 2, 2: 4, 4: 8, 7: 8, 8: 8, 10: 10} {
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
