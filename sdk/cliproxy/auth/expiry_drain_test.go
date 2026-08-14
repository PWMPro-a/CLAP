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

func TestExpiryPriorityAuthsKeepsClosestExpiryLane(t *testing.T) {
	now := time.Now().UTC()
	far := authWithExpiry("far", now.Add(48*time.Hour))
	later := authWithExpiry("later", now.Add(3*time.Hour))
	sooner := authWithExpiry("sooner", now.Add(30*time.Minute))
	noExpiry := &Auth{ID: "no-expiry", Provider: "codex", Status: StatusActive}

	got := expiryPriorityAuths([]*Auth{far, later, noExpiry, sooner}, now)
	if len(got) != 2 {
		t.Fatalf("near-expiry candidates = %d, want 2", len(got))
	}
	if got[0] != sooner || got[1] != later {
		t.Fatalf("near-expiry order = [%s %s], want [sooner later]", got[0].ID, got[1].ID)
	}

	unchanged := []*Auth{far, noExpiry}
	if got := expiryPriorityAuths(unchanged, now); len(got) != len(unchanged) || got[0] != unchanged[0] || got[1] != unchanged[1] {
		t.Fatalf("non-expiring candidates were reordered or filtered: %#v", got)
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
