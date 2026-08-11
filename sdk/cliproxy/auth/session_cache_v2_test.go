package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestSessionCachePersistsAndRestoresBindingGeneration(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "session-affinity.json")
	options := SessionCacheOptions{
		TTL:           time.Minute,
		FlushInterval: time.Hour,
		StateFile:     stateFile,
	}

	cache := NewSessionCacheWithOptions(options)
	first := cache.BindAliases("auth-a", "provider::pck:shared::model", "provider::conv:one::model")
	if first.Generation != 1 {
		t.Fatalf("first generation = %d, want 1", first.Generation)
	}
	rebound := cache.BindAliases("auth-b", "provider::pck:shared::model", "provider::conv:two::model")
	if rebound.Generation != 2 {
		t.Fatalf("rebound generation = %d, want 2", rebound.Generation)
	}
	cache.Stop()

	restored := NewSessionCacheWithOptions(options)
	t.Cleanup(restored.Stop)
	for _, alias := range []string{
		"provider::pck:shared::model",
		"provider::conv:one::model",
		"provider::conv:two::model",
	} {
		binding, ok := restored.GetBinding(alias, false)
		if !ok {
			t.Fatalf("restored alias %q is missing", alias)
		}
		if binding.AuthID != "auth-b" || binding.Generation != 2 {
			t.Fatalf("restored binding for %q = %#v", alias, binding)
		}
	}
}

func TestSessionCacheReportsCorruptPersistenceState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "session-affinity.json")
	if err := os.WriteFile(stateFile, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	cache := NewSessionCacheWithOptions(SessionCacheOptions{TTL: time.Minute, StateFile: stateFile})
	t.Cleanup(cache.Stop)
	status := cache.PersistenceError()
	if status == nil || status.Operation != "decode" || status.StateFile != stateFile || status.Message == "" {
		t.Fatalf("persistence status = %#v", status)
	}
}

func TestSessionAffinityConcurrentFailoverCreatesOneGeneration(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &FillFirstSelector{},
		TTL:      time.Minute,
	})
	t.Cleanup(selector.Stop)
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Affinity": []string{"concurrent-failover"}}}

	initial, err := selector.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{{ID: "auth-a"}})
	if err != nil || initial.ID != "auth-a" {
		t.Fatalf("initial Pick() = %#v, %v", initial, err)
	}

	const workers = 1000
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			selected, pickErr := selector.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{{ID: "auth-b"}, {ID: "auth-c"}})
			if pickErr != nil {
				errors <- pickErr
				return
			}
			if selected.ID != "auth-b" {
				errors <- fmt.Errorf("selected %q, want auth-b", selected.ID)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	primaryID, _ := extractSessionIDs(opts.Headers, nil, nil)
	binding, ok := selector.cache.GetBinding(sessionAffinityCacheKey("codex", primaryID, "gpt-test"), false)
	if !ok {
		t.Fatal("failover binding is missing")
	}
	if binding.AuthID != "auth-b" || binding.Generation != 2 {
		t.Fatalf("failover binding = %#v, want auth-b generation 2", binding)
	}
}

func TestSessionAffinityConcurrentPrimaryKeysShareFallbackBinding(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
	})
	t.Cleanup(selector.Stop)
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}

	for iteration := 0; iteration < 100; iteration++ {
		conversation := fmt.Sprintf("shared-conversation-%d", iteration)
		payloads := [][]byte{
			[]byte(fmt.Sprintf(`{"conversation":{"id":%q},"prompt_cache_key":%q}`, conversation, fmt.Sprintf("pck-a-%d", iteration))),
			[]byte(fmt.Sprintf(`{"conversation":{"id":%q},"prompt_cache_key":%q}`, conversation, fmt.Sprintf("pck-b-%d", iteration))),
		}
		start := make(chan struct{})
		selected := make(chan string, len(payloads))
		errors := make(chan error, len(payloads))
		var wait sync.WaitGroup
		for _, payload := range payloads {
			payload := payload
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				auth, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{OriginalRequest: payload}, auths)
				if err != nil {
					errors <- err
					return
				}
				selected <- auth.ID
			}()
		}
		close(start)
		wait.Wait()
		close(selected)
		close(errors)
		for err := range errors {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		var expected string
		for authID := range selected {
			if expected == "" {
				expected = authID
				continue
			}
			if authID != expected {
				t.Fatalf("iteration %d split one fallback alias across %q and %q", iteration, expected, authID)
			}
		}
	}
}

func TestSessionAffinityConcurrentFailoverAcrossMergedAliasesUsesOneBinding(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
	})
	t.Cleanup(selector.Stop)

	keyA := sessionAffinityCacheKey("codex", "affinity:merged-alias-a", "gpt-test")
	keyB := sessionAffinityCacheKey("codex", "affinity:merged-alias-b", "gpt-test")
	selector.cache.BindAliases("auth-a", keyA, keyB)

	options := []cliproxyexecutor.Options{
		{Headers: http.Header{"X-Session-Affinity": []string{"merged-alias-a"}}},
		{Headers: http.Header{"X-Session-Affinity": []string{"merged-alias-b"}}},
	}
	start := make(chan struct{})
	selected := make(chan string, len(options))
	var wait sync.WaitGroup
	for _, opts := range options {
		opts := opts
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			auth, err := selector.Pick(context.Background(), "codex", "gpt-test", opts, []*Auth{{ID: "auth-b"}, {ID: "auth-c"}})
			if err != nil {
				t.Errorf("Pick() error = %v", err)
				return
			}
			selected <- auth.ID
		}()
	}
	close(start)
	wait.Wait()
	close(selected)

	var expected string
	for authID := range selected {
		if expected == "" {
			expected = authID
			continue
		}
		if authID != expected {
			t.Fatalf("merged aliases failed over to %q and %q", expected, authID)
		}
	}
	binding, ok := selector.cache.GetBinding(keyA, false)
	if !ok || binding.AuthID != expected || binding.Generation != 2 {
		t.Fatalf("merged alias binding = %#v, want auth=%q generation=2", binding, expected)
	}
}

func TestSessionAffinityRendezvousOnlyMovesSessionsToAddedAuth(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:   &RoundRobinSelector{},
		TTL:        time.Minute,
		Rendezvous: true,
	})
	t.Cleanup(selector.Stop)
	original := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}, {ID: "auth-c"}}
	expanded := append(append([]*Auth(nil), original...), &Auth{ID: "auth-d"})
	now := time.Now()
	changed := 0

	const sessions = 4096
	for index := 0; index < sessions; index++ {
		key := fmt.Sprintf("codex::header:session-%d::gpt-test", index)
		before, _, err := selector.pickBindingAuth(context.Background(), key, "codex", "gpt-test", cliproxyexecutor.Options{}, original, now)
		if err != nil {
			t.Fatalf("original pick %d: %v", index, err)
		}
		repeat, _, err := selector.pickBindingAuth(context.Background(), key, "codex", "gpt-test", cliproxyexecutor.Options{}, original, now)
		if err != nil || repeat.ID != before.ID {
			t.Fatalf("unstable rendezvous pick for %q: %q then %q (%v)", key, before.ID, repeat.ID, err)
		}
		after, _, err := selector.pickBindingAuth(context.Background(), key, "codex", "gpt-test", cliproxyexecutor.Options{}, expanded, now)
		if err != nil {
			t.Fatalf("expanded pick %d: %v", index, err)
		}
		if after.ID != before.ID {
			changed++
			if after.ID != "auth-d" {
				t.Fatalf("adding auth-d remapped %q from %q to existing %q", key, before.ID, after.ID)
			}
		}
	}
	changedRatio := float64(changed) / sessions
	if changedRatio < 0.15 || changedRatio > 0.35 {
		t.Fatalf("rendezvous changed ratio = %.3f, want roughly 0.25", changedRatio)
	}
}

func TestSessionAffinityQuotaAwareOnlyAffectsNewBindings(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:   &RoundRobinSelector{},
		TTL:        time.Minute,
		Rendezvous: true,
		QuotaAware: true,
	})
	t.Cleanup(selector.Stop)
	now := time.Now()
	authA := &Auth{ID: "auth-a", Provider: "codex"}
	authB := &Auth{ID: "auth-b", Provider: "codex"}
	setSnapshot := func(auth *Auth, ratio float64, sampledAt time.Time) {
		_, accepted := auth.setCodexQuotaSnapshot("*", CodexQuotaSnapshot{
			UsedRatio: ratio,
			SampledAt: sampledAt,
			ExpiresAt: sampledAt.Add(time.Hour),
		})
		if !accepted {
			t.Fatalf("quota snapshot for %s was not accepted", auth.ID)
		}
	}
	setSnapshot(authA, 0.95, now)
	setSnapshot(authB, 0.10, now)
	auths := []*Auth{authA, authB}

	firstOptions := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Affinity": []string{"quota-session-one"}}}
	first, err := selector.Pick(context.Background(), "codex", "gpt-test", firstOptions, auths)
	if err != nil || first.ID != "auth-b" {
		t.Fatalf("cold quota-aware Pick() = %#v, %v, want auth-b", first, err)
	}

	newSampleTime := now.Add(time.Second)
	setSnapshot(authA, 0.10, newSampleTime)
	setSnapshot(authB, 0.95, newSampleTime)
	sticky, err := selector.Pick(context.Background(), "codex", "gpt-test", firstOptions, auths)
	if err != nil || sticky.ID != "auth-b" {
		t.Fatalf("existing binding moved after quota change: %#v, %v", sticky, err)
	}
	second, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Affinity": []string{"quota-session-two"}},
	}, auths)
	if err != nil || second.ID != "auth-a" {
		t.Fatalf("new binding ignored latest quota: %#v, %v", second, err)
	}
}

func TestSessionAffinityPCKShadowDoesNotModifyRequestPayload(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:            &FillFirstSelector{},
		TTL:                 time.Minute,
		Rendezvous:          true,
		PCKShadow:           true,
		PCKShadowSampleRate: 1,
	})
	t.Cleanup(selector.Stop)
	payload := []byte(`{"prompt_cache_key":"keep-upstream-key","conversation":{"id":"conversation-one"},"input":[{"role":"user","content":"hello"}]}`)
	original := append([]byte(nil), payload...)
	ctx := internallogging.WithResponseHeadersHolder(context.Background())

	if _, err := selector.Pick(ctx, "codex", "gpt-test", cliproxyexecutor.Options{OriginalRequest: payload}, []*Auth{{ID: "auth-a"}}); err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatalf("PCK shadow changed request payload:\n got %s\nwant %s", payload, original)
	}
	headers := internallogging.GetResponseHeaders(ctx)
	if headers.Get("X-Cpa-Pck-Shadow-Sampled") != "true" || headers.Get("X-Cpa-Pck-Original-Hash") == "" {
		t.Fatalf("PCK shadow diagnostics = %#v", headers)
	}
}

func TestManagerSetSelectorStopsReplacedAffinitySelector(t *testing.T) {
	previous := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Minute})
	manager := &Manager{selector: previous}
	manager.SetSelector(&RoundRobinSelector{})
	select {
	case <-previous.cache.doneCh:
	default:
		t.Fatal("replaced session affinity selector is still running")
	}
}

func TestManagerSetSelectorReusesAffinityCacheDuringHotReload(t *testing.T) {
	previous := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &FillFirstSelector{},
		TTL:      time.Minute,
	})
	next := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:   &RoundRobinSelector{},
		TTL:        2 * time.Minute,
		Rendezvous: true,
	})
	manager := &Manager{selector: previous}
	key := sessionAffinityCacheKey("codex", "hot-reload-session", "gpt-test")
	previous.cache.BindAliases("auth-a", key)

	manager.SetSelector(next)
	t.Cleanup(next.Stop)
	if previous.cache != next.cache {
		t.Fatal("hot reload replaced the active session cache")
	}
	binding, ok := next.cache.GetBinding(key, false)
	if !ok || binding.AuthID != "auth-a" || binding.Generation != 1 {
		t.Fatalf("hot reload binding = %#v, want auth-a generation 1", binding)
	}
}
