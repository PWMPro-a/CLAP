package cacheaffinity

import (
	"net/http"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestEnrichUsesDerivedConversationInsteadOfSharedCaller(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	first := requestFixture("first-user", "derived-a")
	second := requestFixture("second-user", "derived-b")

	_, firstOpts, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey == "" || secondDecision.RouteKey == "" {
		t.Fatal("route key is empty")
	}
	if firstDecision.RouteKey == secondDecision.RouteKey {
		t.Fatalf("different derived conversations shared route key %q", firstDecision.RouteKey)
	}
	if !firstDecision.Active || !secondDecision.Active {
		t.Fatal("enabled coordinator was not active")
	}
	if got := MetadataValue(firstOpts.Metadata, cliproxyexecutor.CacheAffinityRouteKeyMetadataKey); got != firstDecision.RouteKey {
		t.Fatalf("metadata route key = %q, want %q", got, firstDecision.RouteKey)
	}
}

func TestEnrichExplicitPromptCacheKeyStaysStable(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	first := requestFixture("first", "derived-first")
	first.req.Payload = []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"client-session","input":"first"}`)
	first.opts.OriginalRequest = first.req.Payload
	delete(first.req.Metadata, cliproxyexecutor.DerivedSessionIDMetadataKey)
	delete(first.opts.Metadata, cliproxyexecutor.DerivedSessionIDMetadataKey)
	second := requestFixture("next", "derived-next")
	second.req.Payload = []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"client-session","input":"next"}`)
	second.opts.OriginalRequest = second.req.Payload
	delete(second.req.Metadata, cliproxyexecutor.DerivedSessionIDMetadataKey)
	delete(second.opts.Metadata, cliproxyexecutor.DerivedSessionIDMetadataKey)

	_, _, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey != secondDecision.RouteKey {
		t.Fatalf("explicit session route changed: %q != %q", firstDecision.RouteKey, secondDecision.RouteKey)
	}
	if firstDecision.UpstreamKey != "client-session" || secondDecision.UpstreamKey != "client-session" {
		t.Fatalf("explicit upstream keys = %q, %q", firstDecision.UpstreamKey, secondDecision.UpstreamKey)
	}
}

func TestEnrichStableIdentityOutranksChangingClientRequestID(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	first := requestFixture("first", "derived-stable-request-id")
	first.opts.Headers.Set("X-Client-Request-Id", "request-1")
	second := requestFixture("second", "derived-stable-request-id")
	second.opts.Headers.Set("X-Client-Request-Id", "request-2")

	_, _, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey != secondDecision.RouteKey {
		t.Fatalf("changing request IDs split a stable derived route: %q != %q", firstDecision.RouteKey, secondDecision.RouteKey)
	}
	if firstDecision.Source != "derived" || secondDecision.Source != "derived" {
		t.Fatalf("sources = %q, %q; want derived", firstDecision.Source, secondDecision.Source)
	}
}

func TestEnrichPromptCacheKeyOutranksChangingClientRequestID(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	first := requestFixture("first", "")
	first.req.Payload = []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"stable-cache","input":"first"}`)
	first.opts.OriginalRequest = first.req.Payload
	first.opts.Headers.Set("X-Client-Request-Id", "request-1")
	second := requestFixture("second", "")
	second.req.Payload = []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"stable-cache","input":"second"}`)
	second.opts.OriginalRequest = second.req.Payload
	second.opts.Headers.Set("X-Client-Request-Id", "request-2")

	_, _, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey != secondDecision.RouteKey {
		t.Fatalf("changing request IDs split prompt cache route: %q != %q", firstDecision.RouteKey, secondDecision.RouteKey)
	}
	if firstDecision.UpstreamKey != "stable-cache" || secondDecision.UpstreamKey != "stable-cache" {
		t.Fatalf("upstream keys = %q, %q; want stable-cache", firstDecision.UpstreamKey, secondDecision.UpstreamKey)
	}
}

func TestEnrichRouteKeySurvivesModelSwitchWhileCacheKeySplits(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	first := requestFixture("first", "derived-model-switch")
	second := requestFixture("next", "derived-model-switch")
	second.req.Model = "gpt-5.4"
	second.req.Payload = []byte(`{"model":"gpt-5.4","input":"next"}`)
	second.opts.OriginalRequest = second.req.Payload

	_, _, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey != secondDecision.RouteKey {
		t.Fatalf("route key changed across model switch: %q != %q", firstDecision.RouteKey, secondDecision.RouteKey)
	}
	if firstDecision.UpstreamKey == secondDecision.UpstreamKey {
		t.Fatalf("different model families shared upstream cache key %q", firstDecision.UpstreamKey)
	}
}

func TestEnrichShadowPublishesInactiveDecision(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true, Shadow: true}}}
	fixture := requestFixture("hello", "derived-shadow")
	_, opts, decision := Enrich(fixture.req, fixture.opts, cfg)
	if decision.Active {
		t.Fatal("shadow decision was active")
	}
	if value := MetadataValue(opts.Metadata, cliproxyexecutor.CacheAffinityRouteKeyMetadataKey); value != "" {
		t.Fatalf("shadow metadata leaked active route key %q", value)
	}
}

func TestEnrichDetectsStablePrefixChange(t *testing.T) {
	routeKey := stableID("route", "derived:derived-prefix-change")
	firstRoot := parseRoot([]byte(`{"model":"gpt-5.6-sol","instructions":"stable-a","input":"hello"}`))
	secondRoot := parseRoot([]byte(`{"model":"gpt-5.6-sol","instructions":"stable-b","input":"hello"}`))
	started := time.Unix(1_700_000_000, 0)
	_, firstChanged := inspectPrefixAt(routeKey, "gpt-5.6-sol", firstRoot, 65536, started, 5*time.Second)
	if firstChanged {
		t.Fatal("first observation reported a prefix change")
	}
	_, skippedChanged := inspectPrefixAt(routeKey, "gpt-5.6-sol", secondRoot, 65536, started.Add(time.Second), 5*time.Second)
	if skippedChanged {
		t.Fatal("rate-limited observation reported a prefix change")
	}
	_, secondChanged := inspectPrefixAt(routeKey, "gpt-5.6-sol", secondRoot, 65536, started.Add(6*time.Second), 5*time.Second)
	if !secondChanged {
		t.Fatal("changed instructions were not detected")
	}
}

func TestEnrichSkipsRepeatedLongPayloadPrefixInspection(t *testing.T) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	fixture := requestFixture("hello", "derived-long-prefix")
	fixture.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"` + strings.Repeat("stable ", 20000) + `","input":"hello"}`)
	fixture.opts.OriginalRequest = fixture.req.Payload
	before := Snapshot()
	_, _, first := Enrich(fixture.req, fixture.opts, cfg)
	_, _, second := Enrich(fixture.req, fixture.opts, cfg)
	after := Snapshot()
	if first.PrefixFP == "" || second.PrefixFP != first.PrefixFP {
		t.Fatalf("prefix fingerprints = %q, %q", first.PrefixFP, second.PrefixFP)
	}
	if after.PrefixInspected-before.PrefixInspected != 1 {
		t.Fatalf("prefix inspected delta = %d, want 1", after.PrefixInspected-before.PrefixInspected)
	}
	if after.PrefixSkipped-before.PrefixSkipped != 1 {
		t.Fatalf("prefix skipped delta = %d, want 1", after.PrefixSkipped-before.PrefixSkipped)
	}
}

func BenchmarkEnrichActive(b *testing.B) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true, MaxEntries: 65536}}}
	fixture := requestFixture("benchmark", "derived-benchmark")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Enrich(fixture.req, fixture.opts, cfg)
	}
}

func BenchmarkEnrichActiveLongPayload(b *testing.B) {
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true, MaxEntries: 65536}}}
	fixture := requestFixture("benchmark", "derived-long-benchmark")
	fixture.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"` + strings.Repeat("stable ", 20000) + `","input":"benchmark"}`)
	fixture.opts.OriginalRequest = fixture.req.Payload
	b.ReportAllocs()
	b.SetBytes(int64(len(fixture.req.Payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Enrich(fixture.req, fixture.opts, cfg)
	}
}

func parseRoot(payload []byte) gjson.Result {
	return gjson.ParseBytes(payload)
}

type coordinatorFixture struct {
	req  cliproxyexecutor.Request
	opts cliproxyexecutor.Options
}

func requestFixture(user, derived string) coordinatorFixture {
	payload := []byte(`{"model":"gpt-5.6-sol","instructions":"stable","tools":[{"type":"function","name":"run"}],"input":"` + user + `"}`)
	return coordinatorFixture{
		req: cliproxyexecutor.Request{
			Model:   "gpt-5.6-sol",
			Payload: payload,
			Metadata: map[string]any{
				cliproxyexecutor.DerivedSessionIDMetadataKey: derived,
			},
		},
		opts: cliproxyexecutor.Options{
			Headers:         http.Header{},
			OriginalRequest: payload,
			SourceFormat:    sdktranslator.FormatOpenAIResponse,
			Metadata: map[string]any{
				cliproxyexecutor.DerivedSessionIDMetadataKey: derived,
				cliproxyexecutor.CallerScopeMetadataKey:      "shared-caller",
			},
		},
	}
}
