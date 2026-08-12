package cacheaffinity

import (
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
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
	second := requestFixture("next", "derived-next")
	second.req.Payload = []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"client-session","input":"next"}`)
	second.opts.OriginalRequest = second.req.Payload

	_, _, firstDecision := Enrich(first.req, first.opts, cfg)
	_, _, secondDecision := Enrich(second.req, second.opts, cfg)
	if firstDecision.RouteKey != secondDecision.RouteKey {
		t.Fatalf("explicit session route changed: %q != %q", firstDecision.RouteKey, secondDecision.RouteKey)
	}
	if firstDecision.UpstreamKey != "client-session" || secondDecision.UpstreamKey != "client-session" {
		t.Fatalf("explicit upstream keys = %q, %q", firstDecision.UpstreamKey, secondDecision.UpstreamKey)
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
	cfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{Enabled: true}}}
	fixture := requestFixture("hello", "derived-prefix-change")
	fixture.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"stable-a","input":"hello"}`)
	fixture.opts.OriginalRequest = fixture.req.Payload
	_, _, first := Enrich(fixture.req, fixture.opts, cfg)
	if first.PrefixChanged {
		t.Fatal("first observation reported a prefix change")
	}
	fixture.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"stable-b","input":"hello"}`)
	fixture.opts.OriginalRequest = fixture.req.Payload
	_, _, second := Enrich(fixture.req, fixture.opts, cfg)
	if !second.PrefixChanged {
		t.Fatal("changed instructions were not detected")
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
