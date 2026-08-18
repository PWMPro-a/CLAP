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

	firstReq, firstOpts, firstDecision := Enrich(first.req, first.opts, cfg)
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
	if firstDecision.PrefixFP == "" {
		t.Fatal("prefix fingerprint is empty")
	}
	if firstDecision.PrefixHeatFP != "" {
		t.Fatalf("small reusable prefix fingerprint = %q, want empty", firstDecision.PrefixHeatFP)
	}
	if got := MetadataValue(firstOpts.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey); got != "" {
		t.Fatalf("options reusable prefix fingerprint = %q, want empty", got)
	}
	if got := MetadataValue(firstReq.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey); got != "" {
		t.Fatalf("request reusable prefix fingerprint = %q, want empty", got)
	}
}

func TestSettingsNormalizesPrefixHeatConfiguration(t *testing.T) {
	defaults := Settings(&internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:           true,
		PrefixHeatEnabled: true,
	}}})
	if !defaults.PrefixHeatEnabled {
		t.Fatal("prefix heat enabled setting was not preserved")
	}
	if defaults.PrefixHeatTTL != defaultPrefixHeatTTL {
		t.Fatalf("default prefix heat TTL = %s, want %s", defaults.PrefixHeatTTL, defaultPrefixHeatTTL)
	}
	if defaults.PrefixHeatMaxEntries != defaults.MaxEntries {
		t.Fatalf("default prefix heat max entries = %d, want max entries %d", defaults.PrefixHeatMaxEntries, defaults.MaxEntries)
	}

	shadow := true
	custom := Settings(&internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:              true,
		PrefixHeatEnabled:    true,
		PrefixHeatShadow:     &shadow,
		PrefixHeatTTL:        "25m",
		PrefixHeatMaxEntries: 1234,
		PrefixHeatMinBytes:   2048,
	}}})
	if !custom.PrefixHeatShadow {
		t.Fatal("prefix heat shadow setting was not preserved")
	}
	if custom.PrefixHeatTTL != 25*time.Minute {
		t.Fatalf("custom prefix heat TTL = %s, want 25m", custom.PrefixHeatTTL)
	}
	if custom.PrefixHeatMaxEntries != 1234 {
		t.Fatalf("custom prefix heat max entries = %d, want 1234", custom.PrefixHeatMaxEntries)
	}
	if custom.PrefixHeatMinBytes != 2048 {
		t.Fatalf("custom prefix heat minimum bytes = %d, want 2048", custom.PrefixHeatMinBytes)
	}
}

func TestSettingsDefaultsPrefixHeatShadowOn(t *testing.T) {
	settings := Settings(&internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:           true,
		PrefixHeatEnabled: true,
	}}})
	if !settings.PrefixHeatShadow {
		t.Fatal("omitted prefix heat shadow setting did not default on")
	}
	shadow := false
	settings = Settings(&internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:           true,
		PrefixHeatEnabled: true,
		PrefixHeatShadow:  &shadow,
	}}})
	if settings.PrefixHeatShadow {
		t.Fatal("explicit false prefix heat shadow setting was not preserved")
	}
}

func TestEnrichPublishesOnlyExactEligibleReusablePrefix(t *testing.T) {
	shortCfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:            true,
		PrefixHeatEnabled:  true,
		PrefixHeatMinBytes: 64,
	}}}
	short := requestFixture("hello", "derived-short-prefix")
	short.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"tiny","input":"hello"}`)
	short.opts.OriginalRequest = short.req.Payload
	_, shortOpts, shortDecision := Enrich(short.req, short.opts, shortCfg)
	if shortDecision.PrefixHeatFP != "" {
		t.Fatalf("short prefix fingerprint = %q, want empty", shortDecision.PrefixHeatFP)
	}
	if got := MetadataValue(shortOpts.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey); got != "" {
		t.Fatalf("short prefix metadata = %q, want empty", got)
	}

	largeCfg := &internalconfig.Config{Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
		Enabled:            true,
		PrefixHeatEnabled:  true,
		PrefixHeatMinBytes: 64,
	}}}
	first := requestFixture("first", "derived-exact-prefix")
	first.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"` + strings.Repeat("alpha", 32) + `","input":"first"}`)
	first.opts.OriginalRequest = first.req.Payload
	second := requestFixture("second", "derived-exact-prefix")
	second.req.Payload = []byte(`{"model":"gpt-5.6-sol","instructions":"` + strings.Repeat("bravo", 32) + `","input":"second"}`)
	second.opts.OriginalRequest = second.req.Payload
	_, firstOpts, firstDecision := Enrich(first.req, first.opts, largeCfg)
	_, secondOpts, secondDecision := Enrich(second.req, second.opts, largeCfg)
	if firstDecision.PrefixHeatFP == "" || secondDecision.PrefixHeatFP == "" {
		t.Fatalf("eligible prefix fingerprints = %q, %q; want non-empty", firstDecision.PrefixHeatFP, secondDecision.PrefixHeatFP)
	}
	if firstDecision.PrefixHeatFP == secondDecision.PrefixHeatFP {
		t.Fatalf("changed exact prefix reused fingerprint %q", firstDecision.PrefixHeatFP)
	}
	if firstDecision.PrefixFP != secondDecision.PrefixFP {
		t.Fatalf("diagnostic fingerprint was unexpectedly recomputed inside inspection interval: %q != %q", firstDecision.PrefixFP, secondDecision.PrefixFP)
	}
	if got := MetadataValue(firstOpts.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey); got != firstDecision.PrefixHeatFP {
		t.Fatalf("first exact prefix metadata = %q, want %q", got, firstDecision.PrefixHeatFP)
	}
	if got := MetadataValue(secondOpts.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey); got != secondDecision.PrefixHeatFP {
		t.Fatalf("second exact prefix metadata = %q, want %q", got, secondDecision.PrefixHeatFP)
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
