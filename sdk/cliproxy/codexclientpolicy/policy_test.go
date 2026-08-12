package codexclientpolicy

import (
	"net/http"
	"strings"
	"testing"
)

func TestEvaluateIdentityVersionAndFingerprint(t *testing.T) {
	policy := Policy{
		MinCodexVersion:          "0.142.0",
		MaxCodexVersion:          "0.200.0",
		EngineFingerprintSignals: DefaultEngineFingerprintSignals,
	}
	tests := []struct {
		name    string
		headers http.Header
		want    bool
		reason  string
	}{
		{name: "official", headers: http.Header{"User-Agent": {"codex_cli_rs/0.142.0 (linux)"}, "X-Codex-Window-Id": {"window"}}, want: true, reason: ReasonOfficialUserAgent},
		{name: "missing fingerprint", headers: http.Header{"User-Agent": {"codex_cli_rs/0.142.0 (linux)"}}, reason: ReasonFingerprintMissing},
		{name: "too old", headers: http.Header{"User-Agent": {"codex_cli_rs/0.141.0 (linux)"}, "X-Codex-Window-Id": {"window"}}, reason: ReasonVersionTooLow},
		{name: "unknown client", headers: http.Header{"User-Agent": {"curl/8.0"}, "X-Codex-Window-Id": {"window"}}, reason: ReasonIdentityMissing},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Evaluate(Request{Headers: test.headers}, policy)
			if got.Allowed != test.want || got.Reason != test.reason {
				t.Fatalf("Evaluate() = %+v, want allowed=%v reason=%q", got, test.want, test.reason)
			}
		})
	}
}

func TestDefaultEngineFingerprintSignalsMatchSub2Defaults(t *testing.T) {
	if len(DefaultEngineFingerprintSignals) != 4 {
		t.Fatalf("default signal count = %d, want 4", len(DefaultEngineFingerprintSignals))
	}
	for index, signal := range DefaultEngineFingerprintSignals {
		wantRequired := index == 0
		if signal.Required != wantRequired {
			t.Fatalf("default signal %d required = %v, want %v", index, signal.Required, wantRequired)
		}
	}
}

func TestEvaluateFingerprintRequiredAndVariantsOr(t *testing.T) {
	signals := []EngineFingerprintSignal{
		{Type: SignalHeaderPrefix, Match: []string{"x-codex-"}, Required: true},
		{Type: SignalHeaderExact, Match: []string{"session-id", "session_id"}, Required: true},
		{Type: SignalBodyPath, Match: []string{"client_metadata.x-codex-window-id", "client_metadata.x-codex-installation-id"}, Required: true},
	}
	headers := make(http.Header)
	headers.Set("X-Codex-Window-Id", "window")
	headers.Set("session_id", "session")
	body := []byte(`{"client_metadata":{"x-codex-installation-id":"install"}}`)
	if !EvaluateEngineFingerprint(headers, body, signals) {
		t.Fatal("required AND and row variant OR should match")
	}
	if EvaluateEngineFingerprint(headers, nil, signals) {
		t.Fatal("missing required body path unexpectedly matched")
	}
	for index := range signals {
		signals[index].Required = false
	}
	if !EvaluateEngineFingerprint(nil, nil, signals) {
		t.Fatal("no required signals should disable the fingerprint gate")
	}
}

func TestEvaluateBlacklistPrecedesWhitelistAndAppServer(t *testing.T) {
	policy := Policy{
		AllowAppServerClients: true,
		Whitelist:             []ClientEntry{{Originator: "opencode", UAContains: []string{"opencode/"}, SkipEngineFingerprint: true}},
		Blacklist:             []ClientEntry{{Originator: "opencode"}},
	}
	result := Evaluate(Request{Headers: http.Header{"User-Agent": {"opencode/1.0"}, "Originator": {"opencode"}}}, policy)
	if result.Allowed || result.Reason != ReasonBlacklisted {
		t.Fatalf("Evaluate() = %+v, want blacklist rejection", result)
	}
}

func TestEvaluateWhitelistAndAppServer(t *testing.T) {
	whitelist := Policy{Whitelist: []ClientEntry{{Originator: "opencode", UAContains: []string{"opencode/"}, SkipEngineFingerprint: true}}}
	result := Evaluate(Request{Headers: http.Header{"User-Agent": {"opencode/1.0"}, "Originator": {"opencode"}}}, whitelist)
	if !result.Allowed || result.Reason != ReasonWhitelisted {
		t.Fatalf("whitelist result = %+v", result)
	}

	appServer := Policy{AllowAppServerClients: true, EngineFingerprintSignals: DefaultEngineFingerprintSignals}
	result = Evaluate(Request{Headers: http.Header{"User-Agent": {"third-party/1.0"}, "X-Codex-Window-Id": {"window"}}}, appServer)
	if !result.Allowed || result.Reason != ReasonAppServer {
		t.Fatalf("app-server result = %+v", result)
	}
}

func TestValidatePolicy(t *testing.T) {
	valid := Policy{
		MinCodexVersion:          "0.142.0",
		MaxCodexVersion:          "0.200.0",
		Whitelist:                []ClientEntry{{Originator: "opencode", UAContains: []string{"opencode/"}}},
		Blacklist:                []ClientEntry{{UAContains: []string{"curl/"}}},
		EngineFingerprintSignals: DefaultEngineFingerprintSignals,
	}
	if err := ValidatePolicy(valid); err != nil {
		t.Fatalf("ValidatePolicy(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Policy)
		want   string
	}{
		{name: "invalid minimum", mutate: func(p *Policy) { p.MinCodexVersion = "latest" }, want: "min-codex-version"},
		{name: "inverted range", mutate: func(p *Policy) { p.MinCodexVersion, p.MaxCodexVersion = "0.201.0", "0.200.0" }, want: "greater than or equal"},
		{name: "dead whitelist", mutate: func(p *Policy) { p.Whitelist = []ClientEntry{{Originator: "opencode"}} }, want: "whitelist entry"},
		{name: "empty blacklist", mutate: func(p *Policy) { p.Blacklist = []ClientEntry{{}} }, want: "blacklist entry"},
		{name: "invalid signal", mutate: func(p *Policy) {
			p.EngineFingerprintSignals = []EngineFingerprintSignal{{Type: "cookie", Match: []string{"x"}}}
		}, want: "invalid type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := ValidatePolicy(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidatePolicy() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	policy := Policy{
		MinCodexVersion:          "0.142.0",
		MaxCodexVersion:          "0.200.0",
		EngineFingerprintSignals: DefaultEngineFingerprintSignals,
	}
	headers := http.Header{
		"User-Agent":        {"codex_cli_rs/0.142.0 (linux)"},
		"X-Codex-Window-Id": {"window"},
	}
	request := Request{Headers: headers}
	b.ReportAllocs()
	for b.Loop() {
		result := Evaluate(request, policy)
		if !result.Allowed {
			b.Fatalf("Evaluate() = %+v", result)
		}
	}
}

func BenchmarkEvaluateRequiredBodyPath(b *testing.B) {
	policy := Policy{
		EngineFingerprintSignals: []EngineFingerprintSignal{
			{Type: SignalBodyPath, Match: []string{"client_metadata.x-codex-window-id"}, Required: true},
		},
	}
	request := Request{
		Headers: http.Header{"User-Agent": {"codex_cli_rs/0.142.0 (linux)"}},
		Body:    []byte(`{"client_metadata":{"x-codex-window-id":"window"}}`),
	}
	b.ReportAllocs()
	for b.Loop() {
		result := Evaluate(request, policy)
		if !result.Allowed {
			b.Fatalf("Evaluate() = %+v", result)
		}
	}
}
