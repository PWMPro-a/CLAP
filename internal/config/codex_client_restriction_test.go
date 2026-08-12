package config

import (
	"strings"
	"testing"
)

func TestParseConfigBytesValidatesCodexClientRestriction(t *testing.T) {
	_, err := ParseConfigBytes([]byte(`codex:
  client-restriction:
    min-codex-version: latest
`))
	if err == nil || !strings.Contains(err.Error(), "min-codex-version") {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
}

func TestParseConfigBytesAllowsExplicitlyDisabledFingerprintGate(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`codex:
  client-restriction:
    engine-fingerprint-signals: []
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if cfg.Codex.ClientRestriction.EngineFingerprintSignals == nil || len(cfg.Codex.ClientRestriction.EngineFingerprintSignals) != 0 {
		t.Fatalf("engine signals = %#v, want explicit empty slice", cfg.Codex.ClientRestriction.EngineFingerprintSignals)
	}
}
