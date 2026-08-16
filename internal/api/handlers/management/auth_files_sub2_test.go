package management

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
)

func TestWriteAuthFileExpandsSub2Bundle(t *testing.T) {
	authDir := t.TempDir()
	payload, err := json.Marshal(map[string]any{
		"type": "sub2api-data",
		"accounts": []map[string]any{
			{
				"name": "one", "type": "oauth", "platform": "openai", "priority": 1,
				"credentials": map[string]any{
					"access_token": "access-one", "refresh_token": "refresh-one",
					"chatgpt_account_id": "account-one", "email": "one@example.com", "plan_type": "pro",
				},
			},
			{
				"name": "two", "type": "oauth", "platform": "openai", "priority": 2,
				"credentials": map[string]any{
					"access_token": "access-two", "refresh_token": "refresh-two",
					"account_id": "account-two", "email": "two@example.com", "plan_type": "team",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	handler := &Handler{cfg: &config.Config{AuthDir: authDir}}
	websockets := true
	if err := handler.writeAuthFileWithDefaults(
		context.Background(),
		"sub2-export.json",
		payload,
		authFileImportDefaults{Websockets: &websockets},
	); err != nil {
		t.Fatalf("writeAuthFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "sub2-export.json")); !os.IsNotExist(err) {
		t.Fatalf("source bundle should not remain as an unknown auth file")
	}
	entries, err := os.ReadDir(authDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("auth files = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "codex-sub2-") {
			t.Fatalf("unexpected generated filename %q", entry.Name())
		}
		data, errRead := os.ReadFile(filepath.Join(authDir, entry.Name()))
		if errRead != nil {
			t.Fatalf("ReadFile: %v", errRead)
		}
		auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{
			Config:  handler.cfg,
			AuthDir: authDir,
		}, filepath.Join(authDir, entry.Name()), data)
		if errSynthesize != nil {
			t.Fatalf("SynthesizeAuthFile(%q): %v", entry.Name(), errSynthesize)
		}
		if len(auths) != 1 || auths[0].Provider != "codex" {
			t.Fatalf("generated file %q is not a runnable Codex auth", entry.Name())
		}
		var metadata map[string]any
		if err = json.Unmarshal(data, &metadata); err != nil {
			t.Fatalf("decode generated file %q: %v", entry.Name(), err)
		}
		if enabled, ok := metadata["websockets"].(bool); !ok || !enabled {
			t.Fatalf("generated file %q websockets = %#v, want true", entry.Name(), metadata["websockets"])
		}
		if fingerprint, _ := metadata["codex_identity_fingerprint"].(string); strings.TrimSpace(fingerprint) == "" {
			t.Fatalf("generated file %q has no Codex identity fingerprint", entry.Name())
		}
	}
}

func TestPrepareCodexIdentityFingerprintForImportInheritsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-member.json")
	existing := []byte(`{"type":"codex","email":"old@example.com","codex_identity_fingerprint":"stable-member","access_token":"old"}`)
	if errWrite := os.WriteFile(path, existing, 0o600); errWrite != nil {
		t.Fatalf("write existing auth file: %v", errWrite)
	}
	incoming := []byte(`{"type":"codex","email":"new@example.com","codex_identity_fingerprint":"replacement-member","access_token":"new"}`)
	prepared, err := prepareCodexIdentityFingerprintForImport(path, incoming)
	if err != nil {
		t.Fatalf("prepare import: %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(prepared, &metadata); err != nil {
		t.Fatalf("decode prepared import: %v", err)
	}
	if got, _ := metadata["codex_identity_fingerprint"].(string); got != "stable-member" {
		t.Fatalf("prepared fingerprint = %q, want stable-member", got)
	}
	if got, _ := metadata["access_token"].(string); got != "new" {
		t.Fatalf("prepared access token = %q, want new", got)
	}
}
