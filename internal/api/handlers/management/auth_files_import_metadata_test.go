package management

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestListAuthFilesIncludesImportMetadataFromManager(t *testing.T) {
	authDir := t.TempDir()
	fileName := "codex-imported.json"
	filePath := filepath.Join(authDir, fileName)
	if err := os.WriteFile(filePath, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": filePath,
		},
		Metadata: map[string]any{
			"codex_identity_fingerprint": "stable-device-a",
			"cpamp_import": map[string]any{
				"version":       float64(1),
				"source":        "manual",
				"method":        "file_upload",
				"platform_id":   "cpa",
				"platform_name": "CPA 文件",
				"imported_by":   "cpa-manager-plus",
				"imported_at":   "2026-08-16T07:30:45Z",
				"secret":        "must-not-leak",
			},
		},
	}
	if _, err := manager.Register(context.Background(), record); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = &memoryAuthStore{}

	entry := firstAuthFileEntry(t, h)
	assertImportMetadataEntry(t, entry, "file_upload", "CPA 文件")
	if got := entry["codex_identity_fingerprint"]; got != "stable-device-a" {
		t.Fatalf("codex_identity_fingerprint = %#v, want stable-device-a", got)
	}
}

func TestListAuthFilesFromDiskIncludesImportMetadata(t *testing.T) {
	authDir := t.TempDir()
	filePath := filepath.Join(authDir, "codex-supply.json")
	data := []byte(`{"type":"codex","codex_identity_fingerprint":"stable-device-b","cpamp_import":{"version":1,"source":"supply","method":"manual_supply","platform_id":"supplier-a","platform_name":"平台 A","imported_by":"cpa-manager-plus","imported_at":"2026-08-16T07:30:45Z","secret":"must-not-leak"}}`)
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)

	entry := firstAuthFileEntry(t, h)
	assertImportMetadataEntry(t, entry, "manual_supply", "平台 A")
	if got := entry["codex_identity_fingerprint"]; got != "stable-device-b" {
		t.Fatalf("codex_identity_fingerprint = %#v, want stable-device-b", got)
	}
}

func assertImportMetadataEntry(t *testing.T, entry map[string]any, method string, platformName string) {
	t.Helper()
	metadata, ok := entry["cpamp_import"].(map[string]any)
	if !ok {
		t.Fatalf("cpamp_import = %#v", entry["cpamp_import"])
	}
	if metadata["method"] != method || metadata["platform_name"] != platformName {
		t.Fatalf("cpamp_import = %#v", metadata)
	}
	if _, leaked := metadata["secret"]; leaked {
		t.Fatalf("unexpected private import metadata: %#v", metadata)
	}
}
