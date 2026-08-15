package management

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestUploadAuthFile_AppliesCodexImportDefaults(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	files := []struct {
		name    string
		content string
	}{
		{name: "codex-default.json", content: `{"type":"codex","email":"default@example.com"}`},
		{name: "codex-explicit.json", content: `{"type":"codex","websockets":false}`},
		{name: "claude-default.json", content: `{"type":"claude"}`},
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("default_websockets", "true"); err != nil {
		t.Fatalf("failed to write import default: %v", err)
	}
	for _, file := range files {
		part, err := writer.CreateFormFile("file", file.name)
		if err != nil {
			t.Fatalf("failed to create multipart file: %v", err)
		}
		if _, err = part.Write([]byte(file.content)); err != nil {
			t.Fatalf("failed to write multipart content: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req
	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	assertWebsockets := func(name string, want any, exists bool) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(authDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var metadata map[string]any
		if err = json.Unmarshal(data, &metadata); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		got, gotExists := metadata["websockets"]
		if gotExists != exists || (exists && got != want) {
			t.Fatalf("%s websockets = %#v (exists=%v), want %#v (exists=%v)", name, got, gotExists, want, exists)
		}
	}
	assertWebsockets("codex-default.json", true, true)
	assertWebsockets("codex-explicit.json", false, true)
	assertWebsockets("claude-default.json", nil, false)
}

func TestPrepareImportedTeamInitialization(t *testing.T) {
	payload := []byte(`{"type":"codex","plan_type":"team","access_token":"access","refresh_token":"refresh"}`)
	prepared, err := prepareImportedTeamInitialization(payload)
	if err != nil {
		t.Fatalf("prepareImportedTeamInitialization: %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(prepared, &metadata); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if metadata[coreauth.MetadataInitializationState] != string(coreauth.InitializationStateInitializing) {
		t.Fatalf("initialization state = %#v", metadata[coreauth.MetadataInitializationState])
	}
	if generation, _ := metadata[coreauth.MetadataInitializationGeneration].(string); generation == "" {
		t.Fatal("initialization generation is empty")
	}
}

func TestUploadAuthFile_RejectsInvalidImportDefaults(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("default_websockets", "sometimes"); err != nil {
		t.Fatalf("failed to write import default: %v", err)
	}
	part, err := writer.CreateFormFile("file", "codex-invalid-default.json")
	if err != nil {
		t.Fatalf("failed to create multipart file: %v", err)
	}
	if _, err = part.Write([]byte(`{"type":"codex"}`)); err != nil {
		t.Fatalf("failed to write multipart content: %v", err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req
	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	if _, err = os.Stat(filepath.Join(authDir, "codex-invalid-default.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid import defaults must not write an auth file")
	}
}

func TestUploadAuthFile_PreservesPriorityAttributes(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	content := `{"type":"codex","email":"midai0530@gmail.com","priority":98}`

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "codex-midai0530@gmail.com-plus.json")
	if err != nil {
		t.Fatalf("failed to create multipart file: %v", err)
	}
	if _, err = part.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write multipart content: %v", err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request = req

	h.UploadAuthFile(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err = json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if status, _ := payload["status"].(string); status != "ok" {
		t.Fatalf("expected status ok, got %#v", payload["status"])
	}

	auth, ok := manager.GetByID("codex-midai0530@gmail.com-plus.json")
	if !ok || auth == nil {
		t.Fatalf("expected uploaded auth record to exist")
	}
	if got := auth.Attributes["priority"]; got != "98" {
		t.Fatalf("priority attribute = %q, want %q", got, "98")
	}
	if got := auth.Metadata["priority"]; got != float64(98) {
		t.Fatalf("priority metadata = %#v, want 98", got)
	}
}
