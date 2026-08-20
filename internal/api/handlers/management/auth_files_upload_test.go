package management

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestUploadAuthFile_NormalizesCodexCPATokenExport(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC().Truncate(time.Second)
	issuedAt := now.Add(-time.Hour).Unix()
	expiresAt := now.Add(10 * 24 * time.Hour).Unix()
	accessToken := testUnsignedJWT(t, map[string]any{
		"iat": issuedAt,
		"exp": expiresAt,
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":      "account-from-token",
			"chatgpt_account_user_id": "account-user-from-token",
			"chatgpt_plan_type":       "plus",
			"chatgpt_user_id":         "user-from-token",
			"poid":                    "org-from-token",
		},
		"https://api.openai.com/profile": map[string]any{
			"email": "USER@example.com",
			"name":  "Token User",
		},
	})
	idTokenJSON := `{"chatgpt_account_id":"account-from-id-token","chatgpt_plan_type":"plus","chatgpt_user_id":"user-from-id-token"}`
	content, errMarshal := json.Marshal(map[string]any{
		"type":          "codex",
		"access_token":  accessToken,
		"refresh_token": "refresh-token",
		"id_token":      idTokenJSON,
		"expired":       false,
		"last_refresh":  "",
		"disabled":      false,
	})
	if errMarshal != nil {
		t.Fatalf("marshal auth file: %v", errMarshal)
	}

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, errPart := writer.CreateFormFile("file", "cpa-exported-codex.json")
	if errPart != nil {
		t.Fatalf("create form file: %v", errPart)
	}
	if _, errWrite := part.Write(content); errWrite != nil {
		t.Fatalf("write form file: %v", errWrite)
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatalf("close multipart writer: %v", errClose)
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
	data, errRead := os.ReadFile(filepath.Join(authDir, "cpa-exported-codex.json"))
	if errRead != nil {
		t.Fatalf("read normalized auth file: %v", errRead)
	}
	var metadata map[string]any
	if errDecode := json.Unmarshal(data, &metadata); errDecode != nil {
		t.Fatalf("decode normalized auth file: %v", errDecode)
	}
	if got := metadata["expired"]; got != time.Unix(expiresAt, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("expired = %#v, want token exp timestamp", got)
	}
	if got := metadata["last_refresh"]; got != time.Unix(issuedAt, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("last_refresh = %#v, want token iat timestamp", got)
	}
	if got := metadata["chatgpt_account_id"]; got != "account-from-id-token" {
		t.Fatalf("chatgpt_account_id = %#v, want id-token account", got)
	}
	if got := metadata["account_id"]; got != "account-from-id-token" {
		t.Fatalf("account_id = %#v, want id-token account", got)
	}
	if got := metadata["chatgpt_plan_type"]; got != "plus" {
		t.Fatalf("chatgpt_plan_type = %#v, want plus", got)
	}
	if got := metadata["email"]; got != "user@example.com" {
		t.Fatalf("email = %#v, want normalized profile email", got)
	}
	if got := metadata["poid"]; got != "org-from-token" {
		t.Fatalf("poid = %#v, want token org", got)
	}

	auth, ok := manager.GetByID("cpa-exported-codex.json")
	if !ok || auth == nil {
		t.Fatalf("expected uploaded auth record to exist")
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled {
		t.Fatalf("auth disabled/status = %v/%s, want active", auth.Disabled, auth.Status)
	}
	if got := auth.Attributes["plan_type"]; got != "plus" {
		t.Fatalf("auth plan_type = %q, want plus", got)
	}
	if _, ok := auth.ExpirationTime(); !ok {
		t.Fatal("auth expiration was not recognized from normalized upload")
	}
	if coreauth.AuthInitializationState(auth) != "" {
		t.Fatalf("initialization state = %q, want empty for plus credential", coreauth.AuthInitializationState(auth))
	}
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

func testUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, errHeader := json.Marshal(map[string]any{"alg": "none"})
	if errHeader != nil {
		t.Fatalf("marshal jwt header: %v", errHeader)
	}
	payload, errPayload := json.Marshal(claims)
	if errPayload != nil {
		t.Fatalf("marshal jwt payload: %v", errPayload)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
