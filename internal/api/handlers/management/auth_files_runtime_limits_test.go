package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestListAuthFiles_IncludesRuntimeLimitFields(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       "runtime-limit-auth",
		Provider: "codex",
		Attributes: map[string]string{
			"runtime_only": "true",
		},
		Metadata: map[string]any{
			"type":                           "codex",
			"max_concurrency":                2,
			"rate_limit_max_requests":        3,
			"rate_limit_window_seconds":      60,
			"selection_error_freeze_seconds": 15,
			"disable_sticky_on_next_request": true,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	ginCtx.Request = req

	h.ListAuthFiles(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &payload); errUnmarshal != nil {
		t.Fatalf("decode payload: %v", errUnmarshal)
	}
	files := payload["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("files len = %d, want 1", len(files))
	}
	entry := files[0].(map[string]any)
	if entry["max_concurrency"].(float64) != 2 {
		t.Fatalf("max_concurrency = %#v, want 2", entry["max_concurrency"])
	}
	if entry["rate_limit_max_requests"].(float64) != 3 {
		t.Fatalf("rate_limit_max_requests = %#v, want 3", entry["rate_limit_max_requests"])
	}
	if entry["runtime_current_concurrency"].(float64) != 0 {
		t.Fatalf("runtime_current_concurrency = %#v, want 0", entry["runtime_current_concurrency"])
	}
}
