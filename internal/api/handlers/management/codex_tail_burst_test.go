package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPutCodexTailBurstQuotaStoresFreshSnapshotAndIgnoresStaleSample(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "codex-auth", Provider: "codex", Status: coreauth.StatusActive}
	registered, errRegister := manager.Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	now := time.Now().UTC().Truncate(time.Second)

	status, payload := putCodexTailBurstQuota(t, handler, map[string]any{
		"auth_index": registered.Index,
		"model":      "gpt-5-codex",
		"used_ratio": 0.99,
		"sampled_at": now.Format(time.RFC3339),
		"generation": 2,
	})
	if status != http.StatusOK || payload["accepted"] != true {
		t.Fatalf("fresh snapshot response = status:%d payload:%#v", status, payload)
	}

	status, payload = putCodexTailBurstQuota(t, handler, map[string]any{
		"auth_index": registered.Index,
		"model":      "gpt-5-codex",
		"used_ratio": 0.10,
		"sampled_at": now.Add(time.Minute).Format(time.RFC3339),
		"generation": 1,
	})
	if status != http.StatusOK || payload["accepted"] != false {
		t.Fatalf("stale snapshot response = status:%d payload:%#v", status, payload)
	}
	snapshot, ok := manager.CodexQuotaSnapshot(registered.ID, "gpt-5-codex")
	if !ok || snapshot.UsedRatio != 0.99 || snapshot.Generation != 2 {
		t.Fatalf("stored snapshot = %#v, found:%t", snapshot, ok)
	}
}

func putCodexTailBurstQuota(t *testing.T, handler *Handler, body map[string]any) (int, map[string]any) {
	t.Helper()
	encoded, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/codex-tail-burst/quota", bytes.NewReader(encoded))
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	handler.PutCodexTailBurstQuota(ginCtx)
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(recorder.Body.Bytes(), &payload); errUnmarshal != nil {
		t.Fatalf("decode response: %v; body=%s", errUnmarshal, recorder.Body.String())
	}
	return recorder.Code, payload
}
