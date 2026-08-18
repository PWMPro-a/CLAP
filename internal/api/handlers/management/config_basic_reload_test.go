package management

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPutConfigYAMLReloadsRuntimeConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("codex:\n  tail-burst:\n    enabled: false\n"), 0o600); errWrite != nil {
		t.Fatalf("write initial config: %v", errWrite)
	}

	handler := NewHandler(&config.Config{}, configPath, nil)
	reloads := make(chan *config.Config, 1)
	handler.SetConfigReloadHook(func(_ context.Context, next *config.Config) {
		reloads <- next
	})

	body := []byte(`codex:
  tail-burst:
    enabled: true
    snapshot-ttl: "90s"
    trigger-remaining-ratio: 0.2
    expiry-window: "10m"
    normal-max-concurrency: 8
    max-concurrency: 300
    quota-collector:
      enabled: true
      interval: "15s"
      max-concurrency: 10
      timeout: "8s"
`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", bytes.NewReader(body))

	handler.PutConfigYAML(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	select {
	case reloaded := <-reloads:
		tailBurst := reloaded.Codex.TailBurst
		if !tailBurst.Enabled || tailBurst.SnapshotTTL != "90s" || tailBurst.NormalMaxConcurrency != 8 || tailBurst.MaxConcurrency != 300 {
			t.Fatalf("reloaded tail-burst config = %#v", tailBurst)
		}
		if !tailBurst.QuotaCollector.Enabled || tailBurst.QuotaCollector.Interval != "15s" || tailBurst.QuotaCollector.MaxConcurrency != 10 {
			t.Fatalf("reloaded quota collector config = %#v", tailBurst.QuotaCollector)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime config reload was not triggered")
	}
}
