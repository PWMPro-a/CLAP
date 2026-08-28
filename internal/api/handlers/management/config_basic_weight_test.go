package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestNormalizeRoutingStrategyWeightedRoundRobin(t *testing.T) {
	for _, input := range []string{"weighted-round-robin", "weightedroundrobin", "wrr"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "weighted-round-robin" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want weighted-round-robin, true", input, got, ok)
		}
	}
}

func TestNormalizeRoutingStrategyConcurrencyBalanced(t *testing.T) {
	for _, input := range []string{"", "concurrency-balanced", "concurrencybalanced", "least-concurrent", "least-connections"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "concurrency-balanced" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want concurrency-balanced, true", input, got, ok)
		}
	}
}

func TestRoutingHighCacheModeRoundTrip(t *testing.T) {
	h := &Handler{cfg: &config.Config{Routing: config.RoutingConfig{HighCacheMode: true}}}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/routing/high-cache-mode", nil)
	h.GetRoutingHighCacheMode(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, "true") {
		t.Fatalf("body = %s, want true", got)
	}
}

func TestRoutingNewCandidateModeRoundTrip(t *testing.T) {
	h := &Handler{cfg: &config.Config{Routing: config.RoutingConfig{NewCandidateMode: true}}}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/routing/new-candidate-mode", nil)
	h.GetRoutingNewCandidateMode(ctx)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "true") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
