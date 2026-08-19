package executor

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestParseCodexTailBurstQuotaSnapshotUsesMostConstrainedWindow(t *testing.T) {
	sampledAt := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	snapshot, ok := parseCodexTailBurstQuotaSnapshot([]byte(`{
  "rate_limit": {
    "primary_window": {"used_percent": 97.2},
    "secondary_window": {"used_percent": 98.7}
  }
}`), sampledAt, 90*time.Second)
	if !ok {
		t.Fatal("parseCodexTailBurstQuotaSnapshot returned no snapshot")
	}
	if snapshot.Window != "secondary" {
		t.Fatalf("window = %q, want secondary", snapshot.Window)
	}
	if math.Abs(snapshot.UsedRatio-0.987) > 1e-9 || math.Abs(snapshot.RemainingRatio-0.013) > 1e-9 {
		t.Fatalf("snapshot ratios = %#v", snapshot)
	}
	if !snapshot.ExpiresAt.Equal(sampledAt.Add(90 * time.Second)) {
		t.Fatalf("expires at = %s, want %s", snapshot.ExpiresAt, sampledAt.Add(90*time.Second))
	}
}

func TestParseCodexTailBurstQuotaSnapshotPrefersWeeklyOverMonthly(t *testing.T) {
	sampledAt := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	snapshot, ok := parseCodexTailBurstQuotaSnapshot([]byte(`{
  "rate_limit": {
    "primary_window": {"used_percent": 97, "limit_window_seconds": 604800},
    "secondary_window": {"used_percent": 100, "limit_window_seconds": 2592000}
  }
}`), sampledAt, 90*time.Second)
	if !ok {
		t.Fatal("parseCodexTailBurstQuotaSnapshot returned no snapshot")
	}
	if snapshot.Window != "primary" || math.Abs(snapshot.UsedRatio-0.97) > 1e-9 {
		t.Fatalf("snapshot = %#v, want weekly primary at 97%%", snapshot)
	}
}

func TestParseCodexTailBurstQuotaSnapshotRejectsMissingUsage(t *testing.T) {
	if _, ok := parseCodexTailBurstQuotaSnapshot([]byte(`{"rate_limit":{"primary_window":{}}}`), time.Now(), time.Minute); ok {
		t.Fatal("missing used_percent produced a snapshot")
	}
}

func TestResolveCodexTailBurstQuotaCollectorSettings(t *testing.T) {
	disabled, enabled := resolveCodexTailBurstQuotaCollectorSettings(&config.Config{})
	if enabled {
		t.Fatal("collector enabled while tail burst is disabled")
	}
	if disabled.interval != defaultCodexQuotaCollectorInterval {
		t.Fatalf("disabled interval = %s", disabled.interval)
	}

	settings, enabled := resolveCodexTailBurstQuotaCollectorSettings(&config.Config{
		Codex: config.CodexConfig{TailBurst: config.CodexTailBurstConfig{
			Enabled:     true,
			SnapshotTTL: "2m",
			QuotaCollector: config.CodexTailBurstQuotaCollectorConfig{
				Interval:       "30s",
				MaxConcurrency: 99,
				Timeout:        "3s",
			},
		}},
	})
	if !enabled {
		t.Fatal("collector disabled while tail burst is enabled")
	}
	if settings.interval != 30*time.Second || settings.timeout != 3*time.Second || settings.snapshotTTL != 2*time.Minute {
		t.Fatalf("unexpected settings: %#v", settings)
	}
	if settings.maxConcurrency != 16 {
		t.Fatalf("max concurrency = %d, want 16", settings.maxConcurrency)
	}
}

func TestResolveCodexTailBurstQuotaCollectorSettingsForCacheAffinity(t *testing.T) {
	settings, enabled := resolveCodexTailBurstQuotaCollectorSettings(&config.Config{
		Codex: config.CodexConfig{
			CacheAffinity: config.CodexCacheAffinityConfig{Enabled: true},
			TailBurst: config.CodexTailBurstConfig{QuotaCollector: config.CodexTailBurstQuotaCollectorConfig{
				Enabled:        true,
				Interval:       "15s",
				MaxConcurrency: 2,
			}},
		},
	})
	if !enabled {
		t.Fatal("collector disabled while cache affinity is enabled")
	}
	if settings.interval != 15*time.Second || settings.maxConcurrency != 2 {
		t.Fatalf("unexpected cache-affinity collector settings: %#v", settings)
	}
}

func TestCollectCodexTailBurstQuotaSnapshotsPublishesBeforeSlowCredentialFinishes(t *testing.T) {
	manager := cliproxyauth.NewManager(nil, nil, nil)
	for _, authID := range []string{"fast", "slow"} {
		if _, errRegister := manager.Register(t.Context(), &cliproxyauth.Auth{
			ID:       authID,
			Provider: "codex",
			Status:   cliproxyauth.StatusActive,
			Metadata: map[string]any{"access_token": "test-token"},
		}); errRegister != nil {
			t.Fatalf("register %s: %v", authID, errRegister)
		}
	}

	slowRelease := make(chan struct{})
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		collectCodexTailBurstQuotaSnapshotsWithFetcher(
			context.Background(),
			manager,
			&config.Config{},
			codexTailBurstQuotaCollectorSettings{
				maxConcurrency: 2,
				timeout:        time.Second,
				snapshotTTL:    time.Minute,
			},
			func(ctx context.Context, _ *config.Config, auth *cliproxyauth.Auth, ttl time.Duration) (cliproxyauth.CodexQuotaSnapshot, error) {
				if auth.ID == "slow" {
					select {
					case <-ctx.Done():
						return cliproxyauth.CodexQuotaSnapshot{}, ctx.Err()
					case <-slowRelease:
						return cliproxyauth.CodexQuotaSnapshot{}, errors.New("released slow credential")
					}
				}
				now := time.Now()
				return cliproxyauth.CodexQuotaSnapshot{
					UsedRatio: 0.9,
					SampledAt: now,
					ExpiresAt: now.Add(ttl),
				}, nil
			},
		)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := manager.CodexQuotaSnapshot("fast", "*"); ok {
			break
		}
		if time.Now().After(deadline) {
			close(slowRelease)
			<-collectorDone
			t.Fatal("fast quota snapshot was not published while the slow credential was still running")
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case <-collectorDone:
		t.Fatal("collector finished before the slow credential was released")
	default:
	}
	close(slowRelease)
	select {
	case <-collectorDone:
	case <-time.After(time.Second):
		t.Fatal("collector did not finish after the slow credential was released")
	}
}

func TestParseCodexTailBurstQuotaSnapshotIncludesResetAt(t *testing.T) {
	sampledAt := time.Unix(1_700_000_000, 0).UTC()
	snapshot, ok := parseCodexTailBurstQuotaSnapshot([]byte(`{
		"rate_limit":{
			"primary_window":{"used_percent":98,"reset_at":1700003600},
			"secondary_window":{"used_percent":20,"reset_after_seconds":7200}
		}
	}`), sampledAt, time.Minute)
	if !ok {
		t.Fatal("quota snapshot was not parsed")
	}
	want := time.Unix(1_700_003_600, 0).UTC()
	if !snapshot.ResetAt.Equal(want) {
		t.Fatalf("reset_at = %v, want %v", snapshot.ResetAt, want)
	}
}
