package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	codexTailBurstUsageURL                = "https://chatgpt.com/backend-api/wham/usage"
	defaultCodexQuotaCollectorInterval    = 45 * time.Second
	defaultCodexQuotaCollectorConcurrency = 4
	defaultCodexQuotaCollectorTimeout     = 8 * time.Second
	defaultCodexQuotaCollectorSnapshotTTL = 90 * time.Second
	maxCodexQuotaUsageResponseSize        = 256 << 10
)

type codexTailBurstQuotaCollectorSettings struct {
	interval       time.Duration
	maxConcurrency int
	timeout        time.Duration
	snapshotTTL    time.Duration
}

// StartCodexTailBurstQuotaCollector starts the asynchronous Codex usage
// collector. The supplied config getter is read on every cycle so config reloads
// take effect without replacing the service or touching active model requests.
func StartCodexTailBurstQuotaCollector(
	ctx context.Context,
	manager *cliproxyauth.Manager,
	configProvider func() *config.Config,
) context.CancelFunc {
	if manager == nil || configProvider == nil {
		return func() {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	collectorCtx, cancel := context.WithCancel(ctx)
	go runCodexTailBurstQuotaCollector(collectorCtx, manager, configProvider)
	return cancel
}

func runCodexTailBurstQuotaCollector(
	ctx context.Context,
	manager *cliproxyauth.Manager,
	configProvider func() *config.Config,
) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		cfg := configProvider()
		settings, enabled := resolveCodexTailBurstQuotaCollectorSettings(cfg)
		if enabled {
			collectCodexTailBurstQuotaSnapshots(ctx, manager, cfg, settings)
		}

		// Keep config changes responsive while disabled without issuing any
		// upstream calls. When enabled, the configured collection interval wins.
		next := settings.interval
		if !enabled && next > 15*time.Second {
			next = 15 * time.Second
		}
		timer.Reset(next)
	}
}

func resolveCodexTailBurstQuotaCollectorSettings(cfg *config.Config) (codexTailBurstQuotaCollectorSettings, bool) {
	settings := codexTailBurstQuotaCollectorSettings{
		interval:       defaultCodexQuotaCollectorInterval,
		maxConcurrency: defaultCodexQuotaCollectorConcurrency,
		timeout:        defaultCodexQuotaCollectorTimeout,
		snapshotTTL:    defaultCodexQuotaCollectorSnapshotTTL,
	}
	if cfg == nil {
		return settings, false
	}
	collector := cfg.Codex.TailBurst.QuotaCollector
	if !cfg.Codex.TailBurst.Enabled && !collector.Enabled {
		return settings, false
	}
	if interval, err := time.ParseDuration(strings.TrimSpace(collector.Interval)); err == nil && interval > 0 {
		settings.interval = interval
	}
	if collector.MaxConcurrency > 0 {
		settings.maxConcurrency = collector.MaxConcurrency
	}
	if timeout, err := time.ParseDuration(strings.TrimSpace(collector.Timeout)); err == nil && timeout > 0 {
		settings.timeout = timeout
	}
	if ttl, err := time.ParseDuration(strings.TrimSpace(cfg.Codex.TailBurst.SnapshotTTL)); err == nil && ttl > 0 {
		settings.snapshotTTL = ttl
	}
	if settings.maxConcurrency > 16 {
		settings.maxConcurrency = 16
	}
	return settings, true
}

func collectCodexTailBurstQuotaSnapshots(
	ctx context.Context,
	manager *cliproxyauth.Manager,
	cfg *config.Config,
	settings codexTailBurstQuotaCollectorSettings,
) {
	if manager == nil {
		return
	}
	auths := manager.List()
	jobs := make(chan *cliproxyauth.Auth)
	updates := make([]cliproxyauth.CodexQuotaSnapshotUpdate, 0, len(auths))
	var updatesMu sync.Mutex
	var workers sync.WaitGroup
	workerCount := settings.maxConcurrency
	if workerCount > len(auths) {
		workerCount = len(auths)
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for auth := range jobs {
				requestCtx, cancel := context.WithTimeout(ctx, settings.timeout)
				snapshot, err := fetchCodexTailBurstQuotaSnapshot(requestCtx, cfg, auth, settings.snapshotTTL)
				cancel()
				if err != nil {
					log.WithError(err).Debugf("codex tail-burst quota collector: auth %s", auth.ID)
					continue
				}
				updatesMu.Lock()
				updates = append(updates, cliproxyauth.CodexQuotaSnapshotUpdate{AuthID: auth.ID, Snapshot: snapshot})
				updatesMu.Unlock()
			}
		}()
	}
	for _, auth := range auths {
		if !codexTailBurstQuotaAuthEligible(auth) {
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		case jobs <- auth:
		}
	}
	close(jobs)
	workers.Wait()
	if accepted, err := manager.UpdateCodexQuotaSnapshots(updates); err != nil {
		log.WithError(err).Debug("codex tail-burst quota collector: store snapshot batch")
	} else if accepted > 0 {
		log.Debugf("codex tail-burst quota collector: published %d usage snapshots", accepted)
	}
}

func codexTailBurstQuotaAuthEligible(auth *cliproxyauth.Auth) bool {
	if auth == nil || auth.Disabled || auth.Unavailable || auth.Status != cliproxyauth.StatusActive || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	if auth.Metadata == nil {
		return false
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	if strings.TrimSpace(accessToken) == "" {
		return false
	}
	for _, key := range []string{"tail_burst_enabled", "tail-burst-enabled"} {
		if raw, ok := auth.Metadata[key]; ok {
			if enabled, parsed := parseCodexTailBurstBool(raw); parsed && !enabled {
				return false
			}
		}
	}
	return true
}

func parseCodexTailBurstBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func fetchCodexTailBurstQuotaSnapshot(
	ctx context.Context,
	cfg *config.Config,
	auth *cliproxyauth.Auth,
	ttl time.Duration,
) (cliproxyauth.CodexQuotaSnapshot, error) {
	if auth == nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("missing auth")
	}
	apiKey, _ := codexCreds(auth)
	client := helps.NewUtlsHTTPClient(ctx, cfg, auth, 0)
	authorization, _, err := helps.PrepareCodexAuthorization(ctx, auth, client, apiKey)
	if err != nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("prepare authorization: %w", err)
	}
	if strings.TrimSpace(authorization) == "" {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("missing authorization")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexTailBurstUsageURL, nil)
	if err != nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("create usage request: %w", err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", codexUserAgent)
	req.Header.Set("Originator", codexOriginator)
	if accountID := codexAuthAccountID(auth); accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("request usage: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCodexQuotaUsageResponseSize))
	if err != nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("read usage response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("usage endpoint returned %d", resp.StatusCode)
	}
	snapshot, ok := parseCodexTailBurstQuotaSnapshot(body, time.Now().UTC(), ttl)
	if !ok {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("usage response has no usable quota windows")
	}
	return snapshot, nil
}

// RefreshQuota verifies a freshly rotated Codex credential against the usage
// endpoint. Lifecycle recovery calls this in a bounded background worker.
func (e *CodexExecutor) RefreshQuota(ctx context.Context, auth *cliproxyauth.Auth) (cliproxyauth.CodexQuotaSnapshot, error) {
	if e == nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("codex executor is nil")
	}
	return fetchCodexTailBurstQuotaSnapshot(ctx, e.cfg, auth, defaultCodexQuotaCollectorSnapshotTTL)
}

func parseCodexTailBurstQuotaSnapshot(body []byte, sampledAt time.Time, ttl time.Duration) (cliproxyauth.CodexQuotaSnapshot, bool) {
	if !gjson.ValidBytes(body) {
		return cliproxyauth.CodexQuotaSnapshot{}, false
	}
	if sampledAt.IsZero() {
		sampledAt = time.Now().UTC()
	}
	if ttl <= 0 {
		ttl = defaultCodexQuotaCollectorSnapshotTTL
	}
	type quotaCandidate struct {
		name       string
		ratio      float64
		resetAt    time.Time
		windowKind string
	}
	candidates := make([]quotaCandidate, 0, 2)
	for _, candidate := range []struct {
		name string
		path string
	}{
		{name: "primary", path: "rate_limit.primary_window"},
		{name: "secondary", path: "rate_limit.secondary_window"},
	} {
		window := gjson.GetBytes(body, candidate.path)
		if !window.Exists() {
			continue
		}
		used := window.Get("used_percent")
		if !used.Exists() {
			used = window.Get("usedPercent")
		}
		if !used.Exists() {
			continue
		}
		ratio := used.Float() / 100
		if ratio < 0 || ratio > 1 {
			continue
		}
		resetAt := codexQuotaWindowResetAt(body, candidate.name, sampledAt)
		candidates = append(candidates, quotaCandidate{
			name:       candidate.name,
			ratio:      ratio,
			resetAt:    resetAt,
			windowKind: codexQuotaWindowKind(window),
		})
	}
	if len(candidates) == 0 {
		return cliproxyauth.CodexQuotaSnapshot{}, false
	}
	// The usage endpoint can expose a monthly window at 100% alongside an
	// independently usable weekly window. Tail draining targets the active
	// weekly allowance first, then falls back to the most constrained known
	// window when the response has no weekly classification.
	preferred := candidates
	weekly := make([]quotaCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.windowKind == "weekly" {
			weekly = append(weekly, candidate)
		}
	}
	if len(weekly) > 0 {
		preferred = weekly
	}
	best := preferred[0]
	for _, candidate := range preferred[1:] {
		if candidate.ratio > best.ratio || (candidate.ratio == best.ratio && candidate.resetAt.After(best.resetAt)) {
			best = candidate
		}
	}
	return cliproxyauth.CodexQuotaSnapshot{
		UsedRatio:      best.ratio,
		RemainingRatio: 1 - best.ratio,
		Window:         best.name,
		SampledAt:      sampledAt,
		ExpiresAt:      sampledAt.Add(ttl),
		ResetAt:        best.resetAt,
	}, true
}

func codexQuotaWindowKind(window gjson.Result) string {
	seconds := window.Get("limit_window_seconds").Float()
	if seconds <= 0 {
		seconds = window.Get("window_seconds").Float()
	}
	if seconds <= 0 {
		seconds = window.Get("window_minutes").Float() * 60
	}
	switch {
	case seconds >= 4.5*60*60 && seconds <= 5.5*60*60:
		return "five_hour"
	case seconds >= 6.5*24*60*60 && seconds <= 7.5*24*60*60:
		return "weekly"
	case seconds >= 28*24*60*60 && seconds <= 31*24*60*60:
		return "monthly"
	default:
		return "unknown"
	}
}

func codexQuotaWindowResetAt(body []byte, windowName string, sampledAt time.Time) time.Time {
	path := "rate_limit." + strings.TrimSpace(windowName) + "_window"
	if resetAt := gjson.GetBytes(body, path+".reset_at").Int(); resetAt > 0 {
		return time.Unix(resetAt, 0).UTC()
	}
	if resetAfter := gjson.GetBytes(body, path+".reset_after_seconds").Int(); resetAfter > 0 {
		return sampledAt.Add(time.Duration(resetAfter) * time.Second)
	}
	return time.Time{}
}
