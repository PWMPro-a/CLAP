package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const (
	defaultCodexTailBurstTriggerRatio = 0.98
	defaultCodexTailBurstSnapshotTTL  = 90 * time.Second

	codexTailBurstRequestedMetadataKey = "__cliproxy_codex_tail_burst_requested"
)

// CodexQuotaSnapshot is an externally sampled usage-window snapshot for a
// single Codex credential and model. It stays in process memory and is never
// fetched on the request path.
type CodexQuotaSnapshot struct {
	UsedRatio      float64   `json:"used_ratio"`
	RemainingRatio float64   `json:"remaining_ratio"`
	Window         string    `json:"window,omitempty"`
	SampledAt      time.Time `json:"sampled_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Generation     uint64    `json:"generation"`
}

type codexQuotaSnapshotStore map[string]CodexQuotaSnapshot
type codexTailBurstCandidateIndex map[string][]string

type codexTailBurstSettings struct {
	enabled      bool
	triggerRatio float64
	snapshotTTL  time.Duration
}

func (m *Manager) codexTailBurstSettings() codexTailBurstSettings {
	settings := codexTailBurstSettings{
		triggerRatio: defaultCodexTailBurstTriggerRatio,
		snapshotTTL:  defaultCodexTailBurstSnapshotTTL,
	}
	if m == nil {
		return settings
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return settings
	}
	tailCfg := cfg.Codex.TailBurst
	settings.enabled = tailCfg.Enabled
	if tailCfg.TriggerUsedRatio > 0 && tailCfg.TriggerUsedRatio < 1 {
		settings.triggerRatio = tailCfg.TriggerUsedRatio
	}
	if parsed, errParse := time.ParseDuration(strings.TrimSpace(tailCfg.SnapshotTTL)); errParse == nil && parsed > 0 {
		settings.snapshotTTL = parsed
	}
	return settings
}

func codexTailBurstEnabledForAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if raw := runtimeLimitLookupAny(auth, "tail_burst_enabled"); raw != nil {
		if enabled, ok := parseBoolAny(raw); ok {
			return enabled
		}
	}
	if raw := runtimeLimitLookupAny(auth, "tail-burst-enabled"); raw != nil {
		if enabled, ok := parseBoolAny(raw); ok {
			return enabled
		}
	}
	return true
}

func normalizeCodexTailBurstModel(model string) string {
	model = canonicalModelKey(model)
	if model == "" {
		return "*"
	}
	return model
}

func cloneCodexQuotaSnapshots(store codexQuotaSnapshotStore) codexQuotaSnapshotStore {
	if len(store) == 0 {
		return nil
	}
	clone := make(codexQuotaSnapshotStore, len(store))
	for model, snapshot := range store {
		clone[model] = snapshot
	}
	return clone
}

// setCodexQuotaSnapshot atomically replaces a model snapshot when the supplied
// sample is newer than the one already in memory. Quota collectors may have
// overlapping polls, so an older response must not move a credential back out
// of (or into) tail drain after a newer sample has already been applied.
func (a *Auth) setCodexQuotaSnapshot(model string, snapshot CodexQuotaSnapshot) (CodexQuotaSnapshot, bool) {
	if a == nil {
		return CodexQuotaSnapshot{}, false
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return CodexQuotaSnapshot{}, false
	}
	model = normalizeCodexTailBurstModel(model)
	current, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if previous, exists := current[model]; exists && !codexQuotaSnapshotNewer(snapshot, previous) {
		return previous, false
	}
	next := cloneCodexQuotaSnapshots(current)
	if next == nil {
		next = make(codexQuotaSnapshotStore, 1)
	}
	next[model] = snapshot
	state.codexQuotaSnapshots.Store(next)
	return snapshot, true
}

func codexQuotaSnapshotNewer(next, previous CodexQuotaSnapshot) bool {
	if next.Generation > 0 && previous.Generation > 0 && next.Generation != previous.Generation {
		return next.Generation > previous.Generation
	}
	if !next.SampledAt.Equal(previous.SampledAt) {
		return next.SampledAt.After(previous.SampledAt)
	}
	// A collector may refresh the expiry for an otherwise identical sample. It
	// is safe to accept only a longer lifetime and keeps duplicate deliveries
	// idempotent.
	return next.ExpiresAt.After(previous.ExpiresAt)
}

func (a *Auth) codexQuotaSnapshot(model string, now time.Time) (CodexQuotaSnapshot, bool) {
	if a == nil {
		return CodexQuotaSnapshot{}, false
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return CodexQuotaSnapshot{}, false
	}
	store, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if len(store) == 0 {
		return CodexQuotaSnapshot{}, false
	}
	model = normalizeCodexTailBurstModel(model)
	snapshot, ok := store[model]
	if !ok && model != "*" {
		snapshot, ok = store["*"]
	}
	if !ok || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(now) {
		return CodexQuotaSnapshot{}, false
	}
	return snapshot, true
}

func (a *Auth) codexQuotaSnapshots(now time.Time) codexQuotaSnapshotStore {
	if a == nil {
		return nil
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return nil
	}
	store, _ := state.codexQuotaSnapshots.Load().(codexQuotaSnapshotStore)
	if len(store) == 0 {
		return nil
	}
	active := make(codexQuotaSnapshotStore, len(store))
	for model, snapshot := range store {
		if !snapshot.ExpiresAt.IsZero() && snapshot.ExpiresAt.After(now) {
			active[model] = snapshot
		}
	}
	return active
}

// UpdateCodexQuotaSnapshot stores one sampled quota snapshot and rebuilds the
// small in-memory tail candidate index. Callers run this from management or a
// collector, never from request execution.
func (m *Manager) UpdateCodexQuotaSnapshot(authID, model string, snapshot CodexQuotaSnapshot) (CodexQuotaSnapshot, bool, error) {
	if m == nil {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth manager is unavailable")
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth id is required")
	}
	if snapshot.UsedRatio < 0 || snapshot.UsedRatio > 1 {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("used ratio must be between 0 and 1")
	}
	now := time.Now()
	if snapshot.SampledAt.IsZero() {
		snapshot.SampledAt = now
	}
	if snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.SampledAt) {
		snapshot.ExpiresAt = snapshot.SampledAt.Add(m.codexTailBurstSettings().snapshotTTL)
	}
	snapshot.RemainingRatio = 1 - snapshot.UsedRatio

	m.mu.RLock()
	auth := m.auths[authID]
	m.mu.RUnlock()
	if auth == nil {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth %q was not found", authID)
	}
	if !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
		return CodexQuotaSnapshot{}, false, fmt.Errorf("auth %q is not a Codex credential", authID)
	}
	stored, accepted := auth.setCodexQuotaSnapshot(model, snapshot)
	if accepted {
		m.refreshCodexTailBurstCandidates()
	}
	return stored, accepted, nil
}

// CodexQuotaSnapshot returns the fresh quota snapshot used by tail routing.
func (m *Manager) CodexQuotaSnapshot(authID, model string) (CodexQuotaSnapshot, bool) {
	if m == nil {
		return CodexQuotaSnapshot{}, false
	}
	m.mu.RLock()
	auth := m.auths[strings.TrimSpace(authID)]
	m.mu.RUnlock()
	if auth == nil {
		return CodexQuotaSnapshot{}, false
	}
	return auth.codexQuotaSnapshot(model, time.Now())
}

// CodexQuotaSnapshots returns the active snapshots for management displays.
func (m *Manager) CodexQuotaSnapshots(authID string) map[string]CodexQuotaSnapshot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	auth := m.auths[strings.TrimSpace(authID)]
	m.mu.RUnlock()
	if auth == nil {
		return nil
	}
	snapshots := auth.codexQuotaSnapshots(time.Now())
	if len(snapshots) == 0 {
		return nil
	}
	return map[string]CodexQuotaSnapshot(snapshots)
}

func (m *Manager) codexTailBurstActive(auth *Auth, model string, now time.Time) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") {
		return false
	}
	settings := m.codexTailBurstSettings()
	if !settings.enabled || !codexTailBurstEnabledForAuth(auth) {
		return false
	}
	snapshot, ok := auth.codexQuotaSnapshot(model, now)
	return ok && snapshot.UsedRatio >= settings.triggerRatio && snapshot.UsedRatio < 1
}

func (m *Manager) refreshCodexTailBurstCandidates() {
	if m == nil {
		return
	}
	settings := m.codexTailBurstSettings()
	index := make(codexTailBurstCandidateIndex)
	if settings.enabled {
		now := time.Now()
		m.mu.RLock()
		for _, auth := range m.auths {
			if auth == nil || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") || !codexTailBurstEnabledForAuth(auth) {
				continue
			}
			for model, snapshot := range auth.codexQuotaSnapshots(now) {
				if snapshot.UsedRatio < settings.triggerRatio || snapshot.UsedRatio >= 1 {
					continue
				}
				key := normalizeCodexTailBurstModel(model)
				index[key] = append(index[key], auth.ID)
			}
		}
		m.mu.RUnlock()
		for key := range index {
			sort.Strings(index[key])
		}
	}
	m.codexTailBurstCandidates.Store(index)
}

func hasCodexProvider(providers []string) bool {
	for _, provider := range providers {
		if strings.EqualFold(strings.TrimSpace(provider), "codex") {
			return true
		}
	}
	return false
}

func codexTailBurstRequestEligible(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	if cliproxyexecutor.DownstreamWebsocket(ctx) || stringMetadataValue(opts.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey) != "" {
		return false
	}
	if requestPath := strings.ToLower(stringMetadataValue(opts.Metadata, cliproxyexecutor.RequestPathMetadataKey)); strings.Contains(requestPath, "/images/") {
		return false
	}
	body := req.Payload
	if len(body) == 0 {
		body = opts.OriginalRequest
	}
	if !gjson.ValidBytes(body) {
		return false
	}
	root := gjson.ParseBytes(body)
	if root.Get("previous_response_id").Exists() || root.Get("tool_choice").Exists() {
		return false
	}
	if tools := root.Get("tools"); tools.IsArray() && len(tools.Array()) > 0 {
		return false
	}
	input := root.Get("input")
	if !input.IsArray() {
		return true
	}
	for _, item := range input.Array() {
		switch item.Get("type").String() {
		case "additional_tools", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
			return false
		}
	}
	return true
}

func (m *Manager) withCodexTailBurstRequestMetadata(ctx context.Context, providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if m == nil || !hasCodexProvider(providers) || !m.codexTailBurstSettings().enabled {
		return opts
	}
	// Avoid parsing every request body when no credential is in its final quota
	// window. The candidate index is rebuilt only by config/auth/snapshot events,
	// so this is a lock-free constant-time fast path for normal traffic.
	index, _ := m.codexTailBurstCandidates.Load().(codexTailBurstCandidateIndex)
	model := normalizeCodexTailBurstModel(authSelectionModelFromOptions(opts, req.Model))
	if len(index[model]) == 0 && (model == "*" || len(index["*"]) == 0) {
		return opts
	}
	if !codexTailBurstRequestEligible(ctx, req, opts) {
		return opts
	}
	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[codexTailBurstRequestedMetadataKey] = true
	opts.Metadata = metadata
	return opts
}

func codexTailBurstRequested(opts cliproxyexecutor.Options) bool {
	if len(opts.Metadata) == 0 {
		return false
	}
	requested, _ := opts.Metadata[codexTailBurstRequestedMetadataKey].(bool)
	return requested
}

func withCodexTailBurstSelected(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[cliproxyexecutor.CodexTailBurstMetadataKey] = true
	opts.Metadata = metadata
	return opts
}

func (m *Manager) pickCodexTailBurstAuth(model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, bool) {
	if m == nil || m.HomeEnabled() || !codexTailBurstRequested(opts) || pinnedAuthIDFromMetadata(opts.Metadata) != "" || disallowFreeAuthFromMetadata(opts.Metadata) {
		return nil, nil, false
	}
	index, _ := m.codexTailBurstCandidates.Load().(codexTailBurstCandidateIndex)
	if len(index) == 0 {
		return nil, nil, false
	}
	key := normalizeCodexTailBurstModel(model)
	candidates := index[key]
	if len(candidates) == 0 && key != "*" {
		candidates = index["*"]
	}
	if len(candidates) == 0 {
		return nil, nil, false
	}
	start := int(m.codexTailBurstSequence.Add(1)-1) % len(candidates)
	now := time.Now()
	registryRef := registry.GetGlobalRegistry()

	m.mu.RLock()
	defer m.mu.RUnlock()
	executor := m.executors["codex"]
	if executor == nil {
		return nil, nil, false
	}
	for offset := 0; offset < len(candidates); offset++ {
		authID := candidates[(start+offset)%len(candidates)]
		if _, alreadyTried := tried[authID]; alreadyTried {
			continue
		}
		auth := m.auths[authID]
		if auth == nil || auth.Disabled || !m.authSupportsRouteModel(registryRef, auth, model) || !m.codexTailBurstActive(auth, model, now) {
			continue
		}
		if blocked, _, _ := isAuthBlockedForModelWithTailBurst(auth, model, now, true); blocked {
			continue
		}
		return auth.Clone(), executor, true
	}
	return nil, nil, false
}
