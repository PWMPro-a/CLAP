// Package cacheaffinity coordinates Codex routing and upstream cache identities.
// It is deliberately independent from credential selection and network transports.
package cacheaffinity

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
)

const (
	defaultMaxEntries     = 65536
	shardCount            = 64
	prefixInspectInterval = 5 * time.Second
)

// Decision separates local routing, upstream prompt caching, and websocket reuse.
type Decision struct {
	RouteKey      string `json:"route_key,omitempty"`
	UpstreamKey   string `json:"upstream_key,omitempty"`
	PoolKey       string `json:"pool_key,omitempty"`
	PrefixFP      string `json:"prefix_fp,omitempty"`
	Source        string `json:"source,omitempty"`
	Active        bool   `json:"active"`
	PrefixChanged bool   `json:"prefix_changed"`
}

// Stats is a lock-free operational snapshot.
type Stats struct {
	Resolved              uint64  `json:"resolved"`
	Active                uint64  `json:"active"`
	Shadow                uint64  `json:"shadow"`
	Explicit              uint64  `json:"explicit"`
	Execution             uint64  `json:"execution"`
	Derived               uint64  `json:"derived"`
	CallerFallback        uint64  `json:"caller_fallback"`
	ClientRequestFallback uint64  `json:"client_request_fallback"`
	PrefixChanged         uint64  `json:"prefix_changed"`
	PrefixInspected       uint64  `json:"prefix_inspected"`
	PrefixSkipped         uint64  `json:"prefix_skipped"`
	UsageLimitSignals     uint64  `json:"usage_limit_signals"`
	UsageLimitFreezes     uint64  `json:"usage_limit_freezes"`
	UsageLimitDeduped     uint64  `json:"usage_limit_deduped"`
	RouteRebinds          uint64  `json:"route_rebinds"`
	RouteHits             uint64  `json:"route_hits"`
	RouteMisses           uint64  `json:"route_misses"`
	RouteFailovers        uint64  `json:"route_failovers"`
	TrackedRoutes         int     `json:"tracked_routes"`
	ResolveNanoseconds    uint64  `json:"resolve_nanoseconds"`
	AverageResolveMicros  float64 `json:"average_resolve_micros"`
}

type counters struct {
	resolved              atomic.Uint64
	active                atomic.Uint64
	shadow                atomic.Uint64
	explicit              atomic.Uint64
	execution             atomic.Uint64
	derived               atomic.Uint64
	callerFallback        atomic.Uint64
	clientRequestFallback atomic.Uint64
	prefixChanged         atomic.Uint64
	prefixInspected       atomic.Uint64
	prefixSkipped         atomic.Uint64
	usageLimitSignals     atomic.Uint64
	usageLimitFreezes     atomic.Uint64
	usageLimitDeduped     atomic.Uint64
	routeRebinds          atomic.Uint64
	routeHits             atomic.Uint64
	routeMisses           atomic.Uint64
	routeFailovers        atomic.Uint64
	resolveNanos          atomic.Uint64
	trackedRoutes         atomic.Uint64
}

type prefixEntry struct {
	fingerprint string
	lastSeen    time.Time
	nextInspect time.Time
	inspecting  bool
}

type prefixShard struct {
	mu      sync.Mutex
	entries map[string]prefixEntry
}

var global = struct {
	counters counters
	shards   [shardCount]prefixShard
}{}

// Enrich computes one decision before credential selection and publishes it in
// request metadata. No goroutine, network call, or response buffering occurs.
func Enrich(req cliproxyexecutor.Request, opts cliproxyexecutor.Options, cfg *internalconfig.Config) (cliproxyexecutor.Request, cliproxyexecutor.Options, Decision) {
	settings := Settings(cfg)
	if !settings.Enabled {
		return req, opts, Decision{}
	}
	started := time.Now()
	payload := opts.OriginalRequest
	if len(payload) == 0 {
		payload = req.Payload
	}
	model := strings.TrimSpace(req.Model)
	if requested := metadataString(opts.Metadata, cliproxyexecutor.RequestedModelMetadataKey); requested != "" {
		model = requested
	}
	identity, source, promptCacheKey := resolveIdentityBeforeBody(opts.Headers, opts.Metadata)
	var root gjson.Result
	rootParsed := false
	if identity == "" {
		root = util.ParseGJSONBytesNoCopy(payload)
		rootParsed = true
		promptCacheKey = explicitPromptCacheKey(root)
		identity, source = resolveIdentityFromBody(opts.Headers, root, promptCacheKey, opts.Metadata)
	}
	if identity == "" {
		return req, opts, Decision{}
	}
	if promptCacheKey == "" && source != "execution" && source != "derived" {
		if !rootParsed {
			root = util.ParseGJSONBytesNoCopy(payload)
			rootParsed = true
		}
		promptCacheKey = explicitPromptCacheKey(root)
	}
	modelFamily := canonicalModelFamily(model)
	routeKey := stableID("route", identity)
	upstreamKey := promptCacheKey
	if upstreamKey == "" {
		upstreamKey = stableID("prompt-cache", modelFamily, identity)
	}
	decision := Decision{
		RouteKey:    routeKey,
		UpstreamKey: upstreamKey,
		// Physical websocket slots are shared by model family while the upstream
		// cache identity remains conversation-scoped. This avoids one socket pool
		// per conversation without coupling connection churn to prompt caching.
		PoolKey: stableID("pool", modelFamily),
		Source:  source,
		Active:  !settings.Shadow,
	}
	decision.PrefixFP, decision.PrefixChanged = inspectPrefixPayload(routeKey, modelFamily, payload, root, rootParsed, settings.MaxEntries)
	publishCounters(decision, time.Since(started))

	metadata := cloneMetadata(opts.Metadata, 4)
	metadata[cliproxyexecutor.CacheAffinityRouteKeyMetadataKey] = decision.RouteKey
	metadata[cliproxyexecutor.CacheAffinityUpstreamKeyMetadataKey] = decision.UpstreamKey
	metadata[cliproxyexecutor.CacheAffinityPoolKeyMetadataKey] = decision.PoolKey
	metadata[cliproxyexecutor.CacheAffinityActiveMetadataKey] = decision.Active
	opts.Metadata = metadata
	req.Metadata = cloneMetadata(req.Metadata, 4)
	req.Metadata[cliproxyexecutor.CacheAffinityRouteKeyMetadataKey] = decision.RouteKey
	req.Metadata[cliproxyexecutor.CacheAffinityUpstreamKeyMetadataKey] = decision.UpstreamKey
	req.Metadata[cliproxyexecutor.CacheAffinityPoolKeyMetadataKey] = decision.PoolKey
	req.Metadata[cliproxyexecutor.CacheAffinityActiveMetadataKey] = decision.Active
	return req, opts, decision
}

// RuntimeSettings contains normalized hot-path settings.
type RuntimeSettings struct {
	Enabled                bool    `json:"enabled"`
	Shadow                 bool    `json:"shadow"`
	MaxEntries             int     `json:"max_entries"`
	MaxRetryCredentials    int     `json:"max_retry_credentials"`
	WebsocketPoolSlots     int     `json:"websocket_pool_slots"`
	QuotaPreemptUsedRatio  float64 `json:"quota_preempt_used_ratio"`
	QuotaHardStopUsedRatio float64 `json:"quota_hard_stop_used_ratio"`
}

// Settings normalizes optional configuration without mutating the config tree.
func Settings(cfg *internalconfig.Config) RuntimeSettings {
	if cfg == nil {
		return RuntimeSettings{}
	}
	raw := cfg.Codex.CacheAffinity
	settings := RuntimeSettings{
		Enabled:                raw.Enabled,
		Shadow:                 raw.Shadow,
		MaxEntries:             raw.MaxEntries,
		MaxRetryCredentials:    raw.MaxRetryCredentials,
		WebsocketPoolSlots:     raw.WebsocketPoolSlots,
		QuotaPreemptUsedRatio:  raw.QuotaPreemptUsedRatio,
		QuotaHardStopUsedRatio: raw.QuotaHardStopUsedRatio,
	}
	if settings.MaxEntries <= 0 {
		settings.MaxEntries = defaultMaxEntries
	}
	if settings.MaxRetryCredentials <= 0 {
		settings.MaxRetryCredentials = 2
	}
	if settings.WebsocketPoolSlots <= 0 {
		settings.WebsocketPoolSlots = 8
	} else if settings.WebsocketPoolSlots > 30 {
		settings.WebsocketPoolSlots = 30
	}
	if settings.QuotaPreemptUsedRatio <= 0 || settings.QuotaPreemptUsedRatio >= 1 {
		settings.QuotaPreemptUsedRatio = 0.97
	}
	if settings.QuotaHardStopUsedRatio <= settings.QuotaPreemptUsedRatio || settings.QuotaHardStopUsedRatio > 1 {
		settings.QuotaHardStopUsedRatio = 0.99
		if settings.QuotaHardStopUsedRatio <= settings.QuotaPreemptUsedRatio {
			settings.QuotaHardStopUsedRatio = 1
		}
	}
	return settings
}

// MetadataValue returns a coordinator value only for active decisions.
func MetadataValue(metadata map[string]any, key string) string {
	if !metadataBool(metadata, cliproxyexecutor.CacheAffinityActiveMetadataKey) {
		return ""
	}
	return metadataString(metadata, key)
}

// Snapshot returns aggregate diagnostics without exposing request content.
func Snapshot() Stats {
	resolved := global.counters.resolved.Load()
	nanos := global.counters.resolveNanos.Load()
	stats := Stats{
		Resolved:              resolved,
		Active:                global.counters.active.Load(),
		Shadow:                global.counters.shadow.Load(),
		Explicit:              global.counters.explicit.Load(),
		Execution:             global.counters.execution.Load(),
		Derived:               global.counters.derived.Load(),
		CallerFallback:        global.counters.callerFallback.Load(),
		ClientRequestFallback: global.counters.clientRequestFallback.Load(),
		PrefixChanged:         global.counters.prefixChanged.Load(),
		PrefixInspected:       global.counters.prefixInspected.Load(),
		PrefixSkipped:         global.counters.prefixSkipped.Load(),
		UsageLimitSignals:     global.counters.usageLimitSignals.Load(),
		UsageLimitFreezes:     global.counters.usageLimitFreezes.Load(),
		UsageLimitDeduped:     global.counters.usageLimitDeduped.Load(),
		RouteRebinds:          global.counters.routeRebinds.Load(),
		RouteHits:             global.counters.routeHits.Load(),
		RouteMisses:           global.counters.routeMisses.Load(),
		RouteFailovers:        global.counters.routeFailovers.Load(),
		TrackedRoutes:         int(global.counters.trackedRoutes.Load()),
		ResolveNanoseconds:    nanos,
	}
	if resolved > 0 {
		stats.AverageResolveMicros = float64(nanos) / float64(resolved) / 1000
	}
	return stats
}

// RecordUsageLimitFreeze records whether a usage-limit signal extended the
// credential freeze window or was deduplicated by an existing window.
func RecordUsageLimitFreeze(extended bool) {
	global.counters.usageLimitSignals.Add(1)
	if extended {
		global.counters.usageLimitFreezes.Add(1)
		return
	}
	global.counters.usageLimitDeduped.Add(1)
}

// RecordRouteRebind records a permanent session move after its bound auth became unavailable.
func RecordRouteRebind() {
	global.counters.routeRebinds.Add(1)
}

// RecordRouteHit records a successful reuse of an established route binding.
func RecordRouteHit() {
	global.counters.routeHits.Add(1)
}

// RecordRouteMiss records the first binding for a route.
func RecordRouteMiss() {
	global.counters.routeMisses.Add(1)
}

// RecordRouteFailover records a temporary failover that preserves the primary binding.
func RecordRouteFailover() {
	global.counters.routeFailovers.Add(1)
}

func resolveIdentityBeforeBody(headers http.Header, metadata map[string]any) (string, string, string) {
	for _, name := range []string{"X-Claude-Code-Session-Id", "Session-Id", "Session_id", "X-Session-ID", "X-Session-Affinity"} {
		if value := cliproxysession.NormalizeExplicitID(headerValue(headers, name)); value != "" {
			return strings.ToLower(name) + ":" + value, "session_header", ""
		}
	}
	if turnMetadata := strings.TrimSpace(headerValue(headers, "X-Codex-Turn-Metadata")); turnMetadata != "" {
		for _, path := range []string{"prompt_cache_key", "window_id", "conversation_id"} {
			if value := cliproxysession.NormalizeExplicitID(gjson.Get(turnMetadata, path).String()); value != "" {
				promptCacheKey := ""
				if path == "prompt_cache_key" {
					promptCacheKey = value
				}
				return "codex-turn:" + value, "codex_turn", promptCacheKey
			}
		}
	}
	if value := cliproxysession.NormalizeExplicitID(headerValue(headers, "X-Codex-Window-Id")); value != "" {
		return "codex-window:" + value, "codex_turn", ""
	}
	if value := metadataString(metadata, cliproxyexecutor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value, "execution", ""
	}
	if value := cliproxysession.DerivedID(metadata); value != "" {
		return "derived:" + value, "derived", ""
	}
	return "", "", ""
}

func resolveIdentityFromBody(headers http.Header, root gjson.Result, promptCacheKey string, metadata map[string]any) (string, string) {
	if promptCacheKey != "" {
		return "prompt_cache_key:" + promptCacheKey, "body_session"
	}
	for _, path := range []string{"session_id", "sessionId", "conversation_id", "conversation.id"} {
		if value := cliproxysession.NormalizeExplicitID(root.Get(path).String()); value != "" {
			return path + ":" + value, "body_session"
		}
	}
	if value := claudeMetadataSessionID(root); value != "" {
		return "claude:" + value, "body_session"
	}
	// X-Client-Request-Id is request-scoped for several Codex clients. It is a
	// useful legacy fallback, but stable conversation signals must outrank it.
	if value := cliproxysession.NormalizeExplicitID(headerValue(headers, "X-Client-Request-Id")); value != "" {
		return "client-request:" + value, "client_request"
	}
	if value := metadataString(metadata, cliproxyexecutor.CallerScopeMetadataKey); value != "" {
		return "caller:" + value, "caller"
	}
	return "", ""
}

func canonicalModelFamily(model string) string {
	model = strings.TrimSpace(thinking.ParseSuffix(model).ModelName)
	if model == "" {
		return "unknown"
	}
	return strings.ToLower(model)
}

func stableID(kind string, values ...string) string {
	name := "cli-proxy-api:cache-affinity:v1:" + kind + ":" + strings.Join(values, "\x00")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func explicitPromptCacheKey(root gjson.Result) string {
	return cliproxysession.NormalizeExplicitID(root.Get("prompt_cache_key").String())
}

func prefixFingerprint(modelFamily string, root gjson.Result) string {
	hash := sha256.New()
	writeFingerprintField(hash, "model", modelFamily)
	writeFingerprintField(hash, "instructions", root.Get("instructions").Raw)
	writeFingerprintField(hash, "tools", root.Get("tools").Raw)
	for _, collection := range []string{"input", "messages"} {
		items := root.Get(collection)
		if !items.IsArray() {
			continue
		}
		for _, item := range items.Array() {
			role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
			if role != "system" && role != "developer" {
				continue
			}
			writeFingerprintField(hash, role, item.Get("content").Raw)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)[:12])
}

type stringWriter interface {
	Write([]byte) (int, error)
}

func writeFingerprintField(writer stringWriter, name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	_, _ = writer.Write([]byte(name))
	_, _ = writer.Write([]byte{0})
	_, _ = writer.Write([]byte(value))
	_, _ = writer.Write([]byte{0})
}

func inspectPrefix(routeKey, modelFamily string, root gjson.Result, maxEntries int) (string, bool) {
	return inspectPrefixAt(routeKey, modelFamily, root, maxEntries, time.Now(), prefixInspectInterval)
}

func inspectPrefixAt(routeKey, modelFamily string, root gjson.Result, maxEntries int, now time.Time, interval time.Duration) (string, bool) {
	return inspectPrefixWith(routeKey, maxEntries, now, interval, func() string {
		return prefixFingerprint(modelFamily, root)
	})
}

func inspectPrefixPayload(routeKey, modelFamily string, payload []byte, root gjson.Result, rootParsed bool, maxEntries int) (string, bool) {
	return inspectPrefixWith(routeKey, maxEntries, time.Now(), prefixInspectInterval, func() string {
		if !rootParsed {
			root = util.ParseGJSONBytesNoCopy(payload)
		}
		return prefixFingerprint(modelFamily, root)
	})
}

func inspectPrefixWith(routeKey string, maxEntries int, now time.Time, interval time.Duration, fingerprint func() string) (string, bool) {
	if routeKey == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(routeKey))
	shard := &global.shards[int(sum[0])%shardCount]
	shard.mu.Lock()
	if shard.entries == nil {
		shard.entries = make(map[string]prefixEntry)
	}
	previous, exists := shard.entries[routeKey]
	if exists {
		previous.lastSeen = now
		if previous.inspecting || now.Before(previous.nextInspect) {
			shard.entries[routeKey] = previous
			shard.mu.Unlock()
			global.counters.prefixSkipped.Add(1)
			return previous.fingerprint, false
		}
		previous.inspecting = true
		previous.nextInspect = now.Add(interval)
		shard.entries[routeKey] = previous
		shard.mu.Unlock()
	} else {
		capacity := maxEntries/shardCount + 1
		if capacity < 1 {
			capacity = 1
		}
		replaced := false
		if len(shard.entries) >= capacity {
			var oldestKey string
			var oldest time.Time
			for key, entry := range shard.entries {
				if entry.inspecting {
					continue
				}
				if oldestKey == "" || entry.lastSeen.Before(oldest) {
					oldestKey = key
					oldest = entry.lastSeen
				}
			}
			if oldestKey != "" {
				delete(shard.entries, oldestKey)
				replaced = true
			} else {
				shard.mu.Unlock()
				global.counters.prefixSkipped.Add(1)
				return "", false
			}
		}
		shard.entries[routeKey] = prefixEntry{lastSeen: now, nextInspect: now.Add(interval), inspecting: true}
		if !replaced {
			global.counters.trackedRoutes.Add(1)
		}
		shard.mu.Unlock()
	}

	currentFingerprint := fingerprint()
	global.counters.prefixInspected.Add(1)
	shard.mu.Lock()
	current, stillTracked := shard.entries[routeKey]
	if !stillTracked {
		shard.mu.Unlock()
		return currentFingerprint, false
	}
	changed := current.fingerprint != "" && current.fingerprint != currentFingerprint
	current.fingerprint = currentFingerprint
	current.lastSeen = now
	current.inspecting = false
	shard.entries[routeKey] = current
	shard.mu.Unlock()
	return currentFingerprint, changed
}

func publishCounters(decision Decision, elapsed time.Duration) {
	global.counters.resolved.Add(1)
	global.counters.resolveNanos.Add(uint64(elapsed.Nanoseconds()))
	if decision.Active {
		global.counters.active.Add(1)
	} else {
		global.counters.shadow.Add(1)
	}
	switch decision.Source {
	case "session_header", "codex_turn", "body_session":
		global.counters.explicit.Add(1)
	case "execution":
		global.counters.execution.Add(1)
	case "derived":
		global.counters.derived.Add(1)
	case "caller":
		global.counters.callerFallback.Add(1)
	case "client_request":
		global.counters.explicit.Add(1)
		global.counters.clientRequestFallback.Add(1)
	}
	if decision.PrefixChanged {
		global.counters.prefixChanged.Add(1)
	}
}

func claudeMetadataSessionID(root gjson.Result) string {
	userID := strings.TrimSpace(root.Get("metadata.user_id").String())
	if userID == "" {
		return ""
	}
	if strings.HasPrefix(userID, "{") {
		return cliproxysession.NormalizeExplicitID(gjson.Get(userID, "session_id").String())
	}
	const marker = "_session_"
	if index := strings.LastIndex(userID, marker); index >= 0 {
		return cliproxysession.NormalizeExplicitID(userID[index+len(marker):])
	}
	return ""
}

func cloneMetadata(source map[string]any, extra int) map[string]any {
	cloned := make(map[string]any, len(source)+extra)
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func metadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func metadataBool(metadata map[string]any, key string) bool {
	if len(metadata) == 0 {
		return false
	}
	value, _ := metadata[key].(bool)
	return value
}

func headerValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	if value := strings.TrimSpace(headers.Get(name)); value != "" {
		return value
	}
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}
