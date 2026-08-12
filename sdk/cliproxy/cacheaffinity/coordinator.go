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
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
)

const (
	defaultMaxEntries = 65536
	shardCount        = 64
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

// Stats is a lock-free operational snapshot apart from bounded entry counts.
type Stats struct {
	Resolved             uint64  `json:"resolved"`
	Active               uint64  `json:"active"`
	Shadow               uint64  `json:"shadow"`
	Explicit             uint64  `json:"explicit"`
	Execution            uint64  `json:"execution"`
	Derived              uint64  `json:"derived"`
	CallerFallback       uint64  `json:"caller_fallback"`
	PrefixChanged        uint64  `json:"prefix_changed"`
	TrackedRoutes        int     `json:"tracked_routes"`
	ResolveNanoseconds   uint64  `json:"resolve_nanoseconds"`
	AverageResolveMicros float64 `json:"average_resolve_micros"`
}

type counters struct {
	resolved       atomic.Uint64
	active         atomic.Uint64
	shadow         atomic.Uint64
	explicit       atomic.Uint64
	execution      atomic.Uint64
	derived        atomic.Uint64
	callerFallback atomic.Uint64
	prefixChanged  atomic.Uint64
	resolveNanos   atomic.Uint64
}

type prefixEntry struct {
	fingerprint string
	lastSeen    time.Time
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
	identity, source := resolveIdentity(opts.Headers, payload, opts.Metadata)
	if identity == "" {
		return req, opts, Decision{}
	}
	modelFamily := canonicalModelFamily(model)
	routeKey := stableID("route", identity)
	upstreamKey := explicitPromptCacheKey(payload)
	if upstreamKey == "" {
		upstreamKey = stableID("prompt-cache", modelFamily, identity)
	}
	decision := Decision{
		RouteKey:    routeKey,
		UpstreamKey: upstreamKey,
		// Physical websocket slots are shared by model family while the upstream
		// cache identity remains conversation-scoped. This avoids one socket pool
		// per conversation without coupling connection churn to prompt caching.
		PoolKey:  stableID("pool", modelFamily),
		PrefixFP: prefixFingerprint(modelFamily, payload),
		Source:   source,
		Active:   !settings.Shadow,
	}
	decision.PrefixChanged = observePrefix(routeKey, decision.PrefixFP, settings.MaxEntries)
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
	tracked := 0
	for i := range global.shards {
		shard := &global.shards[i]
		shard.mu.Lock()
		tracked += len(shard.entries)
		shard.mu.Unlock()
	}
	stats := Stats{
		Resolved:           resolved,
		Active:             global.counters.active.Load(),
		Shadow:             global.counters.shadow.Load(),
		Explicit:           global.counters.explicit.Load(),
		Execution:          global.counters.execution.Load(),
		Derived:            global.counters.derived.Load(),
		CallerFallback:     global.counters.callerFallback.Load(),
		PrefixChanged:      global.counters.prefixChanged.Load(),
		TrackedRoutes:      tracked,
		ResolveNanoseconds: nanos,
	}
	if resolved > 0 {
		stats.AverageResolveMicros = float64(nanos) / float64(resolved) / 1000
	}
	return stats
}

func resolveIdentity(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	for _, name := range []string{"X-Claude-Code-Session-Id", "Session-Id", "Session_id", "X-Session-ID", "X-Session-Affinity", "X-Client-Request-Id"} {
		if value := cliproxysession.NormalizeExplicitID(headerValue(headers, name)); value != "" {
			return strings.ToLower(name) + ":" + value, "explicit"
		}
	}
	if turnMetadata := strings.TrimSpace(headerValue(headers, "X-Codex-Turn-Metadata")); turnMetadata != "" {
		for _, path := range []string{"prompt_cache_key", "window_id", "conversation_id"} {
			if value := cliproxysession.NormalizeExplicitID(gjson.Get(turnMetadata, path).String()); value != "" {
				return "codex-turn:" + value, "explicit"
			}
		}
	}
	for _, path := range []string{"session_id", "sessionId", "conversation_id", "prompt_cache_key", "conversation.id"} {
		if value := cliproxysession.NormalizeExplicitID(gjson.GetBytes(payload, path).String()); value != "" {
			return path + ":" + value, "explicit"
		}
	}
	if value := cliproxysession.ClaudeMetadataSessionID(payload); value != "" {
		return "claude:" + value, "explicit"
	}
	if value := metadataString(metadata, cliproxyexecutor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value, "execution"
	}
	if value := cliproxysession.DerivedID(metadata); value != "" {
		return "derived:" + value, "derived"
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

func explicitPromptCacheKey(payload []byte) string {
	return cliproxysession.NormalizeExplicitID(gjson.GetBytes(payload, "prompt_cache_key").String())
}

func prefixFingerprint(modelFamily string, payload []byte) string {
	hash := sha256.New()
	writeFingerprintField(hash, "model", modelFamily)
	writeFingerprintField(hash, "instructions", gjson.GetBytes(payload, "instructions").Raw)
	writeFingerprintField(hash, "tools", gjson.GetBytes(payload, "tools").Raw)
	for _, collection := range []string{"input", "messages"} {
		items := gjson.GetBytes(payload, collection)
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

func observePrefix(routeKey, fingerprint string, maxEntries int) bool {
	if routeKey == "" || fingerprint == "" {
		return false
	}
	sum := sha256.Sum256([]byte(routeKey))
	shard := &global.shards[int(sum[0])%shardCount]
	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]prefixEntry)
	}
	previous, exists := shard.entries[routeKey]
	changed := exists && previous.fingerprint != fingerprint
	if !exists && len(shard.entries) >= maxEntries/shardCount+1 {
		var oldestKey string
		var oldest time.Time
		for key, entry := range shard.entries {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey = key
				oldest = entry.lastSeen
			}
		}
		delete(shard.entries, oldestKey)
	}
	shard.entries[routeKey] = prefixEntry{fingerprint: fingerprint, lastSeen: now}
	return changed
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
	case "explicit":
		global.counters.explicit.Add(1)
	case "execution":
		global.counters.execution.Add(1)
	case "derived":
		global.counters.derived.Add(1)
	case "caller":
		global.counters.callerFallback.Add(1)
	}
	if decision.PrefixChanged {
		global.counters.prefixChanged.Add(1)
	}
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
