package auth

import (
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func (m *Manager) enrichCacheAffinity(providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	if m == nil || !hasCodexProvider(providers) {
		return req, opts
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	req, opts, _ = cacheaffinity.Enrich(req, opts, cfg)
	return req, opts
}

func (m *Manager) effectiveMaxRetryCredentials(configured int, providers []string) int {
	if m == nil || !hasCodexProvider(providers) {
		return configured
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	settings := cacheaffinity.Settings(cfg)
	if !settings.Enabled || settings.Shadow || settings.MaxRetryCredentials <= 0 {
		return configured
	}
	if configured <= 0 || configured > settings.MaxRetryCredentials {
		return settings.MaxRetryCredentials
	}
	return configured
}

func (m *Manager) confirmCacheAffinityBinding(provider, model, authID string, metadata map[string]any) {
	routeKey := cacheaffinity.MetadataValue(metadata, cliproxyexecutor.CacheAffinityRouteKeyMetadataKey)
	if routeKey == "" || strings.TrimSpace(authID) == "" {
		return
	}
	binder, ok := m.Selector().(sessionAffinityBinder)
	if !ok || binder == nil {
		return
	}
	binder.BindAuthSession(provider, model, "cache-affinity:"+routeKey, authID)
}

type cacheAffinityRuntimeSettings struct {
	active        bool
	hardStopRatio float64
}

func (m *Manager) cacheAffinitySettings() cacheAffinityRuntimeSettings {
	if m == nil {
		return cacheAffinityRuntimeSettings{}
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	settings := cacheaffinity.Settings(cfg)
	return cacheAffinityRuntimeSettings{
		active:        settings.Enabled && !settings.Shadow,
		hardStopRatio: settings.QuotaHardStopUsedRatio,
	}
}

func cacheAffinityUsageLimitResult(result Result) bool {
	if result.Error == nil || result.Error.HTTPStatus != 429 {
		return false
	}
	value := strings.ToLower(result.Error.Code + " " + result.Error.Message)
	return strings.Contains(value, "usage_limit_reached") || strings.Contains(value, "usage limit")
}
