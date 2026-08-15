package auth

import (
	"context"
	"strconv"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type accountGroupSelection struct {
	key string
	ids []int64
}

type apiKeyGroupPolicySnapshot struct {
	byHash map[string]accountGroupSelection
}

func compileAPIKeyGroupPolicySnapshot(cfg *internalconfig.Config) *apiKeyGroupPolicySnapshot {
	snapshot := &apiKeyGroupPolicySnapshot{byHash: make(map[string]accountGroupSelection)}
	if cfg == nil {
		return snapshot
	}
	for _, policy := range cfg.APIKeyGroupPolicies {
		hash := strings.ToLower(strings.TrimSpace(policy.APIKeyHash))
		ids := internalconfig.NormalizeAccountGroupIDs(policy.AllowedGroupIDs)
		if hash == "" || len(ids) == 0 {
			continue
		}
		snapshot.byHash[hash] = accountGroupSelection{
			key: accountGroupSelectionKey(ids),
			ids: append([]int64(nil), ids...),
		}
	}
	return snapshot
}

func accountGroupSelectionKey(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	var builder strings.Builder
	for index, id := range ids {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(strconv.FormatInt(id, 10))
	}
	return builder.String()
}

func (m *Manager) refreshAPIKeyGroupPolicies(cfg *internalconfig.Config) {
	if m == nil {
		return
	}
	m.apiKeyGroupPolicies.Store(compileAPIKeyGroupPolicySnapshot(cfg))
}

func (m *Manager) withAccountGroupPolicy(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if m == nil || len(opts.Metadata) == 0 {
		return opts
	}
	hash, _ := opts.Metadata[cliproxyexecutor.DownstreamAPIKeyHashMetadataKey].(string)
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return opts
	}
	snapshot, _ := m.apiKeyGroupPolicies.Load().(*apiKeyGroupPolicySnapshot)
	if snapshot == nil {
		return opts
	}
	selection, restricted := snapshot.byHash[hash]
	if !restricted || len(selection.ids) == 0 {
		return opts
	}
	metadata := make(map[string]any, len(opts.Metadata)+3)
	for key, value := range opts.Metadata {
		metadata[key] = value
	}
	metadata[cliproxyexecutor.AccountGroupPolicyEvaluatedMetadataKey] = true
	metadata[cliproxyexecutor.AllowedAccountGroupIDsMetadataKey] = append([]int64(nil), selection.ids...)
	metadata[cliproxyexecutor.AccountGroupPolicyKeyMetadataKey] = selection.key
	opts.Metadata = metadata
	return opts
}

func (m *Manager) withAccountGroupPolicyFromContext(ctx context.Context, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if len(opts.Metadata) == 0 || strings.TrimSpace(contextString(opts.Metadata[cliproxyexecutor.DownstreamAPIKeyHashMetadataKey])) == "" {
		if hash := downstreamAPIKeyHashFromContext(ctx); hash != "" {
			metadata := make(map[string]any, len(opts.Metadata)+1)
			for key, value := range opts.Metadata {
				metadata[key] = value
			}
			metadata[cliproxyexecutor.DownstreamAPIKeyHashMetadataKey] = hash
			opts.Metadata = metadata
		}
	}
	return m.withAccountGroupPolicy(opts)
}

func downstreamAPIKeyHashFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ginCtx, ok := ctx.Value("gin").(interface{ Get(string) (any, bool) })
	if !ok || ginCtx == nil {
		return ""
	}
	raw, exists := ginCtx.Get("userApiKey")
	if !exists {
		return ""
	}
	apiKey, ok := raw.(string)
	if !ok {
		return ""
	}
	return internalconfig.HashAPIKeyForGroupPolicy(apiKey)
}

func contextString(value any) string {
	text, _ := value.(string)
	return text
}

func accountGroupPolicyActive(metadata map[string]any) bool {
	if len(metadata) == 0 {
		return false
	}
	active, _ := metadata[cliproxyexecutor.AccountGroupPolicyEvaluatedMetadataKey].(bool)
	return active
}

func accountGroupPolicyAllowsAuth(metadata map[string]any, auth *Auth) bool {
	if !accountGroupPolicyActive(metadata) {
		return true
	}
	if auth == nil {
		return false
	}
	allowed := normalizeRuntimeGroupIDs(metadata[cliproxyexecutor.AllowedAccountGroupIDsMetadataKey])
	return auth.matchesAnyGroup(allowed)
}
