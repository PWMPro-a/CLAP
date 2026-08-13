package auth

import (
	"context"
	"net/http"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/codexclientpolicy"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	codexClientRestrictionEvaluatedMetadataKey        = "__cliproxy_codex_client_restriction_evaluated"
	codexClientRestrictionAllowedMetadataKey          = "__cliproxy_codex_client_restriction_allowed"
	codexClientRestrictionAppServerAllowedMetadataKey = "__cliproxy_codex_client_restriction_app_server_allowed"
	codexClientRestrictionReasonMetadataKey           = "__cliproxy_codex_client_restriction_reason"
)

const codexClientRestrictionMessage = "This account only allows Codex official clients"

func (m *Manager) enrichCodexClientRestriction(providers []string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if m == nil || !hasCodexProvider(providers) {
		return opts
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return opts
	}
	policy := codexClientPolicyFromConfig(cfg.Codex.ClientRestriction)
	headers := opts.OriginalHeaders
	if !opts.OriginalClientSnapshotCaptured {
		headers = opts.Headers
	}
	body := opts.OriginalClientRequest
	if !opts.OriginalClientSnapshotCaptured {
		body = opts.OriginalRequest
		if len(body) == 0 {
			body = req.Payload
		}
	}
	request := codexclientpolicy.Request{Headers: headers, Body: body}
	// Official-client identity is always evaluated without the app-server
	// fallback. The latter is activated only by the internal post-auth marker.
	officialPolicy := policy
	officialPolicy.AllowAppServerClients = false
	result := codexclientpolicy.Evaluate(request, officialPolicy)
	appServerResult := result
	trustedAppServer, _ := opts.Metadata[cliproxyexecutor.CodexAppServerMetadataKey].(bool)
	if trustedAppServer {
		appServerRequest := codexAppServerPolicyRequest(request)
		if policy.AllowAppServerClients && !result.Allowed {
			result = codexclientpolicy.Evaluate(appServerRequest, policy)
		}
		if !policy.AllowAppServerClients {
			appServerPolicy := policy
			appServerPolicy.AllowAppServerClients = true
			appServerResult = codexclientpolicy.Evaluate(appServerRequest, appServerPolicy)
		} else {
			appServerResult = result
		}
	} else if !result.Allowed {
		// App-server admission is backed by an internal post-authentication
		// marker. Client-controlled headers alone must not activate the account
		// or global app-server exception.
		appServerResult = result
	}

	metadata := cloneSchedulerAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 4)
	}
	metadata[codexClientRestrictionEvaluatedMetadataKey] = true
	metadata[codexClientRestrictionAllowedMetadataKey] = result.Allowed
	metadata[codexClientRestrictionAppServerAllowedMetadataKey] = appServerResult.Allowed
	metadata[codexClientRestrictionReasonMetadataKey] = result.Reason
	opts.Metadata = metadata
	return opts
}

func codexAppServerPolicyRequest(request codexclientpolicy.Request) codexclientpolicy.Request {
	headers := request.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	// Keep this identity outside the official-client namespace. The policy can
	// admit it only through the explicit app-server switch.
	headers.Set("User-Agent", "cpa-app-server/1.0")
	headers.Del("Originator")
	headers.Set("X-Codex-App-Server", "authenticated")
	headers.Set("Session-Id", "cpa-app-server-session")
	headers.Set("Thread-Id", "cpa-app-server-thread")
	body := []byte(`{"client_metadata":{"x-codex-installation-id":"cpa-app-server"}}`)
	return codexclientpolicy.Request{Headers: headers, Body: body}
}

func attachCodexAppServerMetadata(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Request {
	trusted, _ := opts.Metadata[cliproxyexecutor.CodexAppServerMetadataKey].(bool)
	if !trusted {
		return req
	}
	metadata := cloneSchedulerAnyMap(req.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[cliproxyexecutor.CodexAppServerMetadataKey] = true
	if callerScope, ok := opts.Metadata[cliproxyexecutor.CallerScopeMetadataKey]; ok {
		metadata[cliproxyexecutor.CallerScopeMetadataKey] = callerScope
	}
	req.Metadata = metadata
	return req
}

func codexClientPolicyFromConfig(cfg internalconfig.CodexClientRestrictionConfig) codexclientpolicy.Policy {
	signals := cfg.EngineFingerprintSignals
	if signals == nil {
		signals = make([]internalconfig.CodexEngineFingerprintSignal, len(codexclientpolicy.DefaultEngineFingerprintSignals))
		for index, signal := range codexclientpolicy.DefaultEngineFingerprintSignals {
			signals[index] = internalconfig.CodexEngineFingerprintSignal{
				Type: signal.Type, Match: append([]string(nil), signal.Match...), Required: signal.Required,
			}
		}
	}
	policy := codexclientpolicy.Policy{
		ForceAllow:               cfg.ForceAllow,
		MinCodexVersion:          strings.TrimSpace(cfg.MinCodexVersion),
		MaxCodexVersion:          strings.TrimSpace(cfg.MaxCodexVersion),
		AllowAppServerClients:    cfg.AllowAppServerClients,
		Whitelist:                make([]codexclientpolicy.ClientEntry, 0, len(cfg.Whitelist)),
		Blacklist:                make([]codexclientpolicy.ClientEntry, 0, len(cfg.Blacklist)),
		EngineFingerprintSignals: make([]codexclientpolicy.EngineFingerprintSignal, 0, len(signals)),
	}
	for _, entry := range cfg.Whitelist {
		policy.Whitelist = append(policy.Whitelist, codexclientpolicy.ClientEntry{
			Originator: entry.Originator, UAContains: append([]string(nil), entry.UAContains...), SkipEngineFingerprint: entry.SkipEngineFingerprint,
		})
	}
	for _, entry := range cfg.Blacklist {
		policy.Blacklist = append(policy.Blacklist, codexclientpolicy.ClientEntry{
			Originator: entry.Originator, UAContains: append([]string(nil), entry.UAContains...),
		})
	}
	for _, signal := range signals {
		policy.EngineFingerprintSignals = append(policy.EngineFingerprintSignals, codexclientpolicy.EngineFingerprintSignal{
			Type: signal.Type, Match: append([]string(nil), signal.Match...), Required: signal.Required,
		})
	}
	return policy
}

func codexClientRestrictionEnabledForAuth(auth *Auth) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(executorKeyFromAuth(auth)), "codex") || auth.AuthKind() != AuthKindOAuth {
		return false
	}
	enabled, ok := parseBoolAny(auth.Metadata["codex_cli_only"])
	return ok && enabled
}

func codexClientRestrictionAppServerEnabledForAuth(auth *Auth) bool {
	if !codexClientRestrictionEnabledForAuth(auth) {
		return false
	}
	enabled, ok := parseBoolAny(auth.Metadata["codex_cli_only_allow_app_server"])
	return ok && enabled
}

func (m *Manager) codexClientRestrictionError(
	ctx context.Context,
	providers map[string]struct{},
	model string,
	opts cliproxyexecutor.Options,
	tried map[string]struct{},
	pinnedAuthID string,
) error {
	if m == nil || len(providers) == 0 {
		return nil
	}
	if evaluated, _ := opts.Metadata[codexClientRestrictionEvaluatedMetadataKey].(bool); !evaluated {
		return nil
	}

	fullEligibility := authSelectionEligibilityForRequest(ctx, opts)
	baseEligibility := fullEligibility
	baseEligibility.codexClientRestrictionEvaluated = false
	registryRef := registry.GetGlobalRegistry()
	restricted := false
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled {
			continue
		}
		provider := executorKeyFromAuth(candidate)
		if _, ok := providers[provider]; !ok {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		if _, used := tried[candidate.ID]; used {
			continue
		}
		if !baseEligibility.allows(candidate) {
			continue
		}
		if strings.TrimSpace(model) != "" && !m.authSupportsRouteModel(registryRef, candidate, model) {
			continue
		}
		if fullEligibility.allows(candidate) {
			return nil
		}
		if codexClientRestrictionEnabledForAuth(candidate) {
			restricted = true
		}
	}
	if !restricted {
		return nil
	}
	return &Error{Code: "codex_client_restricted", Message: codexClientRestrictionMessage, HTTPStatus: http.StatusForbidden}
}

func codexClientRestrictionAllowsAuth(opts cliproxyexecutor.Options, auth *Auth) bool {
	if auth == nil || !codexClientRestrictionEnabledForAuth(auth) {
		return true
	}
	evaluated, _ := opts.Metadata[codexClientRestrictionEvaluatedMetadataKey].(bool)
	if !evaluated {
		return true
	}
	if codexClientRestrictionAppServerEnabledForAuth(auth) {
		allowed, _ := opts.Metadata[codexClientRestrictionAppServerAllowedMetadataKey].(bool)
		return allowed
	}
	allowed, _ := opts.Metadata[codexClientRestrictionAllowedMetadataKey].(bool)
	return allowed
}
