package executor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	codexUserAgent             = "codex-tui/0.147.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.147.0)"
	codexOriginator            = "codex-tui"
	codexDefaultImageToolModel = "gpt-image-2"
	codexResponsesLiteHeader   = "X-OpenAI-Internal-Codex-Responses-Lite"
	codexResponsesLiteMetadata = "client_metadata.ws_request_header_x_openai_internal_codex_responses_lite"
	codexJSONOutputInstruction = "Return the response as JSON."
	codexJSONOutputMessage     = `{"type":"message","role":"developer","content":[{"type":"input_text","text":"Return the response as JSON."}]}`
	codexMissingToolOutput     = "Tool execution result unavailable. Continue using the available context."
)

var dataTag = []byte("data:")

func translateCodexRequestPair(from, to sdktranslator.Format, model string, originalPayload, payload []byte, stream bool, preserveEmptyThinkingBlocks ...bool) ([]byte, []byte) {
	isCompat := len(preserveEmptyThinkingBlocks) > 0 && preserveEmptyThinkingBlocks[0]
	translate := func(raw []byte) []byte {
		var translated []byte
		if isCompat && from == sdktranslator.FormatClaude && to == sdktranslator.FormatCodex {
			translated = helps.TranslateRequestWithAPIKeyModelCompatibility(context.Background(), nil, nil, from, to, model, raw, stream, true)
		} else {
			translated = sdktranslator.TranslateRequest(from, to, model, raw, stream)
		}
		if to == sdktranslator.FormatCodex {
			translated = restoreCodexTranslatedMessageIDs(raw, translated)
		}
		return translated
	}
	if bytes.Equal(originalPayload, payload) {
		body := translate(payload)
		return body, body
	}
	originalTranslated := translate(originalPayload)
	body := translate(payload)
	return originalTranslated, body
}

// Some translation paths rebuild message objects and omit their Responses item IDs.
// Preserve those IDs by message order so prompt-cache/session identity remains stable;
// the final Codex sanitizer applies the required type prefix and length bound.
func restoreCodexTranslatedMessageIDs(source, translated []byte) []byte {
	sourceInput := gjson.GetBytes(source, "input")
	targetInput := gjson.GetBytes(translated, "input")
	if !sourceInput.IsArray() || !targetInput.IsArray() {
		return translated
	}
	ids := make([]string, 0)
	for _, item := range sourceInput.Array() {
		itemType := strings.TrimSpace(item.Get("type").String())
		if itemType != "message" && !(itemType == "" && strings.TrimSpace(item.Get("role").String()) != "") {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.Get("id").String()))
	}
	if len(ids) == 0 {
		return translated
	}
	patched := translated
	messageIndex := 0
	for targetIndex, item := range targetInput.Array() {
		itemType := strings.TrimSpace(item.Get("type").String())
		if itemType != "message" && !(itemType == "" && strings.TrimSpace(item.Get("role").String()) != "") {
			continue
		}
		if messageIndex >= len(ids) {
			break
		}
		id := ids[messageIndex]
		messageIndex++
		if id == "" || strings.TrimSpace(item.Get("id").String()) != "" {
			continue
		}
		if next, errSet := sjson.SetBytes(patched, fmt.Sprintf("input.%d.id", targetIndex), id); errSet == nil {
			patched = next
		}
	}
	return patched
}

// PrepareRequest injects Codex credentials into the outgoing HTTP request.
func (e *CodexExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := codexCreds(auth)
	httpClient := helps.NewUtlsHTTPClient(req.Context(), e.cfg, auth, 0)
	authorization, _, err := helps.PrepareCodexAuthorization(req.Context(), auth, httpClient, apiKey)
	if err != nil {
		return err
	}
	setCodexAuthorizationHeader(req.Header, authorization)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Codex credentials into the request and executes it.
func (e *CodexExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codex executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	apiKey, _ := codexCreds(auth)
	authorization, taskID, err := helps.PrepareCodexAuthorization(ctx, auth, httpClient, apiKey)
	if err != nil {
		return nil, err
	}
	setCodexAuthorizationHeader(httpReq.Header, authorization)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(httpReq, attrs)
	return helps.DoCodexRequestWithAgentRecovery(ctx, auth, httpClient, httpClient, httpReq, taskID)
}

type codexIdentityConfuseState struct {
	enabled                bool
	authID                 string
	installationID         string
	originalPromptCacheKey string
	promptCacheKey         string
	turnIDs                []codexIdentityReplacement
}

type codexIdentityReplacement struct {
	original string
	confused string
}

func (e *CodexExecutor) cacheHelper(ctx context.Context, from sdktranslator.Format, url string, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, userPayload []byte, rawJSON []byte, headerSets ...http.Header) (*http.Request, []byte, codexIdentityConfuseState, error) {
	var headers http.Header
	if len(headerSets) > 0 {
		headers = headerSets[0]
	}
	rawJSON = normalizeCodexUpstreamCompatibility(rawJSON)
	cache, errCache := codexPromptCacheForRequest(ctx, e.cfg, from, req, rawJSON, headers)
	if errCache != nil {
		return nil, nil, codexIdentityConfuseState{}, errCache
	}

	if cache.ID != "" {
		rawJSON = helps.SetStringIfDifferent(rawJSON, "prompt_cache_key", cache.ID)
	}
	rawJSON = restoreCodexTranslatedMessageIDs(userPayload, rawJSON)
	rawJSON = helps.SanitizeCodexInputItemIDs(rawJSON)
	var identityState codexIdentityConfuseState
	rawJSON, identityState = applyCodexIdentityConfuseBody(e.cfg, auth, userPayload, rawJSON)
	if identityState.promptCacheKey != "" {
		cache.ID = identityState.promptCacheKey
	}
	rawJSON, appServerHeaders := applyCodexAppServerFingerprint(rawJSON, nil, req.Metadata)
	rawJSON = normalizeCodexReasoningEffortForModel(rawJSON, gjson.GetBytes(rawJSON, "model").String())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rawJSON))
	if err != nil {
		return nil, nil, codexIdentityConfuseState{}, err
	}
	if cache.ID != "" {
		httpReq.Header.Set("Session_id", cache.ID)
	}
	mergeMissingHeaders(httpReq.Header, appServerHeaders)
	return httpReq, rawJSON, identityState, nil
}

func normalizeCodexUpstreamCompatibility(body []byte) []byte {
	body = normalizeCodexOrphanToolCalls(body)
	body = normalizeCodexToolChoiceCompatibility(body)
	return normalizeCodexStructuredOutputCompatibility(body)
}

func normalizeCodexToolChoiceCompatibility(body []byte) []byte {
	choice := gjson.GetBytes(body, "tool_choice")
	if !choice.Exists() {
		return body
	}
	tools := codexDeclaredTools(body)
	if choice.Type == gjson.String {
		switch strings.ToLower(strings.TrimSpace(choice.String())) {
		case "auto", "none", "required":
			return body
		}
		return codexFallbackToolChoice(body, len(tools) > 0)
	}
	if !choice.IsObject() {
		return codexFallbackToolChoice(body, len(tools) > 0)
	}

	choiceType := strings.ToLower(strings.TrimSpace(choice.Get("type").String()))
	if choiceType == "allowed_tools" {
		return body
	}
	name := strings.TrimSpace(choice.Get("name").String())
	if name == "" {
		name = strings.TrimSpace(choice.Get("function.name").String())
	}
	for _, tool := range tools {
		toolType := strings.ToLower(strings.TrimSpace(tool.Get("type").String()))
		toolName := strings.TrimSpace(tool.Get("name").String())
		if toolName == "" {
			toolName = strings.TrimSpace(tool.Get("function.name").String())
		}
		switch choiceType {
		case "function", "custom":
			if toolType == choiceType && name != "" && toolName == name {
				return body
			}
		case "tool":
			if name != "" && (toolName == name || toolType == strings.ToLower(name)) {
				return body
			}
		default:
			if choiceType != "" && toolType == choiceType {
				return body
			}
		}
	}
	return codexFallbackToolChoice(body, len(tools) > 0)
}

func codexDeclaredTools(body []byte) []gjson.Result {
	tools := gjson.GetBytes(body, "tools")
	declared := make([]gjson.Result, 0)
	if tools.IsArray() {
		declared = append(declared, tools.Array()...)
	}
	input := gjson.GetBytes(body, "input")
	if input.IsArray() {
		for _, item := range input.Array() {
			if strings.TrimSpace(item.Get("type").String()) != "additional_tools" {
				continue
			}
			if additional := item.Get("tools"); additional.IsArray() {
				declared = append(declared, additional.Array()...)
			}
		}
	}
	return declared
}

func codexFallbackToolChoice(body []byte, hasTools bool) []byte {
	if hasTools {
		if updated, errSet := sjson.SetBytes(body, "tool_choice", "auto"); errSet == nil {
			return updated
		}
		return body
	}
	updated, errDelete := sjson.DeleteBytes(body, "tool_choice")
	if errDelete != nil {
		return body
	}
	updated, _ = sjson.DeleteBytes(updated, "parallel_tool_calls")
	return updated
}

// A truncated or retried client transcript can retain a tool call after losing
// its result. Codex rejects the whole request in that state. Supply a stable
// result immediately after the orphan while leaving every valid transcript
// byte-for-byte unchanged.
func normalizeCodexOrphanToolCalls(body []byte) []byte {
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return body
	}
	items := input.Array()
	outputs := make(map[string]struct{}, len(items))
	for _, item := range items {
		itemType := strings.TrimSpace(item.Get("type").String())
		if itemType != "function_call_output" && itemType != "custom_tool_call_output" {
			continue
		}
		if callID := strings.TrimSpace(item.Get("call_id").String()); callID != "" {
			outputs[itemType+"\x00"+callID] = struct{}{}
		}
	}

	normalized := make([][]byte, 0, len(items))
	synthesized := make(map[string]struct{})
	changed := false
	for _, item := range items {
		normalized = append(normalized, []byte(item.Raw))
		callType := strings.TrimSpace(item.Get("type").String())
		outputType := ""
		switch callType {
		case "function_call":
			outputType = "function_call_output"
		case "custom_tool_call":
			outputType = "custom_tool_call_output"
		default:
			continue
		}
		callID := strings.TrimSpace(item.Get("call_id").String())
		if callID == "" {
			continue
		}
		key := outputType + "\x00" + callID
		if _, ok := outputs[key]; ok {
			continue
		}
		if _, ok := synthesized[key]; ok {
			continue
		}
		output := []byte(`{"type":"function_call_output"}`)
		output, _ = sjson.SetBytes(output, "type", outputType)
		output, _ = sjson.SetBytes(output, "call_id", callID)
		output, _ = sjson.SetBytes(output, "output", codexMissingToolOutput)
		normalized = append(normalized, output)
		synthesized[key] = struct{}{}
		changed = true
	}
	if !changed {
		return body
	}
	updated, errSet := sjson.SetRawBytes(body, "input", helps.JoinRawJSONArray(normalized))
	if errSet != nil {
		return body
	}
	return updated
}

// The Responses API requires an explicit JSON reference when json_object output
// is requested. Keep the mutation deterministic and append-only so the existing
// prompt prefix and cache-affinity identity remain stable.
func normalizeCodexStructuredOutputCompatibility(body []byte) []byte {
	formatType := strings.TrimSpace(gjson.GetBytes(body, "text.format.type").String())
	if !strings.EqualFold(formatType, "json_object") {
		return body
	}
	if codexStructuredOutputTextContainsJSON(gjson.GetBytes(body, "instructions")) ||
		codexStructuredOutputInputContainsJSON(gjson.GetBytes(body, "input")) {
		return body
	}

	input := gjson.GetBytes(body, "input")
	switch {
	case input.Type == gjson.String:
		value := input.String()
		if strings.TrimSpace(value) == "" {
			value = codexJSONOutputInstruction
		} else {
			value += "\n\n" + codexJSONOutputInstruction
		}
		if updated, errSet := sjson.SetBytes(body, "input", value); errSet == nil {
			return updated
		}
	case input.IsArray():
		if updated, errSet := sjson.SetRawBytes(body, "input.-1", []byte(codexJSONOutputMessage)); errSet == nil {
			return updated
		}
	}
	return body
}

func codexStructuredOutputInputContainsJSON(value gjson.Result) bool {
	if value.Type == gjson.String {
		return strings.Contains(strings.ToLower(value.String()), "json")
	}
	if !value.IsArray() {
		return false
	}
	for _, item := range value.Array() {
		if item.Type == gjson.String && strings.Contains(strings.ToLower(item.String()), "json") {
			return true
		}
		itemType := strings.TrimSpace(item.Get("type").String())
		role := strings.TrimSpace(item.Get("role").String())
		if itemType != "message" && role == "" {
			continue
		}
		if codexStructuredOutputTextContainsJSON(item.Get("content")) {
			return true
		}
	}
	return false
}

func codexStructuredOutputTextContainsJSON(value gjson.Result) bool {
	if value.Type == gjson.String {
		return strings.Contains(strings.ToLower(value.String()), "json")
	}
	if !value.IsArray() {
		return false
	}
	for _, part := range value.Array() {
		if part.Type == gjson.String && strings.Contains(strings.ToLower(part.String()), "json") {
			return true
		}
		for _, field := range []string{"text", "content"} {
			if strings.Contains(strings.ToLower(part.Get(field).String()), "json") {
				return true
			}
		}
	}
	return false
}

func applyCodexAppServerFingerprint(body []byte, headers http.Header, metadata map[string]any) ([]byte, http.Header) {
	trusted, _ := metadata[cliproxyexecutor.CodexAppServerMetadataKey].(bool)
	if !trusted {
		return body, headers
	}
	if headers == nil {
		headers = make(http.Header)
	}
	cacheID := strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String())
	callerScope := strings.TrimSpace(metadataString(metadata, cliproxyexecutor.CallerScopeMetadataKey))
	seed := cacheID
	if seed == "" {
		seed = callerScope
	}
	if seed == "" {
		seed = "cpa-app-server"
	}
	installationSeed := callerScope
	if installationSeed == "" {
		installationSeed = seed
	}
	installationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:app-server:installation:"+installationSeed)).String()
	windowID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:app-server:window:"+seed)).String()
	threadID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:app-server:thread:"+seed)).String()
	sessionID := cacheID
	if sessionID == "" {
		sessionID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:app-server:session:"+seed)).String()
	}
	if !gjson.GetBytes(body, "client_metadata.x-codex-installation-id").Exists() {
		body, _ = sjson.SetBytes(body, "client_metadata.x-codex-installation-id", installationID)
	}
	if !gjson.GetBytes(body, "client_metadata.x-codex-window-id").Exists() {
		body, _ = sjson.SetBytes(body, "client_metadata.x-codex-window-id", windowID)
	}
	setHeaderIfMissing(headers, "X-Codex-Window-Id", windowID)
	setHeaderIfMissing(headers, "Session_id", sessionID)
	setHeaderIfMissing(headers, "Thread-Id", threadID)
	return body, headers
}

func setHeaderIfMissing(headers http.Header, key, value string) {
	if headers == nil || strings.TrimSpace(headerValueCaseInsensitive(headers, key)) != "" {
		return
	}
	setHeaderCasePreserved(headers, key, value)
}

func mergeMissingHeaders(target, source http.Header) {
	for key, values := range source {
		if strings.TrimSpace(headerValueCaseInsensitive(target, key)) != "" || len(values) == 0 {
			continue
		}
		setHeaderCasePreserved(target, key, values[0])
	}
}

func codexPromptCacheForRequest(ctx context.Context, cfg *config.Config, from sdktranslator.Format, req cliproxyexecutor.Request, rawJSON []byte, headers http.Header) (helps.CodexCache, error) {
	var cache helps.CodexCache
	if sourceFormatEqual(from, sdktranslator.FormatClaude) {
		modelName := strings.TrimSpace(gjson.GetBytes(rawJSON, "model").String())
		if modelName == "" {
			modelName = thinking.ParseSuffix(req.Model).ModelName
		}
		cached, ok, errCache := helps.ClaudeCodePromptCache(ctx, modelName, req.Payload, headers)
		if errCache != nil {
			return helps.CodexCache{}, errCache
		}
		if ok {
			cache = cached
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAIResponse) {
		promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key")
		if promptCacheKey.Exists() {
			cache.ID = promptCacheKey.String()
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAI) {
		if promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key"); promptCacheKey.Exists() {
			cache.ID = strings.TrimSpace(promptCacheKey.String())
		}
	}
	if coordinated := cacheaffinity.MetadataValue(req.Metadata, cliproxyexecutor.CacheAffinityUpstreamKeyMetadataKey); coordinated != "" {
		cache.ID = coordinated
	}
	if cache.ID == "" && codexHighCacheMode(cfg) {
		cache.ID = codexHighCachePromptCacheID(ctx, req.Metadata)
	}
	if cache.ID == "" {
		cache.ID = helps.ProviderSessionUUID("codex", req.Metadata)
	}
	if cache.ID == "" && sourceFormatEqual(from, sdktranslator.FormatOpenAI) {
		cache.ID = codexAPIKeyPromptCacheID(ctx)
	}
	return cache, nil
}

func codexHighCacheMode(cfg *config.Config) bool {
	return cfg != nil && cfg.Routing.HighCacheMode
}

func codexHighCachePromptCacheID(ctx context.Context, metadata map[string]any) string {
	if key := codexAPIKeyPromptCacheID(ctx); key != "" {
		return key
	}
	if callerScope := strings.TrimSpace(metadataString(metadata, cliproxyexecutor.CallerScopeMetadataKey)); callerScope != "" {
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache-caller-scope:"+callerScope)).String()
	}
	return ""
}

func codexAPIKeyPromptCacheID(ctx context.Context) string {
	if apiKey := strings.TrimSpace(helps.APIKeyFromContext(ctx)); apiKey != "" {
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
	}
	return ""
}

func applyCodexIdentityConfuseBody(cfg *config.Config, auth *cliproxyauth.Auth, userPayload []byte, rawJSON []byte) ([]byte, codexIdentityConfuseState) {
	if !codexIdentityConfuseEnabled(cfg) || auth == nil || strings.TrimSpace(auth.ID) == "" || len(rawJSON) == 0 {
		return rawJSON, codexIdentityConfuseState{}
	}

	state := codexIdentityConfuseState{
		enabled:        true,
		authID:         strings.TrimSpace(auth.ID),
		installationID: codexAccountInstallationID(auth),
	}
	clientPromptCacheKey := strings.TrimSpace(gjson.GetBytes(userPayload, "prompt_cache_key").String())
	promptCacheKey := strings.TrimSpace(gjson.GetBytes(rawJSON, "prompt_cache_key").String())
	if promptCacheKey != "" {
		state.originalPromptCacheKey = clientPromptCacheKey
		state.promptCacheKey = codexIdentityConfuseUUID(auth.ID, "prompt-cache", promptCacheKey)
		rawJSON = helps.SetStringIfDifferent(rawJSON, "prompt_cache_key", state.promptCacheKey)
	}
	// Installation identity is an account-level device fingerprint. It must not
	// inherit the downstream installation ID: one account may be reached by many
	// clients, and allowing that input into the derivation makes the same OAuth
	// credential look like a different installation on every caller. The stable
	// account seed also survives auth-file renames when account metadata exists.
	if state.installationID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-installation-id", state.installationID)
	}
	if turnMetadata := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-turn-metadata").String()); turnMetadata != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-turn-metadata", applyCodexTurnMetadataIdentityConfuse(turnMetadata, &state))
	}
	if state.promptCacheKey != "" {
		if windowID := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-window-id").String()); windowID != "" {
			rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-window-id", state.promptCacheKey+":0")
		}
	}

	return rawJSON, state
}

func applyCodexIdentityConfuseHeaders(headers http.Header, state *codexIdentityConfuseState) {
	if headers == nil {
		return
	}
	if state == nil || !state.enabled {
		return
	}

	if rawTurnMetadata := strings.TrimSpace(headers.Get("X-Codex-Turn-Metadata")); rawTurnMetadata != "" {
		headers.Set("X-Codex-Turn-Metadata", applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata, state))
	}
	if state.promptCacheKey == "" {
		return
	}

	setCodexSessionHeaderCasePreserved(headers, "Session_id", state.promptCacheKey)
	if headerValueCaseInsensitive(headers, "Conversation_id") != "" {
		setHeaderCasePreserved(headers, "Conversation_id", state.promptCacheKey)
	}
	headers.Set("X-Client-Request-Id", state.promptCacheKey)
	headers.Set("Thread-Id", state.promptCacheKey)
	headers.Set("X-Codex-Window-Id", state.promptCacheKey+":0")
}

func applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata string, state *codexIdentityConfuseState) string {
	updatedTurnMetadata := rawTurnMetadata
	if state == nil || !state.enabled {
		return updatedTurnMetadata
	}
	if state.promptCacheKey != "" && gjson.Get(rawTurnMetadata, "prompt_cache_key").Exists() {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "prompt_cache_key", state.promptCacheKey)
	} else if state.promptCacheKey != "" {
		if state.originalPromptCacheKey != "" {
			updatedTurnMetadata = strings.ReplaceAll(updatedTurnMetadata, state.originalPromptCacheKey, state.promptCacheKey)
		}
	}
	if turnID := strings.TrimSpace(gjson.Get(rawTurnMetadata, "turn_id").String()); turnID != "" {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "turn_id", state.confuseTurnID(turnID))
	}
	if state.promptCacheKey != "" && gjson.Get(rawTurnMetadata, "window_id").Exists() {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "window_id", state.promptCacheKey+":0")
	}
	return updatedTurnMetadata
}

func applyCodexIdentityConfuseResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	// Client-facing identifiers are rewritten only by applyCodexIdentityExposeResponsePayload.
	// Keeping this pass focused on turn IDs prevents an internally derived cache key
	// from being restored to a client that never supplied one.
	if state.originalPromptCacheKey != state.promptCacheKey {
		payload = replaceCodexIdentityResponsePayload(payload, state.originalPromptCacheKey, state.promptCacheKey)
	}
	for _, turnID := range state.turnIDs {
		payload = replaceCodexIdentityResponsePayload(payload, turnID.original, turnID.confused)
	}
	return payload
}

func applyCodexIdentityExposeResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	if state.originalPromptCacheKey != "" {
		payload = replaceCodexIdentityResponsePayload(payload, state.promptCacheKey, state.originalPromptCacheKey)
	}
	for _, turnID := range state.turnIDs {
		payload = replaceCodexIdentityResponsePayload(payload, turnID.confused, turnID.original)
	}
	return payload
}

func (state *codexIdentityConfuseState) confuseTurnID(turnID string) string {
	turnID = strings.TrimSpace(turnID)
	if state == nil || !state.enabled || strings.TrimSpace(state.authID) == "" || turnID == "" {
		return turnID
	}
	for _, replacement := range state.turnIDs {
		if replacement.original == turnID || replacement.confused == turnID {
			return replacement.confused
		}
	}
	confusedTurnID := codexIdentityConfuseUUID(state.authID, "turn", turnID)
	state.turnIDs = append(state.turnIDs, codexIdentityReplacement{original: turnID, confused: confusedTurnID})
	return confusedTurnID
}

func replaceCodexIdentityResponsePayload(payload []byte, from string, to string) []byte {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if len(payload) == 0 || from == "" || to == "" || from == to || !bytes.Contains(payload, []byte(from)) {
		return payload
	}
	return bytes.ReplaceAll(payload, []byte(from), []byte(to))
}

func codexIdentityConfuseEnabled(cfg *config.Config) bool {
	if cfg == nil || !cfg.Codex.IdentityConfuse {
		return false
	}
	strategy := strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy))
	return cfg.Routing.SessionAffinity || cfg.Routing.HighCacheMode || strategy == "fill-first" || strategy == "fillfirst" || strategy == "ff"
}

func codexIdentityConfuseUUID(authID string, kind string, value string) string {
	name := strings.Join([]string{"cli-proxy-api", "codex", "identity-confuse", kind, strings.TrimSpace(authID), strings.TrimSpace(value)}, ":")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func codexAccountInstallationID(auth *cliproxyauth.Auth) string {
	seed := codexAccountFingerprintSeed(auth)
	if seed == "" {
		return ""
	}
	name := strings.Join([]string{"cli-proxy-api", "codex", "account-fingerprint", "installation", seed}, ":")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func codexAccountFingerprintSeed(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	// A persisted explicit seed has highest precedence. Supply/import tooling can
	// retain this value while rotating tokens or changing display metadata.
	if explicit := firstCodexAuthMetadataString(auth,
		"codex_identity_fingerprint",
		"codex-identity-fingerprint",
		"codexIdentityFingerprint",
	); explicit != "" {
		return "explicit:" + explicit
	}

	// Team workspace/account IDs are shared by many members, so email remains a
	// required part of the normal seed. Lower-casing makes casing-only supplier
	// updates preserve the same upstream installation identity.
	email := strings.ToLower(firstCodexAuthMetadataString(auth, "email", "outlook_email"))
	accountID := firstCodexAuthMetadataString(auth, "chatgpt_account_id", "account_id", "workspace_id", "organization_id")
	if email != "" {
		return strings.Join([]string{"account", email, accountID}, ":")
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return "auth-id:" + id
	}
	return ""
}

func firstCodexAuthMetadataString(auth *cliproxyauth.Auth, keys ...string) string {
	if auth == nil {
		return ""
	}
	for _, key := range keys {
		if auth.Metadata != nil {
			if value, ok := auth.Metadata[key].(string); ok {
				if value = strings.TrimSpace(value); value != "" {
					return value
				}
			}
		}
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func applyCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config) {
	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}
	applyCodexHeadersFromSources(r, auth, token, stream, cfg, ginHeaders)
}

// applyModelHeaderOverrides forces models.json config.override_header onto upstream headers.
func applyModelHeaderOverrides(headers http.Header, modelName string) {
	if headers == nil {
		return
	}
	overrides := registry.ModelOverrideHeaders(modelName)
	if len(overrides) == 0 {
		return
	}
	for key, value := range overrides {
		headers.Set(key, value)
	}
	if strings.Contains(headers.Get("User-Agent"), "Mac OS") && codexSessionHeaderValue(headers) == "" {
		headers.Set("Session_id", uuid.NewString())
	}
}

// applyCodexDirectImageHeaders sets Codex upstream headers for direct /images/* calls.
// Downstream client User-Agent values are not forwarded to reduce Cloudflare 1010 blocks.
func applyCodexDirectImageHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config) {
	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header.Clone()
		ginHeaders.Del("User-Agent")
	}
	applyCodexHeadersFromSources(r, auth, token, stream, cfg, ginHeaders)
}

func applyCodexHeadersFromSources(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config, ginHeaders http.Header) {
	r.Header.Set("Content-Type", "application/json")
	setCodexAuthorizationHeader(r.Header, token)

	if ginHeaders != nil && ginHeaders.Get("X-Codex-Beta-Features") != "" {
		r.Header.Set("X-Codex-Beta-Features", ginHeaders.Get("X-Codex-Beta-Features"))
	}
	misc.EnsureHeader(r.Header, ginHeaders, "Version", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-Metadata", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Client-Request-Id", "")
	cfgUserAgent, _ := codexHeaderDefaults(cfg, auth)
	ensureHeaderWithConfigPrecedence(r.Header, ginHeaders, "User-Agent", cfgUserAgent, codexUserAgent)

	if strings.Contains(r.Header.Get("User-Agent"), "Mac OS") {
		misc.EnsureHeader(r.Header, ginHeaders, "Session_id", uuid.NewString())
	}

	if stream {
		r.Header.Set("Accept", "text/event-stream")
	} else {
		r.Header.Set("Accept", "application/json")
	}
	r.Header.Set("Connection", "Keep-Alive")

	isAPIKey := false
	if auth != nil && auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["api_key"]); v != "" {
			isAPIKey = true
		}
	}
	if originator := strings.TrimSpace(ginHeaders.Get("Originator")); originator != "" {
		r.Header.Set("Originator", originator)
	} else if !isAPIKey {
		r.Header.Set("Originator", codexOriginator)
	}
	if !isAPIKey {
		if accountID := codexAuthAccountID(auth); accountID != "" {
			r.Header.Set("Chatgpt-Account-Id", accountID)
		}
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)
	applyCodexCloakingHeaders(r.Header, cfg)
}

func codexAuthAccountID(auth *cliproxyauth.Auth) string {
	return firstCodexAuthMetadataString(
		auth,
		"account_id",
		"chatgpt_account_id",
		"workspace_id",
		"organization_id",
	)
}

func setCodexAuthorizationHeader(headers http.Header, authorization string) {
	if headers == nil {
		return
	}
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		headers.Del("Authorization")
		return
	}
	lower := strings.ToLower(authorization)
	if strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "agentassertion ") {
		headers.Set("Authorization", authorization)
		return
	}
	headers.Set("Authorization", "Bearer "+authorization)
}

func applyCodexCloakingHeaders(headers http.Header, cfg *config.Config) {
	if headers == nil || cfg == nil || cfg.Codex.DisableCodexCloaking {
		return
	}
	headers.Set("User-Agent", codexUserAgent)
	headers.Set("Originator", codexOriginator)
}

func normalizeCodexInstructions(body []byte) []byte {
	instructions := gjson.GetBytes(body, "instructions")
	if !instructions.Exists() || instructions.Type == gjson.Null {
		body, _ = sjson.SetBytes(body, "instructions", "")
	}
	return body
}

var imageGenToolJSON = []byte(`{"type":"image_generation","output_format":"png"}`)
var imageGenToolArrayJSON = []byte(`[{"type":"image_generation","output_format":"png"}]`)

func isCodexFreePlanAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["plan_type"]), "free")
}

func isImageGenerationFunctionTool(tool gjson.Result) bool {
	switch tool.Get("type").String() {
	case "function":
		return tool.Get("name").String() == "image_gen.imagegen"
	case "namespace":
		if tool.Get("name").String() != "image_gen" {
			return false
		}
		tools := tool.Get("tools")
		if !tools.IsArray() {
			return false
		}
		for _, nestedTool := range tools.Array() {
			if nestedTool.Get("type").String() == "function" && nestedTool.Get("name").String() == "imagegen" {
				return true
			}
		}
	}
	return false
}

func isCodexResponsesLiteRequest(body []byte, headers http.Header) bool {
	if strings.EqualFold(strings.TrimSpace(headers.Get(codexResponsesLiteHeader)), "true") {
		return true
	}
	// Codex Desktop mirrors websocket-only request headers into client_metadata.
	value := gjson.GetBytes(body, codexResponsesLiteMetadata)
	if !value.Exists() {
		return false
	}
	return value.Type == gjson.True || value.Type == gjson.String && strings.EqualFold(strings.TrimSpace(value.String()), "true")
}

func ensureImageGenerationTool(body []byte, baseModel string, auth *cliproxyauth.Auth, headers http.Header) []byte {
	if isCodexResponsesLiteRequest(body, headers) {
		return body
	}
	if strings.HasSuffix(baseModel, "spark") {
		return body
	}
	if isCodexFreePlanAuth(auth) {
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	if !tools.Exists() || !tools.IsArray() {
		body, _ = sjson.SetRawBytes(body, "tools", imageGenToolArrayJSON)
		return body
	}
	for _, t := range tools.Array() {
		if t.Get("type").String() == "image_generation" || isImageGenerationFunctionTool(t) {
			return body
		}
	}
	body, _ = sjson.SetRawBytes(body, "tools.-1", imageGenToolJSON)
	return body
}

func injectCodexTailBurstTool(body []byte, baseModel string, opts cliproxyexecutor.Options, cfg *config.Config, headers http.Header) []byte {
	if cfg == nil || !cfg.Codex.TailBurst.Enabled || !cfg.Codex.TailBurst.ToolInjection.Enabled || len(opts.Metadata) == 0 {
		return body
	}
	tailBurst, _ := opts.Metadata[cliproxyexecutor.CodexTailBurstMetadataKey].(bool)
	if !tailBurst {
		return body
	}
	updated, _ := helps.InjectCodexTailBurstTool(
		body,
		baseModel,
		cfg.Codex.TailBurst.ToolInjection.ModelAllowlist,
		isCodexResponsesLiteRequest(body, headers),
	)
	return updated
}

func normalizeCodexParallelToolCalls(body []byte, headers http.Header) []byte {
	if isCodexResponsesLiteRequest(body, headers) {
		body = helps.SetBoolIfDifferent(body, "parallel_tool_calls", false)
		return body
	}
	return normalizeCodexParallelToolCallsForTools(body)
}

func normalizeCodexParallelToolCallsForTools(body []byte) []byte {
	if !gjson.GetBytes(body, "parallel_tool_calls").Exists() {
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	hasTools := tools.Exists() && tools.IsArray() && len(tools.Array()) > 0
	if hasTools {
		return body
	}

	body, _ = sjson.DeleteBytes(body, "parallel_tool_calls")
	return body
}

func publishCodexImageToolUsage(ctx context.Context, reporter *helps.UsageReporter, body []byte, completedData []byte) {
	detail, ok := helps.ParseCodexImageToolUsage(completedData)
	if !ok {
		return
	}
	reporter.EnsurePublished(ctx)
	reporter.PublishAdditionalModel(ctx, codexImageGenerationToolModel(body), detail)
}

func codexImageGenerationToolModel(body []byte) string {
	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		for _, tool := range tools.Array() {
			if tool.Get("type").String() != "image_generation" {
				continue
			}
			if model := strings.TrimSpace(tool.Get("model").String()); model != "" {
				return model
			}
			break
		}
	}
	return codexDefaultImageToolModel
}
