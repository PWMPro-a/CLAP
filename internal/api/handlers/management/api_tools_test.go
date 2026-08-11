package management

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

type apiToolsAgentIdentityRuntime struct {
	authorization  string
	taskID         string
	authorizeErr   error
	recoverErr     error
	recoveries     int
	runtimeDeleted bool
}

func (r *apiToolsAgentIdentityRuntime) Authorization(context.Context, *http.Client) (string, string, error) {
	return r.authorization, r.taskID, r.authorizeErr
}

func (r *apiToolsAgentIdentityRuntime) RecoverAuthorization(context.Context, *http.Client, string) (string, error) {
	r.recoveries++
	return "", r.recoverErr
}

func (r *apiToolsAgentIdentityRuntime) MarkRuntimeDeleted() {
	r.runtimeDeleted = true
}

func (r *apiToolsAgentIdentityRuntime) RedactSensitiveBody(body []byte) []byte {
	redacted := strings.ReplaceAll(string(body), "runtime-secret", "[redacted]")
	redacted = strings.ReplaceAll(redacted, "task-secret", "[redacted]")
	return []byte(redacted)
}

func invokeManagementAPICall(t *testing.T, handler *Handler, payload map[string]any) (int, apiCallResponse) {
	t.Helper()
	body, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		t.Fatalf("json.Marshal: %v", errMarshal)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/api-call", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.APICall(ctx)

	var response apiCallResponse
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &response); errDecode != nil {
		t.Fatalf("decode api-call response: %v body=%s", errDecode, recorder.Body.String())
	}
	return recorder.Code, response
}

func TestAPICallAgentIdentityUsesWholeAuthorizationValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var upstreamAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	runtime := &apiToolsAgentIdentityRuntime{
		authorization: "AgentAssertion signed-value",
		taskID:        "task-secret",
	}
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "agent", Provider: "codex", Runtime: runtime}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	status, response := invokeManagementAPICall(t, handler, map[string]any{
		"auth_index": auth.Index,
		"method":     http.MethodGet,
		"url":        upstream.URL,
		"header": map[string]string{
			"Authorization": "Bearer $TOKEN$",
		},
	})

	if status != http.StatusOK || response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d upstream_status=%d body=%s", status, response.StatusCode, response.Body)
	}
	if upstreamAuthorization != "AgentAssertion signed-value" {
		t.Fatalf("Authorization = %q, want complete AgentAssertion", upstreamAuthorization)
	}
	if strings.HasPrefix(upstreamAuthorization, "Bearer AgentAssertion ") {
		t.Fatalf("Authorization has duplicate scheme: %q", upstreamAuthorization)
	}
}

func TestAPICallNormalOAuthKeepsBearerTokenReplacement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var upstreamAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "oauth",
		Provider: "codex",
		Metadata: map[string]any{"access_token": "oauth-token"},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	status, response := invokeManagementAPICall(t, handler, map[string]any{
		"auth_index": auth.Index,
		"method":     http.MethodGet,
		"url":        upstream.URL,
		"header": map[string]string{
			"Authorization": "Bearer $TOKEN$",
		},
	})

	if status != http.StatusOK || response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d upstream_status=%d body=%s", status, response.StatusCode, response.Body)
	}
	if upstreamAuthorization != "Bearer oauth-token" {
		t.Fatalf("Authorization = %q, want ordinary bearer token", upstreamAuthorization)
	}
}

func TestAPICallAgentIdentityQueuesRejectedTaskWithoutLeakingDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"task_expired","detail":"runtime-secret task-secret"}}`)
	}))
	defer upstream.Close()

	runtime := &apiToolsAgentIdentityRuntime{
		authorization: "AgentAssertion signed-value",
		taskID:        "task-secret",
		recoverErr:    codexauth.ErrAgentIdentityRegistrationPending,
	}
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "agent", Provider: "codex", Runtime: runtime}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	status, response := invokeManagementAPICall(t, handler, map[string]any{
		"auth_index": auth.Index,
		"method":     http.MethodGet,
		"url":        upstream.URL,
		"header": map[string]string{
			"Authorization": "Bearer $TOKEN$",
		},
	})

	if status != http.StatusOK || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d upstream_status=%d body=%s", status, response.StatusCode, response.Body)
	}
	if runtime.recoveries != 1 {
		t.Fatalf("task recoveries = %d, want 1", runtime.recoveries)
	}
	if !strings.Contains(response.Body, "agent_identity_registration_pending") ||
		strings.Contains(response.Body, "runtime-secret") || strings.Contains(response.Body, "task-secret") {
		t.Fatalf("unsafe or unexpected response body: %s", response.Body)
	}
}

func TestAPICallAgentIdentityPendingReturnsSanitizedResult(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &apiToolsAgentIdentityRuntime{
		taskID:       "task-secret",
		authorizeErr: codexauth.ErrAgentIdentityRegistrationPending,
	}
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "agent", Provider: "codex", Runtime: runtime}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	status, response := invokeManagementAPICall(t, handler, map[string]any{
		"auth_index": auth.Index,
		"method":     http.MethodGet,
		"url":        "https://example.invalid/quota",
		"header": map[string]string{
			"Authorization": "Bearer $TOKEN$",
		},
	})

	if status != http.StatusOK || response.StatusCode != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body, "agent_identity_registration_pending") {
		t.Fatalf("status=%d upstream_status=%d body=%s", status, response.StatusCode, response.Body)
	}
	if strings.Contains(response.Body, "task-secret") {
		t.Fatalf("pending response exposed task details: %s", response.Body)
	}
}

func TestAPICallAgentIdentityRuntimeDeletedReturnsSanitizedResult(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"Agent runtime has been deleted: runtime-secret task-secret"}}`)
	}))
	defer upstream.Close()

	runtime := &apiToolsAgentIdentityRuntime{
		authorization: "AgentAssertion signed-value",
		taskID:        "task-secret",
	}
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "agent", Provider: "codex", Runtime: runtime}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	status, response := invokeManagementAPICall(t, handler, map[string]any{
		"auth_index": auth.Index,
		"method":     http.MethodGet,
		"url":        upstream.URL,
		"header": map[string]string{
			"Authorization": "Bearer $TOKEN$",
		},
	})

	if status != http.StatusOK || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d upstream_status=%d body=%s", status, response.StatusCode, response.Body)
	}
	if !runtime.runtimeDeleted || !strings.Contains(response.Body, "agent_identity_runtime_deleted") {
		t.Fatalf("runtime_deleted=%v body=%s", runtime.runtimeDeleted, response.Body)
	}
	if strings.Contains(response.Body, "runtime-secret") || strings.Contains(response.Body, "task-secret") {
		t.Fatalf("runtime-deleted response leaked identity details: %s", response.Body)
	}
}

func TestAPICallTransportDirectBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	h := &Handler{
		cfg: &config.Config{
			SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"},
		},
	}

	transport := h.apiCallTransport(&coreauth.Auth{ProxyURL: "direct"})
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", transport)
	}
	if httpTransport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestAPICallTransportAuthSourceIPBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	h := &Handler{
		cfg: &config.Config{
			SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"},
		},
	}

	transport := h.apiCallTransport(&coreauth.Auth{SourceIP: "127.0.0.2"})
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", transport)
	}
	if httpTransport.Proxy != nil {
		t.Fatal("expected source IP transport to bypass proxy function")
	}
	if httpTransport.DialContext == nil {
		t.Fatal("expected source IP transport to configure DialContext")
	}
}

func TestAPICallTransportInvalidAuthFallsBackToGlobalProxy(t *testing.T) {
	t.Parallel()

	h := &Handler{
		cfg: &config.Config{
			SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"},
		},
	}

	transport := h.apiCallTransport(&coreauth.Auth{ProxyURL: "bad-value"})
	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", transport)
	}

	req, errRequest := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if errRequest != nil {
		t.Fatalf("http.NewRequest returned error: %v", errRequest)
	}

	proxyURL, errProxy := httpTransport.Proxy(req)
	if errProxy != nil {
		t.Fatalf("httpTransport.Proxy returned error: %v", errProxy)
	}
	if proxyURL == nil || proxyURL.String() != "http://global-proxy.example.com:8080" {
		t.Fatalf("proxy URL = %v, want http://global-proxy.example.com:8080", proxyURL)
	}
}

func TestAPICallTransportAPIKeyAuthFallsBackToConfigProxyURL(t *testing.T) {
	t.Parallel()

	h := &Handler{
		cfg: &config.Config{
			SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"},
			GeminiKey: []config.GeminiKey{{
				APIKey:   "gemini-key",
				ProxyURL: "http://gemini-proxy.example.com:8080",
			}},
			ClaudeKey: []config.ClaudeKey{{
				APIKey:   "claude-key",
				ProxyURL: "http://claude-proxy.example.com:8080",
			}},
			CodexKey: []config.CodexKey{{
				APIKey:   "codex-key",
				ProxyURL: "http://codex-proxy.example.com:8080",
			}},
			XAIKey: []config.XAIKey{{
				APIKey:   "xai-key",
				ProxyURL: "http://xai-proxy.example.com:8080",
			}},
			OpenAICompatibility: []config.OpenAICompatibility{{
				Name:    "bohe",
				BaseURL: "https://bohe.example.com",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{
					APIKey:   "compat-key",
					ProxyURL: "http://compat-proxy.example.com:8080",
				}},
			}},
		},
	}

	cases := []struct {
		name      string
		auth      *coreauth.Auth
		wantProxy string
	}{
		{
			name: "gemini",
			auth: &coreauth.Auth{
				Provider:   "gemini",
				Attributes: map[string]string{"api_key": "gemini-key"},
			},
			wantProxy: "http://gemini-proxy.example.com:8080",
		},
		{
			name: "claude",
			auth: &coreauth.Auth{
				Provider:   "claude",
				Attributes: map[string]string{"api_key": "claude-key"},
			},
			wantProxy: "http://claude-proxy.example.com:8080",
		},
		{
			name: "codex",
			auth: &coreauth.Auth{
				Provider:   "codex",
				Attributes: map[string]string{"api_key": "codex-key"},
			},
			wantProxy: "http://codex-proxy.example.com:8080",
		},
		{
			name: "xai",
			auth: &coreauth.Auth{
				Provider:   "xai",
				Attributes: map[string]string{"api_key": "xai-key"},
			},
			wantProxy: "http://xai-proxy.example.com:8080",
		},
		{
			name: "openai-compatibility",
			auth: &coreauth.Auth{
				Provider: "bohe",
				Attributes: map[string]string{
					"api_key":      "compat-key",
					"compat_name":  "bohe",
					"provider_key": "bohe",
				},
			},
			wantProxy: "http://compat-proxy.example.com:8080",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transport := h.apiCallTransport(tc.auth)
			httpTransport, ok := transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport type = %T, want *http.Transport", transport)
			}

			req, errRequest := http.NewRequest(http.MethodGet, "https://example.com", nil)
			if errRequest != nil {
				t.Fatalf("http.NewRequest returned error: %v", errRequest)
			}

			proxyURL, errProxy := httpTransport.Proxy(req)
			if errProxy != nil {
				t.Fatalf("httpTransport.Proxy returned error: %v", errProxy)
			}
			if proxyURL == nil || proxyURL.String() != tc.wantProxy {
				t.Fatalf("proxy URL = %v, want %s", proxyURL, tc.wantProxy)
			}
		})
	}
}

func TestAuthByIndexDistinguishesSharedAPIKeysAcrossProviders(t *testing.T) {
	t.Parallel()

	manager := coreauth.NewManager(nil, nil, nil)
	geminiAuth := &coreauth.Auth{
		ID:       "gemini:apikey:123",
		Provider: "gemini",
		Attributes: map[string]string{
			"api_key": "shared-key",
		},
	}
	compatAuth := &coreauth.Auth{
		ID:       "openai-compatibility:bohe:456",
		Provider: "bohe",
		Label:    "bohe",
		Attributes: map[string]string{
			"api_key":      "shared-key",
			"compat_name":  "bohe",
			"provider_key": "bohe",
		},
	}

	if _, errRegister := manager.Register(context.Background(), geminiAuth); errRegister != nil {
		t.Fatalf("register gemini auth: %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), compatAuth); errRegister != nil {
		t.Fatalf("register compat auth: %v", errRegister)
	}

	geminiIndex := geminiAuth.EnsureIndex()
	compatIndex := compatAuth.EnsureIndex()
	if geminiIndex == compatIndex {
		t.Fatalf("shared api key produced duplicate auth_index %q", geminiIndex)
	}

	h := &Handler{authManager: manager}

	gotGemini := h.authByIndex(geminiIndex)
	if gotGemini == nil {
		t.Fatal("expected gemini auth by index")
	}
	if gotGemini.ID != geminiAuth.ID {
		t.Fatalf("authByIndex(gemini) returned %q, want %q", gotGemini.ID, geminiAuth.ID)
	}

	gotCompat := h.authByIndex(compatIndex)
	if gotCompat == nil {
		t.Fatal("expected compat auth by index")
	}
	if gotCompat.ID != compatAuth.ID {
		t.Fatalf("authByIndex(compat) returned %q, want %q", gotCompat.ID, compatAuth.ID)
	}
}
