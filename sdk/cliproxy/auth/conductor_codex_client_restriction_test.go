package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func newCodexClientRestrictionManager(t *testing.T, auths ...*Auth) (*Manager, string) {
	t.Helper()
	model := "gpt-5.6"
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		ClientRestriction: internalconfig.CodexClientRestrictionConfig{
			EngineFingerprintSignals: []internalconfig.CodexEngineFingerprintSignal{
				{Type: "header_prefix", Match: []string{"x-codex-"}, Required: true},
			},
		},
	}})
	for _, credential := range auths {
		if _, errRegister := manager.Register(context.Background(), credential); errRegister != nil {
			t.Fatalf("register %s: %v", credential.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(credential.ID, "codex", []*registry.ModelInfo{{ID: model}})
		authID := credential.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
	}
	return manager, model
}

func protectedCodexAuth(id string, appServer bool) *Auth {
	return &Auth{
		ID: id, Provider: "codex", Status: StatusActive,
		Attributes: map[string]string{"auth_kind": "oauth"},
		Metadata: map[string]any{
			"access_token":                    "token-" + id,
			"codex_cli_only":                  true,
			"codex_cli_only_allow_app_server": appServer,
		},
	}
}

func TestCodexClientRestrictionSelectsProtectedAuthForOfficialRequest(t *testing.T) {
	protected := protectedCodexAuth("protected", false)
	manager, model := newCodexClientRestrictionManager(t, protected)
	headers := make(http.Header)
	headers.Set("User-Agent", "codex_cli_rs/0.142.0 (linux)")
	headers.Set("X-Codex-Window-Id", "window")
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(),
	})
	if errSelect != nil || selected == nil || selected.ID != protected.ID {
		t.Fatalf("SelectAuth() = %#v, %v", selected, errSelect)
	}
}

func TestCodexClientRestrictionFallsBackToUnprotectedAuth(t *testing.T) {
	protected := protectedCodexAuth("protected", false)
	unprotected := &Auth{ID: "ordinary", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": "ordinary"}}
	manager, model := newCodexClientRestrictionManager(t, protected, unprotected)
	headers := make(http.Header)
	headers.Set("User-Agent", "curl/8.0")
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{Headers: headers, OriginalHeaders: headers.Clone()})
	if errSelect != nil || selected == nil || selected.ID != unprotected.ID {
		t.Fatalf("SelectAuth() = %#v, %v, want ordinary auth", selected, errSelect)
	}
}

func TestCodexClientRestrictionReturnsForbiddenWhenAllCandidatesProtected(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("protected", false))
	headers := make(http.Header)
	headers.Set("User-Agent", "curl/8.0")
	_, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{Headers: headers, OriginalHeaders: headers.Clone()})
	var authErr *Error
	if !errors.As(errSelect, &authErr) || authErr.Code != "codex_client_restricted" || authErr.HTTPStatus != http.StatusForbidden {
		t.Fatalf("SelectAuth() error = %#v, want 403 codex_client_restricted", errSelect)
	}
}

func TestCodexClientRestrictionAccountAppServerOverride(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("app-server", true))
	headers := make(http.Header)
	headers.Set("User-Agent", "opencode/1.0")
	headers.Set("X-Codex-Window-Id", "window")
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(),
		Metadata: map[string]any{cliproxyexecutor.CodexAppServerMetadataKey: true},
	})
	if errSelect != nil || selected == nil || selected.ID != "app-server" {
		t.Fatalf("SelectAuth() = %#v, %v", selected, errSelect)
	}
}

func TestCodexClientRestrictionRejectsSpoofedAppServerHeaders(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("app-server", true))
	headers := make(http.Header)
	headers.Set("User-Agent", "cpa-app-server/1.0")
	headers.Set("X-Codex-App-Server", "authenticated")
	headers.Set("Session-Id", "copied-session")
	headers.Set("Thread-Id", "copied-thread")
	body := []byte(`{"client_metadata":{"x-codex-installation-id":"copied-installation"}}`)
	_, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(), OriginalRequest: body, OriginalClientRequest: body,
		OriginalClientSnapshotCaptured: true,
	})
	var authErr *Error
	if !errors.As(errSelect, &authErr) || authErr.Code != "codex_client_restricted" {
		t.Fatalf("SelectAuth() error = %#v, want spoofed app-server rejection", errSelect)
	}
}

func TestCodexClientRestrictionGlobalAppServerStillRequiresInternalProof(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("global-app-server", false))
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		ClientRestriction: internalconfig.CodexClientRestrictionConfig{
			AllowAppServerClients: true,
			EngineFingerprintSignals: []internalconfig.CodexEngineFingerprintSignal{
				{Type: "header_prefix", Match: []string{"x-codex-"}, Required: true},
			},
		},
	}})
	headers := http.Header{"User-Agent": {"copied-app-server/1.0"}, "X-Codex-Window-Id": {"copied"}}
	_, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(), OriginalClientSnapshotCaptured: true,
	})
	var authErr *Error
	if !errors.As(errSelect, &authErr) || authErr.Code != "codex_client_restricted" {
		t.Fatalf("SelectAuth() error = %#v, want missing internal proof rejection", errSelect)
	}

	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(), OriginalClientSnapshotCaptured: true,
		Metadata: map[string]any{cliproxyexecutor.CodexAppServerMetadataKey: true},
	})
	if errSelect != nil || selected == nil || selected.ID != "global-app-server" {
		t.Fatalf("trusted SelectAuth() = %#v, %v", selected, errSelect)
	}
}

func TestCodexClientRestrictionTrustedAppServerPassesStrictFourSignals(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("app-server", true))
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		ClientRestriction: internalconfig.CodexClientRestrictionConfig{
			EngineFingerprintSignals: []internalconfig.CodexEngineFingerprintSignal{
				{Type: "header_prefix", Match: []string{"x-codex-"}, Required: true},
				{Type: "header_exact", Match: []string{"session-id", "session_id"}, Required: true},
				{Type: "header_exact", Match: []string{"thread-id", "thread_id"}, Required: true},
				{Type: "body_path", Match: []string{"client_metadata.x-codex-installation-id"}, Required: true},
			},
		},
	}})
	headers := http.Header{"User-Agent": {"ordinary-gateway/1.0"}}
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: headers, OriginalHeaders: headers.Clone(), OriginalClientSnapshotCaptured: true,
		Metadata: map[string]any{cliproxyexecutor.CodexAppServerMetadataKey: true},
	})
	if errSelect != nil || selected == nil || selected.ID != "app-server" {
		t.Fatalf("SelectAuth() = %#v, %v", selected, errSelect)
	}
}

func TestAttachCodexAppServerMetadataCopiesOnlyInternalProof(t *testing.T) {
	req := cliproxyexecutor.Request{Metadata: map[string]any{"request": "kept"}}
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.CodexAppServerMetadataKey: true,
		cliproxyexecutor.CallerScopeMetadataKey:    "caller-a",
		"unrelated":                                "not-copied",
	}}

	got := attachCodexAppServerMetadata(req, opts)
	if trusted, _ := got.Metadata[cliproxyexecutor.CodexAppServerMetadataKey].(bool); !trusted {
		t.Fatal("missing internal proof")
	}
	if got.Metadata[cliproxyexecutor.CallerScopeMetadataKey] != "caller-a" || got.Metadata["request"] != "kept" {
		t.Fatalf("metadata = %#v", got.Metadata)
	}
	if _, exists := got.Metadata["unrelated"]; exists {
		t.Fatalf("unrelated option metadata leaked into request: %#v", got.Metadata)
	}
}

func TestCodexClientRestrictionUsesOriginalSnapshot(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("protected", false))
	original := make(http.Header)
	original.Set("User-Agent", "codex_cli_rs/0.142.0 (linux)")
	original.Set("X-Codex-Window-Id", "window")
	rewritten := make(http.Header)
	rewritten.Set("User-Agent", "curl/8.0")
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers: rewritten, OriginalHeaders: original, OriginalClientSnapshotCaptured: true,
	})
	if errSelect != nil || selected == nil || selected.ID != "protected" {
		t.Fatalf("SelectAuth() = %#v, %v", selected, errSelect)
	}
}

func TestCodexClientRestrictionPreservesCapturedEmptySnapshot(t *testing.T) {
	manager, model := newCodexClientRestrictionManager(t, protectedCodexAuth("protected", false))
	manager.SetConfigSnapshot(&internalconfig.Config{Codex: internalconfig.CodexConfig{
		ClientRestriction: internalconfig.CodexClientRestrictionConfig{
			EngineFingerprintSignals: []internalconfig.CodexEngineFingerprintSignal{
				{Type: "body_path", Match: []string{"client_metadata.x-codex-window-id"}, Required: true},
			},
		},
	}})
	injectedHeaders := http.Header{"User-Agent": {"codex_cli_rs/0.142.0 (linux)"}}
	injectedBody := []byte(`{"client_metadata":{"x-codex-window-id":"injected"}}`)
	_, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{
		Headers:                        injectedHeaders,
		OriginalHeaders:                nil,
		OriginalRequest:                injectedBody,
		OriginalClientRequest:          nil,
		OriginalClientSnapshotCaptured: true,
	})
	var authErr *Error
	if !errors.As(errSelect, &authErr) || authErr.Code != "codex_client_restricted" {
		t.Fatalf("SelectAuth() error = %#v, want captured empty snapshot rejection", errSelect)
	}
}
