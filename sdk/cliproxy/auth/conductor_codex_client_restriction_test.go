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
	selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{Headers: headers, OriginalHeaders: headers.Clone()})
	if errSelect != nil || selected == nil || selected.ID != "app-server" {
		t.Fatalf("SelectAuth() = %#v, %v", selected, errSelect)
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
