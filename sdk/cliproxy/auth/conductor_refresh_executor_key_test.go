package auth

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type countingRefreshExecutor struct {
	id           string
	refreshCalls atomic.Int32
}

func TestEnsureFreshAuthTokenRefreshesExpiredCredential(t *testing.T) {
	executor := &countingRefreshExecutor{id: "codex"}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "expired-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "stale-token",
			"refresh_token": "refresh-token",
			"expires_at":    time.Now().Add(-time.Minute).Unix(),
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	refreshed, err := manager.EnsureFreshAuthToken(context.Background(), auth.ID, 2*time.Minute)
	if err != nil {
		t.Fatalf("EnsureFreshAuthToken() error = %v", err)
	}
	if refreshed == nil || executor.refreshCalls.Load() != 1 {
		t.Fatalf("refreshed=%#v calls=%d, want one refresh", refreshed, executor.refreshCalls.Load())
	}
}

func TestEnsureFreshAuthTokenKeepsValidCredential(t *testing.T) {
	executor := &countingRefreshExecutor{id: "codex"}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "valid-auth",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "valid-token",
			"refresh_token": "refresh-token",
			"expires_at":    time.Now().Add(time.Hour).Unix(),
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	current, err := manager.EnsureFreshAuthToken(context.Background(), auth.ID, 2*time.Minute)
	if err != nil {
		t.Fatalf("EnsureFreshAuthToken() error = %v", err)
	}
	if current == nil || executor.refreshCalls.Load() != 0 {
		t.Fatalf("current=%#v calls=%d, want no refresh", current, executor.refreshCalls.Load())
	}
}

func (e *countingRefreshExecutor) Identifier() string { return e.id }

func (e *countingRefreshExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *countingRefreshExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *countingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.refreshCalls.Add(1)
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "refreshed-token"
	return auth, nil
}

func (e *countingRefreshExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *countingRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestRefreshAuthForRequest_UsesExecutorKeyFromAuth(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &countingRefreshExecutor{id: "openai-compatible-custom"}
	manager.RegisterExecutor(executor)

	auth := &Auth{
		ID:       "compat-oauth",
		Provider: "plugin-provider",
		Attributes: map[string]string{
			"compat_name":  "custom",
			"provider_key": "custom",
			"base_url":     "https://compat.example.com/v1",
		},
		Metadata: map[string]any{
			"access_token":  "old-token",
			"refresh_token": "refresh-1",
		},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	refreshed, errRefresh := manager.refreshAuthForRequest(ctx, auth.ID, "old-token")
	if errRefresh != nil {
		t.Fatalf("refreshAuthForRequest() error = %v", errRefresh)
	}
	if executor.refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", executor.refreshCalls.Load())
	}
	if refreshed == nil || refreshed.Metadata["access_token"] != "refreshed-token" {
		t.Fatalf("refreshed auth = %#v, want updated access_token", refreshed)
	}
}
