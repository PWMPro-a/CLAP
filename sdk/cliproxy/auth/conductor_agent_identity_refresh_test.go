package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type blockingRefreshExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (e *blockingRefreshExecutor) Identifier() string { return "codex" }

func (e *blockingRefreshExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *blockingRefreshExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *blockingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	close(e.started)
	<-e.release
	return auth, nil
}

func (e *blockingRefreshExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *blockingRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestAgentIdentityMetadataSkipsOAuthAutoRefreshBeforeRuntimeAttachment(t *testing.T) {
	auth := &Auth{
		ID:       "agent-startup",
		Provider: "codex",
		Metadata: map[string]any{
			"auth_mode":                "agentIdentity",
			"agent_runtime_id":         "runtime-id",
			"refresh_interval_seconds": 1,
		},
		LastRefreshedAt: time.Now().Add(-time.Hour),
	}
	manager := NewManager(nil, nil, nil)
	now := time.Now()
	if manager.shouldRefresh(auth, now) {
		t.Fatal("Agent Identity metadata must not enter OAuth refresh before its runtime is attached")
	}
	if _, scheduled := nextRefreshCheckAt(now, auth, time.Minute); scheduled {
		t.Fatal("Agent Identity metadata must not be scheduled for OAuth refresh")
	}
}

func TestRefreshPreservesRuntimeInstalledConcurrently(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	executor := &blockingRefreshExecutor{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "refresh-runtime-race",
		Provider: "codex",
		Metadata: map[string]any{"refresh_token": "refresh-token"},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := manager.refreshAuthForRequest(context.Background(), auth.ID, "")
		done <- err
	}()
	<-executor.started

	runtime := &struct{ name string }{name: "agent-runtime"}
	installed := auth.Clone()
	installed.Runtime = runtime
	if _, err := manager.Update(context.Background(), installed); err != nil {
		t.Fatalf("install runtime: %v", err)
	}
	close(executor.release)
	if err := <-done; err != nil {
		t.Fatalf("refreshAuthForRequest() error = %v", err)
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok {
		t.Fatal("auth missing after refresh")
	}
	if updated.Runtime != runtime {
		t.Fatalf("Runtime = %#v, want concurrently installed runtime", updated.Runtime)
	}
}
