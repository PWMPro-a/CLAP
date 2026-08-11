package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	responseAffinityProvider = "response-affinity"
	responseAffinityModel    = "response-affinity-model"
)

type responseAffinityFallbackSelector struct {
	auth *Auth
}

func (s responseAffinityFallbackSelector) Pick(_ context.Context, _ string, _ string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if pinnedID := pinnedAuthIDFromMetadata(opts.Metadata); pinnedID != "" {
		for _, auth := range auths {
			if auth != nil && auth.ID == pinnedID {
				return auth, nil
			}
		}
	}
	return s.auth, nil
}

type responseAffinityExecutor struct{}

func (*responseAffinityExecutor) Identifier() string { return responseAffinityProvider }

func (*responseAffinityExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte(fmt.Sprintf(`{"id":"resp_execute","auth_id":%q}`, auth.ID))}, nil
}

func (*responseAffinityExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(fmt.Sprintf("data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_stream\",\"auth_id\":%q}}\n\n", auth.ID))}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (*responseAffinityExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (*responseAffinityExecutor) CountTokens(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte(fmt.Sprintf(`{"id":"resp_count","auth_id":%q}`, auth.ID))}, nil
}

func (*responseAffinityExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

type responseAffinityHomeDispatcher struct {
	auth Auth
}

func (responseAffinityHomeDispatcher) HeartbeatOK() bool { return true }

func (d responseAffinityHomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	return json.Marshal(homeAuthDispatchResponse{Auth: d.auth})
}

func (responseAffinityHomeDispatcher) AbortAmbiguousDispatch() {}

func TestExecutionResponsesBindPreviousResponseSessionAffinity(t *testing.T) {
	tests := []struct {
		name       string
		responseID string
		execute    func(*Manager) error
	}{
		{
			name:       "execute",
			responseID: "resp_execute",
			execute: func(manager *Manager) error {
				_, err := manager.Execute(context.Background(), []string{responseAffinityProvider}, cliproxyexecutor.Request{Model: responseAffinityModel}, pinnedResponseAffinityOptions())
				return err
			},
		},
		{
			name:       "count tokens",
			responseID: "resp_count",
			execute: func(manager *Manager) error {
				_, err := manager.ExecuteCount(context.Background(), []string{responseAffinityProvider}, cliproxyexecutor.Request{Model: responseAffinityModel}, pinnedResponseAffinityOptions())
				return err
			},
		},
		{
			name:       "stream",
			responseID: "resp_stream",
			execute: func(manager *Manager) error {
				result, err := manager.ExecuteStream(context.Background(), []string{responseAffinityProvider}, cliproxyexecutor.Request{Model: responseAffinityModel}, pinnedResponseAffinityOptions())
				if err != nil {
					return err
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						return chunk.Err
					}
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := &Auth{ID: "affinity-primary", Provider: responseAffinityProvider, Status: StatusActive}
			fallback := &Auth{ID: "affinity-fallback", Provider: responseAffinityProvider, Status: StatusActive}
			manager, selector := newResponseAffinityManager(t, primary, fallback)

			if err := tt.execute(manager); err != nil {
				t.Fatalf("execute response: %v", err)
			}
			assertResponseAffinityBound(t, selector, tt.responseID, primary, fallback)
		})
	}
}

func TestHomeExecutionResponsePreservesResponseSessionAffinityBinding(t *testing.T) {
	primary := &Auth{ID: "home-affinity-primary", Provider: responseAffinityProvider, Status: StatusActive}
	fallback := &Auth{ID: "home-affinity-fallback", Provider: responseAffinityProvider, Status: StatusActive}
	manager, selector := newResponseAffinityManager(t, nil, fallback)
	manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	manager.PublishHomeDispatch(responseAffinityHomeDispatcher{auth: *primary}, executionregistry.New(), 1)

	if _, err := manager.Execute(context.Background(), []string{responseAffinityProvider}, cliproxyexecutor.Request{Model: responseAffinityModel}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("execute Home response: %v", err)
	}
	assertResponseAffinityBound(t, selector, "resp_execute", primary, fallback)
}

func newResponseAffinityManager(t *testing.T, primary, fallback *Auth) (*Manager, *SessionAffinitySelector) {
	t.Helper()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: responseAffinityFallbackSelector{auth: fallback},
		TTL:      time.Hour,
	})
	t.Cleanup(selector.Stop)

	manager := NewManager(nil, selector, nil)
	manager.RegisterExecutor(&responseAffinityExecutor{})
	modelRegistry := registry.GetGlobalRegistry()
	registerModel := func(auth *Auth) {
		if auth == nil {
			return
		}
		modelRegistry.RegisterClient(auth.ID, responseAffinityProvider, []*registry.ModelInfo{{ID: responseAffinityModel}})
		t.Cleanup(func() { modelRegistry.UnregisterClient(auth.ID) })
	}
	registerModel(primary)
	registerModel(fallback)
	if primary != nil {
		if _, err := manager.Register(WithSkipPersist(context.Background()), primary); err != nil {
			t.Fatalf("register primary auth: %v", err)
		}
	}
	if fallback != nil {
		if _, err := manager.Register(WithSkipPersist(context.Background()), fallback); err != nil {
			t.Fatalf("register fallback auth: %v", err)
		}
	}
	return manager, selector
}

func pinnedResponseAffinityOptions() cliproxyexecutor.Options {
	return cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.PinnedAuthMetadataKey: "affinity-primary",
	}}
}

func assertResponseAffinityBound(t *testing.T, selector *SessionAffinitySelector, responseID string, primary, fallback *Auth) {
	t.Helper()
	selected, err := selector.Pick(context.Background(), responseAffinityProvider, responseAffinityModel, cliproxyexecutor.Options{
		OriginalRequest: []byte(fmt.Sprintf(`{"previous_response_id":%q}`, responseID)),
	}, []*Auth{primary, fallback})
	if err != nil {
		t.Fatalf("pick previous response affinity: %v", err)
	}
	if selected == nil || selected.ID != primary.ID {
		t.Fatalf("selected auth = %#v, want %q", selected, primary.ID)
	}
}
