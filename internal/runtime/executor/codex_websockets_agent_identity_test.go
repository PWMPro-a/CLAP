package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type codexWebsocketAgentIdentityRuntime struct {
	recoveryCalls atomic.Int32
}

func (*codexWebsocketAgentIdentityRuntime) Authorization(context.Context, *http.Client) (string, string, error) {
	return "AgentAssertion stale", "task-stale", nil
}

func (r *codexWebsocketAgentIdentityRuntime) RecoverAuthorization(context.Context, *http.Client, string) (string, error) {
	r.recoveryCalls.Add(1)
	return "AgentAssertion fresh", nil
}

func (*codexWebsocketAgentIdentityRuntime) MarkRuntimeDeleted() {}

func (*codexWebsocketAgentIdentityRuntime) RedactSensitiveBody(body []byte) []byte { return body }

func TestApplyCodexWebsocketHeadersPreservesCompleteAuthorization(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		want          string
	}{
		{name: "OAuth bearer", authorization: "Bearer oauth-token", want: "Bearer oauth-token"},
		{name: "agent identity", authorization: "AgentAssertion signed-assertion", want: "AgentAssertion signed-assertion"},
		{name: "legacy bare token", authorization: "legacy-token", want: "Bearer legacy-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := applyCodexWebsocketHeaders(context.Background(), nil, &cliproxyauth.Auth{}, tt.authorization, nil)
			if got := headers.Get("Authorization"); got != tt.want {
				t.Fatalf("Authorization = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCodexWebsocketHandshakeRecoversRejectedAgentIdentityTask(t *testing.T) {
	var acceptedFresh atomic.Bool
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "AgentAssertion stale":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"task_expired"}}`))
		case "AgentAssertion fresh":
			acceptedFresh.Store(true)
			conn, errUpgrade := upgrader.Upgrade(w, r, nil)
			if errUpgrade == nil {
				defer func() { _ = conn.Close() }()
				<-r.Context().Done()
			}
		default:
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	runtime := &codexWebsocketAgentIdentityRuntime{}
	auth := &cliproxyauth.Auth{ID: "agent-auth", Runtime: runtime}
	headers := make(http.Header)
	headers.Set("Authorization", "AgentAssertion stale")
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	exec := NewCodexWebsocketsExecutor(nil)

	conn, closer, resp, errDial := exec.ensureUpstreamConnWithAgentRecovery(
		context.Background(), auth, nil, auth.ID, wsURL, headers, server.Client(), "task-stale",
	)
	if errDial != nil {
		t.Fatalf("ensureUpstreamConnWithAgentRecovery() error = %v", errDial)
	}
	if conn == nil || closer == nil {
		t.Fatal("recovered websocket connection is nil")
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if errClose := closer.Close(); errClose != nil {
		t.Fatalf("close recovered websocket: %v", errClose)
	}
	if runtime.recoveryCalls.Load() != 1 || !acceptedFresh.Load() {
		t.Fatalf("recovery calls = %d, accepted fresh = %v", runtime.recoveryCalls.Load(), acceptedFresh.Load())
	}
	if got := headers.Get("Authorization"); got != "AgentAssertion fresh" {
		t.Fatalf("Authorization = %q, want recovered assertion", got)
	}
}
