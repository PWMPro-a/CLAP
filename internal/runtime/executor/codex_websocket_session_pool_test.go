package executor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexWebsocketsExecuteStreamUsesIsolatedHTTPSSEConnections(t *testing.T) {
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer conn.Close()
		connectionID := handshakes.Add(1)
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.output_text.delta","delta":"connection-%d"}`, connectionID)))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp-%d","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`, connectionID)))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	exec.store = store
	auth := &cliproxyauth.Auth{
		ID: "auth-pool-test",
		Attributes: map[string]string{
			"api_key":  "sk-test",
			"base_url": server.URL,
		},
	}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[{"type":"message","role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FromString("openai-response"),
		ResponseFormat: sdktranslator.FromString("openai-response"),
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionSessionMetadataKey: "shared-untrusted-session-id",
		},
	}

	outputs := make([]string, 0, 2)
	for attempt := 0; attempt < 2; attempt++ {
		result, errExecute := exec.ExecuteStream(nil, auth, req, opts)
		if errExecute != nil {
			t.Fatalf("ExecuteStream() attempt %d error = %v", attempt, errExecute)
		}
		var output strings.Builder
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream attempt %d error chunk = %v", attempt, chunk.Err)
			}
			output.Write(chunk.Payload)
		}
		if output.Len() == 0 {
			t.Fatalf("stream attempt %d produced no payload", attempt)
		}
		outputs = append(outputs, output.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for handshakes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("upstream handshakes = %d, want 2 for two isolated SSE requests", got)
	}
	if !strings.Contains(outputs[0], "connection-1") {
		t.Fatalf("first SSE response did not contain its connection payload: %s", outputs[0])
	}
	if !strings.Contains(outputs[1], "connection-2") || strings.Contains(outputs[1], "connection-1") {
		t.Fatalf("second SSE response was not isolated from the first connection: %s", outputs[1])
	}
}
