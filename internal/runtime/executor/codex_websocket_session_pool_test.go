package executor

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexStatelessWebsocketSessionPoolReusesIdleSlotsAndBoundsBusySlots(t *testing.T) {
	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{store: store}

	first, locked := exec.acquireStatelessSession("auth\x00url\x00proxy")
	if !locked || first == nil {
		t.Fatal("first stateless session was not acquired")
	}
	first.reqMu.Unlock()

	reused, locked := exec.acquireStatelessSession("auth\x00url\x00proxy")
	if !locked || reused != first {
		t.Fatal("idle stateless session was not reused")
	}
	reused.reqMu.Unlock()

	busy := make([]*codexWebsocketSession, 0, codexStatelessWebsocketPoolSlots)
	for i := 0; i < codexStatelessWebsocketPoolSlots; i++ {
		sess, acquired := exec.acquireStatelessSession("auth\x00url\x00proxy")
		if !acquired || sess == nil {
			t.Fatalf("slot %d was not acquired", i)
		}
		busy = append(busy, sess)
	}
	if sess, acquired := exec.acquireStatelessSession("auth\x00url\x00proxy"); acquired || sess != nil {
		t.Fatal("busy stateless pool exceeded its slot limit")
	}
	for _, sess := range busy {
		sess.reqMu.Unlock()
	}
}

func TestCodexWebsocketsExecuteStreamReusesStatelessHTTPSSESession(t *testing.T) {
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer conn.Close()
		handshakes.Add(1)
		for i := 0; i < 2; i++ {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","delta":"hello"}`))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-1","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))
		}
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
	}

	for attempt := 0; attempt < 2; attempt++ {
		result, errExecute := exec.ExecuteStream(nil, auth, req, opts)
		if errExecute != nil {
			t.Fatalf("ExecuteStream() attempt %d error = %v", attempt, errExecute)
		}
		gotChunk := false
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream attempt %d error chunk = %v", attempt, chunk.Err)
			}
			gotChunk = gotChunk || len(chunk.Payload) > 0
		}
		if !gotChunk {
			t.Fatalf("stream attempt %d produced no payload", attempt)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for handshakes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("upstream handshakes = %d, want 1 for two sequential SSE requests", got)
	}
}
