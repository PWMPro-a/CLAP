package executor

import (
	"bytes"
	"context"
	"errors"
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
			responseID := fmt.Sprintf("resp-%d", i+1)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`, responseID)))
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

func TestCodexWebsocketsStatelessPoolDropsCompletedResponseFrames(t *testing.T) {
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

		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-stale-1"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-stale-1"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-stale-1","delta":"first"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-stale-1","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))

		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-stale-1","delta":"STALE_SHOULD_NOT_LEAK"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"id":"resp-stale-1","output":[]}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-fresh-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-fresh-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-fresh-2","delta":"fresh-second"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-fresh-2","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	exec.store = store
	auth := &cliproxyauth.Auth{
		ID: "auth-pool-stale-test",
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

	firstResult, errExecute := exec.ExecuteStream(nil, auth, req, opts)
	if errExecute != nil {
		t.Fatalf("first ExecuteStream() error = %v", errExecute)
	}
	drainCodexWebsocketTestStream(t, firstResult)

	secondResult, errExecute := exec.ExecuteStream(nil, auth, req, opts)
	if errExecute != nil {
		t.Fatalf("second ExecuteStream() error = %v", errExecute)
	}
	secondBody := drainCodexWebsocketTestStream(t, secondResult)
	if strings.Contains(secondBody, "STALE_SHOULD_NOT_LEAK") || strings.Contains(secondBody, "resp-stale-1") {
		t.Fatalf("second stream leaked completed response frames: %s", secondBody)
	}
	if !strings.Contains(secondBody, "fresh-second") {
		t.Fatalf("second stream missing fresh response event: %s", secondBody)
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("upstream handshakes = %d, want 1 to preserve pooled first-token latency", got)
	}
}

func TestCodexWebsocketsExecutionSessionDropsCompletedResponseFrames(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade websocket: %v", errUpgrade)
			return
		}
		defer conn.Close()

		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-session-stale-1"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-session-stale-1"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-session-stale-1","delta":"first"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-session-stale-1","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))

		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-session-stale-1","delta":"STALE_SESSION_SHOULD_NOT_LEAK"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.done","response":{"id":"resp-session-stale-1","output":[]}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-session-fresh-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-session-fresh-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-session-fresh-2","delta":"fresh-session-second"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-session-fresh-2","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	exec.store = store
	defer exec.closeAllExecutionSessions("test_cleanup")
	auth := &cliproxyauth.Auth{
		ID: "auth-execution-session-stale-test",
		Attributes: map[string]string{
			"api_key":  "sk-test",
			"base_url": server.URL,
		},
	}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[{"type":"message","role":"user","content":"hello"}]}`),
	}
	lifecycle := &countingWebsocketLifecycle{}
	opts := cliproxyexecutor.Options{
		SourceFormat:       sdktranslator.FromString("openai-response"),
		ResponseFormat:     sdktranslator.FromString("openai-response"),
		ExecutionLifecycle: lifecycle,
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionSessionMetadataKey: "named-stale-session",
		},
	}

	firstResult, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
	if errExecute != nil {
		t.Fatalf("first ExecuteStream() error = %v", errExecute)
	}
	drainCodexWebsocketTestStream(t, firstResult)

	secondResult, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
	if errExecute != nil {
		t.Fatalf("second ExecuteStream() error = %v", errExecute)
	}
	secondBody := drainCodexWebsocketTestStream(t, secondResult)
	if strings.Contains(secondBody, "STALE_SESSION_SHOULD_NOT_LEAK") || strings.Contains(secondBody, "resp-session-stale-1") {
		t.Fatalf("second execution-session stream leaked completed response frames: %s", secondBody)
	}
	if !strings.Contains(secondBody, "fresh-session-second") || !strings.Contains(secondBody, "resp-session-fresh-2") {
		t.Fatalf("second execution-session stream missing fresh response events: %s", secondBody)
	}
}

func TestCodexWebsocketsStatelessPoolReconnectsAfterCanceledResponse(t *testing.T) {
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
		if connectionID == 1 {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-canceled-1"}}`))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-canceled-1"}}`))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-canceled-1","delta":"cancel-me"}`))
			for {
				if _, _, errRead := conn.ReadMessage(); errRead != nil {
					return
				}
			}
		}
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-after-cancel-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.added","item":{"id":"item-after-cancel-2"}}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","item_id":"item-after-cancel-2","delta":"fresh-after-cancel"}`))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-after-cancel-2","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	exec.store = store
	auth := &cliproxyauth.Auth{
		ID: "auth-pool-cancel-test",
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

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult, errExecute := exec.ExecuteStream(firstCtx, auth, req, opts)
	if errExecute != nil {
		t.Fatalf("first ExecuteStream() error = %v", errExecute)
	}
	gotFirstPayload := false
	for chunk := range firstResult.Chunks {
		if chunk.Err != nil && !errors.Is(chunk.Err, context.Canceled) {
			t.Fatalf("first stream error chunk = %v", chunk.Err)
		}
		if len(chunk.Payload) > 0 && !gotFirstPayload {
			gotFirstPayload = true
			cancelFirst()
		}
	}
	cancelFirst()
	if !gotFirstPayload {
		t.Fatal("first stream produced no payload before cancellation")
	}

	secondResult, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
	if errExecute != nil {
		t.Fatalf("second ExecuteStream() error = %v", errExecute)
	}
	secondBody := drainCodexWebsocketTestStream(t, secondResult)
	if !strings.Contains(secondBody, "fresh-after-cancel") || strings.Contains(secondBody, "cancel-me") {
		t.Fatalf("second stream was not isolated after cancellation: %s", secondBody)
	}
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("upstream handshakes = %d, want 2 after discarding the incomplete connection", got)
	}
}

func TestCodexWebsocketsExecutionSessionUsesParallelConnectionInsteadOfQueueing(t *testing.T) {
	var handshakes atomic.Int32
	firstRequestReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	parallelRequestsReceived := make(chan int32, codexWebsocketStandbySlots)
	releaseParallel := make(chan struct{})
	releaseFirstRequest := func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}
	defer releaseFirstRequest()
	releaseParallelRequests := func() {
		select {
		case <-releaseParallel:
		default:
			close(releaseParallel)
		}
	}
	defer releaseParallelRequests()
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
		if connectionID == 1 {
			close(firstRequestReceived)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp-parallel-1"}}`))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_text.delta","response_id":"resp-parallel-1","delta":"first"}`))
			<-releaseFirst
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp-parallel-1","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`))
			return
		}
		responseID := fmt.Sprintf("resp-parallel-%d", connectionID)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, responseID)))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.output_text.delta","response_id":%q,"delta":%q}`, responseID, fmt.Sprintf("parallel-slot-%d", connectionID))))
		parallelRequestsReceived <- connectionID
		<-releaseParallel
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`, responseID)))
	}))
	defer server.Close()

	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	exec.store = store
	auth := &cliproxyauth.Auth{
		ID: "auth-parallel-session-test",
		Attributes: map[string]string{
			"api_key":  "sk-test",
			"base_url": server.URL,
		},
	}
	auth.EnsureIndex()
	req := cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":[{"type":"message","role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FromString("openai-response"),
		ResponseFormat: sdktranslator.FromString("openai-response"),
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionSessionMetadataKey: "shared-parallel-session",
		},
	}
	parallelPoolKey := codexStatelessWebsocketPoolKey(auth, exec.cfg, auth.ID, "ws"+strings.TrimPrefix(server.URL, "http")+"/responses")
	defer func() {
		store.mu.Lock()
		standbys := append([]*codexWebsocketSession(nil), store.stateless[parallelPoolKey]...)
		delete(store.stateless, parallelPoolKey)
		store.mu.Unlock()
		for _, standby := range standbys {
			closeCodexWebsocketSession(standby, "test_cleanup")
		}
	}()

	firstResult, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
	if errExecute != nil {
		t.Fatalf("first ExecuteStream() error = %v", errExecute)
	}
	firstDone := make(chan string, 1)
	go func() {
		var body bytes.Buffer
		for chunk := range firstResult.Chunks {
			if chunk.Err != nil {
				body.WriteString("stream error: " + chunk.Err.Error())
				break
			}
			body.Write(chunk.Payload)
		}
		firstDone <- body.String()
	}()

	select {
	case <-firstRequestReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach upstream")
	}

	standbyDeadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		standbys := append([]*codexWebsocketSession(nil), store.stateless[parallelPoolKey]...)
		store.mu.Unlock()
		ready := 0
		for _, standby := range standbys {
			if standby == nil || !standby.reqMu.TryLock() {
				continue
			}
			standby.connMu.Lock()
			connected := standby.conn != nil
			standby.connMu.Unlock()
			standby.reqMu.Unlock()
			if connected {
				ready++
			}
		}
		if ready >= codexWebsocketStandbySlots {
			break
		}
		if time.Now().After(standbyDeadline) {
			t.Fatalf("ready standby websocket slots = %d, want %d", ready, codexWebsocketStandbySlots)
		}
		time.Sleep(5 * time.Millisecond)
	}
	readyHandshakeCount := handshakes.Load()
	if want := int32(1 + codexWebsocketStandbySlots); readyHandshakeCount != want {
		t.Fatalf("handshakes after prewarm = %d, want %d", readyHandshakeCount, want)
	}

	type streamOutcome struct {
		body string
		err  error
	}
	parallelDone := make(chan streamOutcome, codexWebsocketStandbySlots)
	firstByteLatencies := make(chan time.Duration, codexWebsocketStandbySlots)
	for i := 0; i < codexWebsocketStandbySlots; i++ {
		parallelAuth := auth.Clone()
		go func(requestAuth *cliproxyauth.Auth) {
			startedAt := time.Now()
			parallelResult, errParallel := exec.ExecuteStream(context.Background(), requestAuth, req, opts)
			if errParallel != nil {
				parallelDone <- streamOutcome{err: errParallel}
				return
			}
			var body bytes.Buffer
			firstByteSeen := false
			for chunk := range parallelResult.Chunks {
				if chunk.Err != nil {
					parallelDone <- streamOutcome{err: chunk.Err}
					return
				}
				if len(chunk.Payload) > 0 && !firstByteSeen {
					firstByteSeen = true
					firstByteLatencies <- time.Since(startedAt)
				}
				body.Write(chunk.Payload)
			}
			parallelDone <- streamOutcome{body: body.String()}
		}(parallelAuth)
	}

	for i := 0; i < codexWebsocketStandbySlots; i++ {
		select {
		case <-parallelRequestsReceived:
		case <-time.After(2 * time.Second):
			t.Fatalf("parallel request %d queued behind an active slot", i+1)
		}
	}

	if got := handshakes.Load(); got != readyHandshakeCount {
		t.Fatalf("parallel requests opened cold websockets: handshakes = %d, prewarmed = %d", got, readyHandshakeCount)
	}
	maxFirstByteLatency := time.Duration(0)
	for i := 0; i < codexWebsocketStandbySlots; i++ {
		select {
		case latency := <-firstByteLatencies:
			if latency > maxFirstByteLatency {
				maxFirstByteLatency = latency
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("parallel SSE request %d produced no first byte", i+1)
		}
	}
	t.Logf("parallel SSE hot-slot max first-byte latency: %s", maxFirstByteLatency)
	releaseParallelRequests()
	seenParallelBodies := make(map[string]struct{}, codexWebsocketStandbySlots)
	for i := 0; i < codexWebsocketStandbySlots; i++ {
		select {
		case parallel := <-parallelDone:
			if parallel.err != nil {
				t.Fatalf("parallel ExecuteStream() error = %v", parallel.err)
			}
			if !strings.Contains(parallel.body, "parallel-slot-") || strings.Contains(parallel.body, "resp-parallel-1") {
				t.Fatalf("parallel stream was not isolated: %s", parallel.body)
			}
			seenParallelBodies[parallel.body] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("parallel request %d did not finish", i+1)
		}
	}
	if len(seenParallelBodies) != codexWebsocketStandbySlots {
		t.Fatalf("distinct parallel responses = %d, want %d", len(seenParallelBodies), codexWebsocketStandbySlots)
	}
	releaseFirstRequest()
	select {
	case firstBody := <-firstDone:
		if !strings.Contains(firstBody, "resp-parallel-1") || strings.Contains(firstBody, "resp-parallel-2") {
			t.Fatalf("first stream was not isolated: %s", firstBody)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not finish after release")
	}
}

func drainCodexWebsocketTestStream(t *testing.T, result *cliproxyexecutor.StreamResult) string {
	t.Helper()
	var body bytes.Buffer
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error chunk = %v", chunk.Err)
		}
		body.Write(chunk.Payload)
	}
	return body.String()
}
