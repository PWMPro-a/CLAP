package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type runtimeLimitTestExecutor struct {
	mu        sync.Mutex
	calls     []string
	callCount map[string]int

	blockAuth string
	started   chan struct{}
	release   chan struct{}

	firstErrors map[string]error
}

func (e *runtimeLimitTestExecutor) Identifier() string { return "codex" }

func (e *runtimeLimitTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	_ = req
	_ = opts
	e.mu.Lock()
	if e.callCount == nil {
		e.callCount = make(map[string]int)
	}
	e.callCount[auth.ID]++
	callNumber := e.callCount[auth.ID]
	e.calls = append(e.calls, auth.ID)
	block := auth.ID == e.blockAuth && callNumber == 1 && e.release != nil
	if block && e.started != nil {
		close(e.started)
		e.started = nil
	}
	errFirst := e.firstErrors[auth.ID]
	e.mu.Unlock()

	if block {
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case <-e.release:
		}
	}
	if errFirst != nil && callNumber == 1 {
		return cliproxyexecutor.Response{}, errFirst
	}
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}

func (e *runtimeLimitTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "stream not implemented"}
}

func (e *runtimeLimitTestExecutor) Refresh(context.Context, *Auth) (*Auth, error) { return nil, nil }

func (e *runtimeLimitTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (e *runtimeLimitTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "http request not implemented"}
}

func newRuntimeLimitManager(t *testing.T, executor *runtimeLimitTestExecutor, auths ...*Auth) *Manager {
	t.Helper()
	mgr := NewManager(nil, nil, nil)
	mgr.RegisterExecutor(executor)
	for _, auth := range auths {
		if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}
	return mgr
}

func TestRuntimeLimits_MaxConcurrencySkipsBusyAuth(t *testing.T) {
	executor := &runtimeLimitTestExecutor{
		blockAuth: "auth-a",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	mgr := newRuntimeLimitManager(t, executor,
		&Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}},
		&Auth{ID: "auth-b", Provider: "codex", Status: StatusActive},
	)

	firstDone := make(chan cliproxyexecutor.Response, 1)
	go func() {
		resp, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
		if err != nil {
			t.Errorf("first execute: %v", err)
		}
		firstDone <- resp
	}()

	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("first request did not start on auth-a")
	}

	second, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if string(second.Payload) != "auth-b" {
		t.Fatalf("second payload = %q, want auth-b", string(second.Payload))
	}

	close(executor.release)
	select {
	case first := <-firstDone:
		if string(first.Payload) != "auth-a" {
			t.Fatalf("first payload = %q, want auth-a", string(first.Payload))
		}
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
}

func TestRuntimeLimits_RateLimitSkipsHotAuth(t *testing.T) {
	executor := &runtimeLimitTestExecutor{}
	mgr := newRuntimeLimitManager(t, executor,
		&Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
			"rate_limit_max_requests":   1,
			"rate_limit_window_seconds": 60,
		}},
		&Auth{ID: "auth-b", Provider: "codex", Status: StatusActive},
	)

	first, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if string(first.Payload) != "auth-a" {
		t.Fatalf("first payload = %q, want auth-a", string(first.Payload))
	}

	second, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if string(second.Payload) != "auth-b" {
		t.Fatalf("second payload = %q, want auth-b", string(second.Payload))
	}
}

func TestRuntimeLimits_RuntimeFreezeSkipsFailedAuth(t *testing.T) {
	executor := &runtimeLimitTestExecutor{
		firstErrors: map[string]error{
			"auth-a": &Error{HTTPStatus: http.StatusBadRequest, Message: "model not supported"},
		},
	}
	mgr := newRuntimeLimitManager(t, executor,
		&Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
			"selection_error_freeze_seconds": 60,
		}},
		&Auth{ID: "auth-b", Provider: "codex", Status: StatusActive},
	)

	resp, err := mgr.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if string(resp.Payload) != "auth-b" {
		t.Fatalf("payload = %q, want auth-b", string(resp.Payload))
	}

	authA, ok := mgr.GetByID("auth-a")
	if !ok {
		t.Fatal("auth-a missing")
	}
	snapshot := authA.RuntimeLimitSnapshot(time.Now())
	if snapshot.FrozenUntil.IsZero() {
		t.Fatal("auth-a was not runtime frozen")
	}
}

func TestRuntimeLimits_StreamReleaseOnContextCancel(t *testing.T) {
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}}
	release, acquired, reason, _ := auth.acquireRuntimeSlot(time.Now())
	if !acquired {
		t.Fatalf("runtime slot was not acquired: %s", reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	chunks := make(chan cliproxyexecutor.StreamChunk)
	wrapped := wrapStreamResultWithRuntimeRelease(ctx, &cliproxyexecutor.StreamResult{Chunks: chunks}, release)
	if wrapped == nil || wrapped.Chunks == nil {
		t.Fatal("wrapped stream is nil")
	}

	cancel()
	deadline := time.After(time.Second)
	for {
		if auth.RuntimeLimitSnapshot(time.Now()).CurrentConcurrency == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("runtime slot was not released after context cancellation")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type runtimeLimitStaticSelector struct {
	auth *Auth
}

func (s runtimeLimitStaticSelector) Pick(context.Context, string, string, cliproxyexecutor.Options, []*Auth) (*Auth, error) {
	return s.auth, nil
}

func TestRuntimeLimits_StickyBypassOnlyInvalidatesCurrentSession(t *testing.T) {
	now := time.Now()
	authA := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"disable_sticky_on_next_request": true,
	}}
	authB := &Auth{ID: "auth-b", Provider: "codex", Status: StatusActive}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: runtimeLimitStaticSelector{auth: authB},
		TTL:      time.Hour,
	})

	keyOne := sessionAffinityCacheKey("codex", "header:session-1", "gpt-5")
	keyTwo := sessionAffinityCacheKey("codex", "header:session-2", "gpt-5")
	selector.cache.Set(keyOne, authA.ID)
	selector.cache.Set(keyTwo, authA.ID)
	authA.markStickyBypassForSession(keyOne, now)

	picked, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{
		Headers: runtimeLimitSessionHeaders("session-1"),
	}, []*Auth{authA, authB})
	if err != nil {
		t.Fatalf("pick session-1: %v", err)
	}
	if picked == nil || picked.ID != authB.ID {
		t.Fatalf("session-1 picked %v, want auth-b", picked)
	}

	picked, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{
		Headers: runtimeLimitSessionHeaders("session-2"),
	}, []*Auth{authA, authB})
	if err != nil {
		t.Fatalf("pick session-2: %v", err)
	}
	if picked == nil || picked.ID != authA.ID {
		t.Fatalf("session-2 picked %v, want auth-a", picked)
	}
}

func runtimeLimitSessionHeaders(sessionID string) http.Header {
	headers := make(http.Header)
	headers.Set("X-Session-ID", sessionID)
	return headers
}

func TestSessionAffinityPreviousResponseIDUsesBoundAuth(t *testing.T) {
	authA := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	authB := &Auth{ID: "auth-b", Provider: "codex", Status: StatusActive}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: runtimeLimitStaticSelector{auth: authB},
		TTL:      time.Hour,
	})
	selector.BindAuthSession("codex", "gpt-5", "response:resp_previous", authA.ID)

	picked, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{
		OriginalRequest: []byte(`{"model":"gpt-5","previous_response_id":"resp_previous","input":"next"}`),
	}, []*Auth{authA, authB})
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if picked == nil || picked.ID != authA.ID {
		t.Fatalf("picked %v, want auth-a", picked)
	}
}

func TestSessionAffinityCodexWindowMetadataIsStable(t *testing.T) {
	left := []byte(`{"model":"gpt-5","client_metadata":{"x-codex-window-id":"window-1"},"input":"hello"}`)
	right := []byte(`{"model":"gpt-5","client_metadata":{"x-codex-window-id":"window-1"},"input":"different"}`)

	leftID, _ := extractSessionIDs(nil, left, nil)
	rightID, _ := extractSessionIDs(nil, right, nil)
	if leftID != "window:window-1" || rightID != leftID {
		t.Fatalf("session ids = %q/%q, want stable window id", leftID, rightID)
	}
}

func TestResponseSessionAffinityIDsExtractResponsesPayloads(t *testing.T) {
	ids := responseSessionAffinityIDs([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream\"}}\n\n"))
	if len(ids) != 1 || ids[0] != "resp_stream" {
		t.Fatalf("stream ids = %#v, want resp_stream", ids)
	}
	ids = responseSessionAffinityIDs([]byte(`{"id":"resp_json","object":"response"}`))
	if len(ids) != 1 || ids[0] != "resp_json" {
		t.Fatalf("json ids = %#v, want resp_json", ids)
	}
}
