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
	mu          sync.Mutex
	startedOnce sync.Once
	calls       []string
	callCount   map[string]int

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
		e.startedOnce.Do(func() { close(e.started) })
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

func TestRuntimeLimits_PersistentQuotaFreezeReasonSurvivesBlockedChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		freezeAuth func(*Auth, time.Time)
		wantReason string
	}{
		{
			name: "usage limit reached",
			freezeAuth: func(auth *Auth, now time.Time) {
				retryAfter := time.Hour
				auth.freezeUsageLimit(now, &retryAfter)
			},
			wantReason: runtimeSkipReasonUsageLimitReached,
		},
		{
			name: "quota preempt",
			freezeAuth: func(auth *Auth, now time.Time) {
				auth.updateQuotaPreempt(now, now.Add(time.Hour), true)
			},
			wantReason: runtimeSkipReasonQuotaPreempt,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
			test.freezeAuth(auth, now)

			blocked, _, _ := runtimeAuthBlockedForModel(auth, now.Add(time.Second))
			if !blocked {
				t.Fatal("runtime freeze did not block auth")
			}
			if _, acquired, _, _ := auth.acquireRuntimeSlot(now.Add(2 * time.Second)); acquired {
				t.Fatal("runtime slot acquired while auth was frozen")
			}
			if got := auth.RuntimeLimitSnapshot(now.Add(3 * time.Second)).LastSkipReason; got != test.wantReason {
				t.Fatalf("last skip reason = %q, want %q", got, test.wantReason)
			}
		})
	}
}

func TestRuntimeLimits_UpstreamRateLimitBlocksEveryModelAndQuotaFallback(t *testing.T) {
	now := time.Now()
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	auth.updateQuotaPreempt(now, now.Add(time.Hour), true)
	retryAfter := 40 * time.Second
	if !auth.freezeUpstreamRateLimit(now, &retryAfter) {
		t.Fatal("first upstream rate limit did not open a cooldown window")
	}

	for _, model := range []string{"gpt-a", "gpt-b"} {
		blocked, reason, retryAt := runtimeAuthBlockedForModelWithTailBurst(auth, model, now.Add(time.Second), false)
		if !blocked || reason != blockReasonCooldown || retryAt.Before(now.Add(39*time.Second)) {
			t.Fatalf("model %s block = (%t, %v, %v), want account-wide rate-limit cooldown", model, blocked, reason, retryAt)
		}
	}

	fallback := auth.Clone()
	fallback.quotaPreemptFallback = true
	if quotaOnly, hasCapacity := runtimeQuotaPreemptFallbackState(fallback, now.Add(time.Second)); quotaOnly || hasCapacity {
		t.Fatalf("quota fallback crossed upstream rate-limit cooldown: quotaOnly=%t hasCapacity=%t", quotaOnly, hasCapacity)
	}

	snapshot := auth.RuntimeLimitSnapshot(now.Add(time.Second))
	if snapshot.RateLimitedUntil.Before(now.Add(39 * time.Second)) {
		t.Fatalf("runtime snapshot = %#v, want upstream rate-limit deadline", snapshot)
	}
	if quotaOnly, hasCapacity := runtimeQuotaPreemptFallbackState(fallback, now.Add(41*time.Second)); !quotaOnly || !hasCapacity {
		t.Fatalf("quota fallback did not recover after Retry-After: quotaOnly=%t hasCapacity=%t", quotaOnly, hasCapacity)
	}
}

func TestRuntimeLimits_UpstreamRateLimitBackoffDeduplicatesBurstAndRequiresStableRecovery(t *testing.T) {
	now := time.Now()
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	retryAfter := 5 * time.Second
	if !auth.freezeUpstreamRateLimit(now, &retryAfter) {
		t.Fatal("first upstream rate limit did not open a cooldown window")
	}
	first := auth.RuntimeLimitSnapshot(now).RateLimitedUntil
	if auth.freezeUpstreamRateLimit(now.Add(time.Second), &retryAfter) {
		t.Fatal("same-window rate-limit burst advanced cooldown")
	}
	if got := auth.RuntimeLimitSnapshot(now.Add(time.Second)).RateLimitedUntil; !got.Equal(first) {
		t.Fatalf("same-window deadline = %v, want %v", got, first)
	}

	state := auth.ensureRuntimeLimits()
	state.mu.Lock()
	state.upstreamRateLimitedUntil = now.Add(-time.Second)
	state.mu.Unlock()
	if !auth.freezeUpstreamRateLimit(now.Add(20*time.Second), &retryAfter) {
		t.Fatal("second rate limit did not open a new cooldown window")
	}
	second := auth.RuntimeLimitSnapshot(now.Add(20 * time.Second)).RateLimitedUntil
	if second.Before(now.Add(49 * time.Second)) {
		t.Fatalf("second cooldown deadline = %v, want progressive backoff of at least 30 seconds", second)
	}

	state.mu.Lock()
	state.upstreamRateLimitedUntil = now.Add(-time.Second)
	state.mu.Unlock()
	auth.observeUpstreamRateLimitSuccess(now.Add(time.Minute))
	state.mu.Lock()
	level := state.upstreamRateLimitBackoff
	state.mu.Unlock()
	if level == 0 {
		t.Fatal("short success reset backoff before the account was stable")
	}

	auth.observeUpstreamRateLimitSuccess(now.Add(6 * time.Minute))
	state.mu.Lock()
	level = state.upstreamRateLimitBackoff
	lastSeen := state.upstreamRateLimitLastSeen
	state.mu.Unlock()
	if level != 0 || !lastSeen.IsZero() {
		t.Fatalf("backoff after stable recovery = %d, last seen = %v, want reset", level, lastSeen)
	}
}

func TestRuntimeLimits_UpstreamRateLimitBurstExtendsStableRecoveryWindow(t *testing.T) {
	now := time.Now()
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	retryAfter := 5 * time.Second
	if !auth.freezeUpstreamRateLimit(now, &retryAfter) {
		t.Fatal("first upstream rate limit did not open a cooldown window")
	}
	if auth.freezeUpstreamRateLimit(now.Add(10*time.Second), &retryAfter) {
		t.Fatal("same-window rate-limit burst advanced cooldown")
	}

	state := auth.ensureRuntimeLimits()
	state.mu.Lock()
	state.upstreamRateLimitedUntil = now.Add(-time.Second)
	state.mu.Unlock()
	auth.observeUpstreamRateLimitSuccess(now.Add(5*time.Minute + time.Second))
	state.mu.Lock()
	level := state.upstreamRateLimitBackoff
	state.mu.Unlock()
	if level == 0 {
		t.Fatal("same-window 429 did not extend the stable recovery window")
	}

	auth.observeUpstreamRateLimitSuccess(now.Add(5*time.Minute + 11*time.Second))
	state.mu.Lock()
	level = state.upstreamRateLimitBackoff
	state.mu.Unlock()
	if level != 0 {
		t.Fatalf("backoff level after five stable minutes = %d, want 0", level)
	}
}

func TestRuntimeLimits_SuccessfulLifecycleRecoveryPreservesUpstreamCooldown(t *testing.T) {
	now := time.Now()
	auth := &Auth{
		ID:       "auth-a",
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{"selection_error_freeze_seconds": 60},
	}
	retryAfter := 5 * time.Minute
	auth.freezeUpstreamRateLimit(now, &retryAfter)
	auth.freezeUsageLimit(now, &retryAfter)
	auth.updateQuotaPreempt(now, now.Add(time.Hour), true)
	auth.maybeFreezeRuntimeResult(Result{Error: &Error{
		HTTPStatus: http.StatusTooManyRequests,
		Code:       "rate_limit_exceeded",
		Message:    "Rate limit exceeded",
	}}, now, "")

	auth.clearTransientRateLimitRecovery(now.Add(time.Second))
	state := auth.ensureRuntimeLimits()
	state.mu.Lock()
	frozenUntil := state.frozenUntil
	upstreamUntil := state.upstreamRateLimitedUntil
	usageUntil := state.usageLimitFreezeUntil
	quotaUntil := state.quotaPreemptFreezeUntil
	backoff := state.upstreamRateLimitBackoff
	lastSeen := state.upstreamRateLimitLastSeen
	state.mu.Unlock()

	if !frozenUntil.IsZero() {
		t.Fatalf("generic recovery freeze remains: %v", frozenUntil)
	}
	if upstreamUntil.Before(now.Add(4*time.Minute)) || lastSeen.IsZero() {
		t.Fatalf("upstream cooldown was cleared by lifecycle recovery: upstream=%v backoff=%d lastSeen=%v", upstreamUntil, backoff, lastSeen)
	}
	if !usageUntil.After(now) || !quotaUntil.After(now) {
		t.Fatalf("persistent quota guards were cleared: usage=%v quota=%v", usageUntil, quotaUntil)
	}
	if blocked, reason, retryAt := runtimeAuthBlockedForModelWithTailBurst(auth, "gpt-5.6-sol", now.Add(2*time.Second), false); !blocked || reason != blockReasonCooldown || !retryAt.Equal(quotaUntil) {
		t.Fatalf("post-recovery block = (%t, %v, %v), want persistent quota freeze %v", blocked, reason, retryAt, quotaUntil)
	}
}

func TestRuntimeLimits_PersistentQuotaFreezeSourcesRecoverIndependently(t *testing.T) {
	t.Parallel()

	now := time.Now()
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive}
	usageUntil := now.Add(10 * time.Minute)
	quotaUntil := now.Add(time.Hour)
	retryAfter := 10 * time.Minute
	auth.freezeUsageLimit(now, &retryAfter)
	auth.updateQuotaPreempt(now, quotaUntil, true)
	auth.updateQuotaPreempt(now.Add(time.Minute), now.Add(5*time.Minute), true)

	state := auth.ensureRuntimeLimits()
	state.mu.Lock()
	if !state.usageLimitFreezeUntil.Equal(usageUntil) || !state.quotaPreemptFreezeUntil.Equal(quotaUntil) {
		state.mu.Unlock()
		t.Fatalf("independent freeze deadlines = usage:%v quota:%v, want usage:%v quota:%v", state.usageLimitFreezeUntil, state.quotaPreemptFreezeUntil, usageUntil, quotaUntil)
	}
	state.mu.Unlock()

	auth.updateQuotaPreempt(now.Add(time.Minute), time.Time{}, false)
	if !runtimeAuthHasPersistentQuotaFreeze(auth, now.Add(time.Minute)) {
		t.Fatal("usage-limit freeze was cleared when quota-preempt recovered")
	}

	state.mu.Lock()
	state.usageLimitFreezeUntil = time.Time{}
	state.mu.Unlock()
	if runtimeAuthHasPersistentQuotaFreeze(auth, now.Add(2*time.Minute)) {
		t.Fatal("persistent quota freeze remained after both sources recovered")
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

func TestRuntimeLimits_CountTokensAcquiresAndReleasesRuntimeSlot(t *testing.T) {
	executor := &runtimeLimitTestExecutor{
		blockAuth: "auth-a",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	defer func() {
		select {
		case <-executor.release:
		default:
			close(executor.release)
		}
	}()
	auth := &Auth{ID: "auth-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}}
	manager := newRuntimeLimitManager(t, executor, auth)
	manager.SetSelector(&FillFirstSelector{})

	done := make(chan error, 1)
	go func() {
		_, err := manager.ExecuteCount(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
		done <- err
	}()

	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("count tokens request did not start")
	}
	if got := auth.RuntimeLimitSnapshot(time.Now()).CurrentConcurrency; got != 1 {
		close(executor.release)
		t.Fatalf("current concurrency while count tokens is running = %d, want 1", got)
	}

	close(executor.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ExecuteCount() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("count tokens request did not finish")
	}
	if got := auth.RuntimeLimitSnapshot(time.Now()).CurrentConcurrency; got != 0 {
		t.Fatalf("current concurrency after count tokens = %d, want 0", got)
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
