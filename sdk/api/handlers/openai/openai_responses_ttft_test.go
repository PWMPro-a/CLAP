package openai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	providerexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const responsesSSETTFTUpstreamDelay = 180 * time.Millisecond

type firstWriteRecorder struct {
	*httptest.ResponseRecorder
	firstWrite     chan time.Time
	firstWriteOnce sync.Once
}

func newFirstWriteRecorder() *firstWriteRecorder {
	return &firstWriteRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		firstWrite:       make(chan time.Time, 1),
	}
}

func (r *firstWriteRecorder) WriteHeader(statusCode int) {
	r.markFirstWrite()
	r.ResponseRecorder.WriteHeader(statusCode)
}

func (r *firstWriteRecorder) Write(body []byte) (int, error) {
	r.markFirstWrite()
	return r.ResponseRecorder.Write(body)
}

func (r *firstWriteRecorder) Flush() {
	r.ResponseRecorder.Flush()
}

func (r *firstWriteRecorder) markFirstWrite() {
	r.firstWriteOnce.Do(func() { r.firstWrite <- time.Now() })
}

func TestOpenAIResponsesSSETTFTBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream response writer does not support streaming")
			return
		}
		flusher.Flush()
		timer := time.NewTimer(responsesSSETTFTUpstreamDelay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"hello\"}\n\n")
		flusher.Flush()
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)

	engine := newResponsesTTFTTestEngine(t, upstream.URL, internalconfig.StreamingConfig{})

	measure := func() (time.Duration, error) {
		recorder := newFirstWriteRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"handler-ttft-model","stream":true,"input":"hello"}`))
		request.Header.Set("Content-Type", "application/json")
		started := time.Now()
		done := make(chan struct{})
		go func() {
			engine.ServeHTTP(recorder, request)
			close(done)
		}()
		var firstWrite time.Time
		select {
		case firstWrite = <-recorder.firstWrite:
		case <-time.After(3 * time.Second):
			return 0, fmt.Errorf("timed out waiting for first downstream SSE write")
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			return 0, fmt.Errorf("timed out waiting for downstream stream completion")
		}
		if recorder.Code != http.StatusOK {
			return 0, fmt.Errorf("response status %d: %s", recorder.Code, recorder.Body.String())
		}
		return firstWrite.Sub(started), nil
	}

	for range 3 {
		if _, errMeasure := measure(); errMeasure != nil {
			t.Fatalf("warm-up: %v", errMeasure)
		}
	}
	samples := make([]time.Duration, 20)
	for index := range samples {
		value, errMeasure := measure()
		if errMeasure != nil {
			t.Fatalf("sample %d: %v", index, errMeasure)
		}
		samples[index] = value
	}
	assertResponsesSSETTFTBudget(t, "serial", samples, 220*time.Millisecond, 40*time.Millisecond)

	concurrent := make([]time.Duration, 16)
	errorsByIndex := make([]error, len(concurrent))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range concurrent {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			concurrent[index], errorsByIndex[index] = measure()
		}()
	}
	close(start)
	wait.Wait()
	for index, errMeasure := range errorsByIndex {
		if errMeasure != nil {
			t.Fatalf("concurrent sample %d: %v", index, errMeasure)
		}
	}
	assertResponsesSSETTFTBudget(t, "concurrent-16", concurrent, 230*time.Millisecond, 50*time.Millisecond)
}

func TestOpenAIResponsesSSEBootstrapKeepAlive(t *testing.T) {
	const (
		bootstrapDelay = 100 * time.Millisecond
		upstreamDelay  = 2200 * time.Millisecond
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()
		timer := time.NewTimer(upstreamDelay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_bootstrap\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)

	engine := newResponsesTTFTTestEngine(t, upstream.URL, internalconfig.StreamingConfig{
		BootstrapKeepAliveMillis: int(bootstrapDelay / time.Millisecond),
		KeepAliveSeconds:         1,
	})
	recorder := newFirstWriteRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"handler-ttft-model","stream":true,"input":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	done := make(chan struct{})
	go func() {
		engine.ServeHTTP(recorder, request)
		close(done)
	}()

	var firstWrite time.Time
	select {
	case firstWrite = <-recorder.firstWrite:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bootstrap SSE heartbeat")
	}
	if elapsed := firstWrite.Sub(started); elapsed < 70*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("bootstrap first write = %s, want near %s", elapsed, bootstrapDelay)
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for stream completion")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if count := strings.Count(body, ": keep-alive\n\n"); count < 3 {
		t.Fatalf("keep-alive count = %d, want initial plus periodic heartbeats: %q", count, body)
	}
	if !strings.Contains(body, `"id":"resp_bootstrap"`) {
		t.Fatalf("missing upstream completion after heartbeats: %q", body)
	}
}

func TestOpenAIResponsesSSEBootstrapKeepAliveDefaults(t *testing.T) {
	const upstreamDelay = 2200 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()
		timer := time.NewTimer(upstreamDelay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)

	engine := newResponsesTTFTTestEngine(t, upstream.URL, internalconfig.StreamingConfig{})
	recorder := newFirstWriteRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"handler-ttft-model","stream":true,"input":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	done := make(chan struct{})
	go func() {
		engine.ServeHTTP(recorder, request)
		close(done)
	}()

	var firstWrite time.Time
	select {
	case firstWrite = <-recorder.firstWrite:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bootstrap SSE heartbeat")
	}
	if elapsed := firstWrite.Sub(started); elapsed > 100*time.Millisecond {
		t.Fatalf("bootstrap first write = %s, want immediate commit", elapsed)
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for codex stream completion")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), ": keep-alive") {
		t.Fatalf("missing bootstrap heartbeat: %q", recorder.Body.String())
	}
}

func TestOpenAIResponsesSSEBootstrapKeepsImmediateHTTPError(t *testing.T) {
	engine := newResponsesTTFTTestEngine(t, "http://127.0.0.1:1", internalconfig.StreamingConfig{
		BootstrapKeepAliveMillis: 150,
		KeepAliveSeconds:         1,
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"missing-model","stream":true,"input":"hello"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusOK {
		t.Fatalf("immediate selection error was committed as SSE 200: %q", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), ": keep-alive") {
		t.Fatalf("immediate error unexpectedly emitted bootstrap heartbeat: %q", recorder.Body.String())
	}
}

func newResponsesTTFTTestEngine(t *testing.T, upstreamURL string, streaming internalconfig.StreamingConfig) *gin.Engine {
	t.Helper()
	runtimeConfig := &internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{Streaming: streaming},
		Routing:   internalconfig.RoutingConfig{HighCacheMode: true, NewCandidateMode: true},
	}
	executor := providerexecutor.NewCodexExecutor(runtimeConfig)
	selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback:      &coreauth.RoundRobinSelector{},
		TTL:           time.Minute,
		HighCacheMode: true,
	})
	t.Cleanup(selector.Stop)
	manager := coreauth.NewManager(nil, selector, nil)
	manager.SetConfig(runtimeConfig)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{
		ID:       "handler-ttft-auth",
		Provider: executor.Identifier(),
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"base_url": upstreamURL,
			"api_key":  "ttft-test-key",
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	const model = "handler-ttft-model"
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	manager.RefreshSchedulerEntry(auth.ID)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	base := handlers.NewBaseAPIHandlers(&runtimeConfig.SDKConfig, manager)
	handler := NewOpenAIResponsesAPIHandler(base)
	engine := gin.New()
	engine.POST("/v1/responses", handler.Responses)
	return engine
}

func assertResponsesSSETTFTBudget(t *testing.T, name string, samples []time.Duration, ttftBudget, overheadBudget time.Duration) {
	t.Helper()
	sort.Slice(samples, func(left, right int) bool { return samples[left] < samples[right] })
	p50 := responsesTTFTPercentile(samples, 50)
	p95 := responsesTTFTPercentile(samples, 95)
	overheadP95 := p95 - responsesSSETTFTUpstreamDelay
	t.Logf("OpenAI Responses SSE end-to-end TTFT %s: upstream=%s ttft_p50=%s ttft_p95=%s ttft_max=%s handler_overhead_p95=%s", name, responsesSSETTFTUpstreamDelay, p50, p95, samples[len(samples)-1], overheadP95)
	if p95 > ttftBudget {
		t.Errorf("%s end-to-end TTFT p95 = %s, budget %s", name, p95, ttftBudget)
	}
	if overheadP95 > overheadBudget {
		t.Errorf("%s handler overhead p95 = %s, budget %s", name, overheadP95, overheadBudget)
	}
}

func responsesTTFTPercentile(sorted []time.Duration, percentile int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted)*percentile + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}
