package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const codexSSETTFTUpstreamDelay = 180 * time.Millisecond

type codexSSETiming struct {
	requestReceived time.Time
	firstEventSent  time.Time
}

type codexSSETTFTSample struct {
	ttft          time.Duration
	upstreamDelay time.Duration
	proxyOverhead time.Duration
}

type codexSSETTFTFixture struct {
	server   *httptest.Server
	executor *CodexExecutor
	auth     *cliproxyauth.Auth
	timings  sync.Map
	sequence atomic.Uint64
}

func newCodexSSETTFTFixture(tb testing.TB) *codexSSETTFTFixture {
	tb.Helper()
	fixture := &codexSSETTFTFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			http.Error(w, errRead.Error(), http.StatusBadRequest)
			return
		}
		requestID := gjson.GetBytes(body, "client_metadata.ttft_benchmark_id").String()
		if requestID == "" {
			http.Error(w, "missing TTFT benchmark id", http.StatusBadRequest)
			return
		}
		requestReceived := time.Now()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		flusher.Flush()

		timer := time.NewTimer(codexSSETTFTUpstreamDelay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}

		firstEventSent := time.Now()
		fixture.timings.Store(requestID, codexSSETiming{
			requestReceived: requestReceived,
			firstEventSent:  firstEventSent,
		})
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"hello\"}\n\n")
		flusher.Flush()
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
		flusher.Flush()
	}))
	tb.Cleanup(fixture.server.Close)
	fixture.executor = NewCodexExecutor(&config.Config{Routing: config.RoutingConfig{HighCacheMode: true}})
	fixture.auth = &cliproxyauth.Auth{
		ID:       "ttft-auth",
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": fixture.server.URL,
			"api_key":  "ttft-test-key",
		},
	}
	fixture.auth.EnsureIndex()
	return fixture
}

func (f *codexSSETTFTFixture) measure(ctx context.Context) (codexSSETTFTSample, error) {
	requestID := fmt.Sprintf("ttft-%d", f.sequence.Add(1))
	payload := []byte(fmt.Sprintf(`{"model":"gpt-5.5","input":"hello","client_metadata":{"ttft_benchmark_id":%q}}`, requestID))
	started := time.Now()
	result, errExecute := f.executor.ExecuteStream(ctx, f.auth.Clone(), cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: payload,
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey:    "ttft-caller",
			cliproxyexecutor.CodexAppServerMetadataKey: true,
		},
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatCodex,
		Stream:       true,
	})
	if errExecute != nil {
		return codexSSETTFTSample{}, fmt.Errorf("execute stream: %w", errExecute)
	}

	var firstChunkAt time.Time
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			return codexSSETTFTSample{}, fmt.Errorf("stream chunk: %w", chunk.Err)
		}
		if firstChunkAt.IsZero() && len(chunk.Payload) > 0 {
			firstChunkAt = time.Now()
		}
	}
	if firstChunkAt.IsZero() {
		return codexSSETTFTSample{}, fmt.Errorf("stream emitted no payload")
	}
	rawTiming, ok := f.timings.LoadAndDelete(requestID)
	if !ok {
		return codexSSETTFTSample{}, fmt.Errorf("upstream timing missing for %s", requestID)
	}
	timing := rawTiming.(codexSSETiming)
	return codexSSETTFTSample{
		ttft:          firstChunkAt.Sub(started),
		upstreamDelay: timing.firstEventSent.Sub(timing.requestReceived),
		proxyOverhead: timing.requestReceived.Sub(started) + firstChunkAt.Sub(timing.firstEventSent),
	}, nil
}

func TestCodexExecutorSSETTFTBudget(t *testing.T) {
	fixture := newCodexSSETTFTFixture(t)
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, errMeasure := fixture.measure(ctx)
		cancel()
		if errMeasure != nil {
			t.Fatalf("warm-up: %v", errMeasure)
		}
	}

	serial := make([]codexSSETTFTSample, 20)
	for index := range serial {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		sample, errMeasure := fixture.measure(ctx)
		cancel()
		if errMeasure != nil {
			t.Fatalf("serial sample %d: %v", index, errMeasure)
		}
		serial[index] = sample
	}
	assertCodexSSETTFTBudget(t, "serial", serial, 220*time.Millisecond, 40*time.Millisecond)

	concurrent := make([]codexSSETTFTSample, 16)
	errorsByIndex := make([]error, len(concurrent))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range concurrent {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			concurrent[index], errorsByIndex[index] = fixture.measure(ctx)
		}()
	}
	close(start)
	wait.Wait()
	for index, errMeasure := range errorsByIndex {
		if errMeasure != nil {
			t.Fatalf("concurrent sample %d: %v", index, errMeasure)
		}
	}
	assertCodexSSETTFTBudget(t, "concurrent-16", concurrent, 230*time.Millisecond, 50*time.Millisecond)
}

func BenchmarkCodexExecutorSSETTFT200ms(b *testing.B) {
	fixture := newCodexSSETTFTFixture(b)
	samples := make([]codexSSETTFTSample, 0, b.N)
	b.ResetTimer()
	for range b.N {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		sample, errMeasure := fixture.measure(ctx)
		cancel()
		if errMeasure != nil {
			b.Fatal(errMeasure)
		}
		samples = append(samples, sample)
	}
	b.StopTimer()
	ttft := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.ttft })
	upstream := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.upstreamDelay })
	overhead := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.proxyOverhead })
	b.ReportMetric(durationMilliseconds(percentileDuration(ttft, 50)), "ttft_p50_ms")
	b.ReportMetric(durationMilliseconds(percentileDuration(ttft, 95)), "ttft_p95_ms")
	b.ReportMetric(durationMilliseconds(percentileDuration(upstream, 95)), "upstream_p95_ms")
	b.ReportMetric(durationMilliseconds(percentileDuration(overhead, 95)), "proxy_overhead_p95_ms")
}

func assertCodexSSETTFTBudget(t *testing.T, name string, samples []codexSSETTFTSample, ttftBudget, overheadBudget time.Duration) {
	t.Helper()
	ttft := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.ttft })
	upstream := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.upstreamDelay })
	overhead := sampleDurations(samples, func(sample codexSSETTFTSample) time.Duration { return sample.proxyOverhead })
	ttftP50 := percentileDuration(ttft, 50)
	ttftP95 := percentileDuration(ttft, 95)
	upstreamP95 := percentileDuration(upstream, 95)
	overheadP95 := percentileDuration(overhead, 95)
	t.Logf("Codex SSE TTFT %s: upstream_p95=%s ttft_p50=%s ttft_p95=%s ttft_max=%s proxy_overhead_p95=%s", name, upstreamP95, ttftP50, ttftP95, ttft[len(ttft)-1], overheadP95)
	if ttftP95 > ttftBudget {
		t.Errorf("%s TTFT p95 = %s, budget %s", name, ttftP95, ttftBudget)
	}
	if overheadP95 > overheadBudget {
		t.Errorf("%s proxy overhead p95 = %s, budget %s", name, overheadP95, overheadBudget)
	}
}

func sampleDurations(samples []codexSSETTFTSample, value func(codexSSETTFTSample) time.Duration) []time.Duration {
	durations := make([]time.Duration, len(samples))
	for index, sample := range samples {
		durations[index] = value(sample)
	}
	sort.Slice(durations, func(left, right int) bool { return durations[left] < durations[right] })
	return durations
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
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

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
