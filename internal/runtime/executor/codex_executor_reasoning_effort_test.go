package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

var benchmarkCodexReasoningEffortBody []byte

func TestNormalizeCodexReasoningEffortForModel(t *testing.T) {
	tests := []struct {
		name  string
		model string
		body  string
		want  string
	}{
		{name: "gpt 5.5 clamps max", model: "gpt-5.5", body: `{"reasoning":{"effort":"max"}}`, want: "xhigh"},
		{name: "gpt 5.4 clamps uppercase max", model: "gpt-5.4", body: `{"reasoning":{"effort":"MAX"}}`, want: "xhigh"},
		{name: "gpt 5.6 sol preserves max", model: "gpt-5.6-sol", body: `{"reasoning":{"effort":"max"}}`, want: "max"},
		{name: "gpt 5.6 terra canonicalizes max", model: "codex/gpt-5.6-terra", body: `{"reasoning":{"effort":"MAX"}}`, want: "max"},
		{name: "gpt 6 preserves max", model: "gpt-6.0", body: `{"reasoning":{"effort":"max"}}`, want: "max"},
		{name: "other effort unchanged", model: "gpt-5.5", body: `{"reasoning":{"effort":"high"}}`, want: "high"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeCodexReasoningEffortForModel([]byte(test.body), test.model)
			if effort := gjson.GetBytes(got, "reasoning.effort").String(); effort != test.want {
				t.Fatalf("reasoning.effort = %q, want %q; body=%s", effort, test.want, got)
			}
		})
	}
}

func TestCodexHTTPExecutorsClampMaxReasoningEffort(t *testing.T) {
	routes := []struct {
		name    string
		compact bool
		stream  bool
	}{
		{name: "execute"},
		{name: "stream", stream: true},
		{name: "compact", compact: true},
	}
	scenarios := []struct {
		name    string
		config  *config.Config
		payload string
	}{
		{
			name:    "direct client max",
			config:  &config.Config{},
			payload: `{"model":"gpt-5.5","input":"hello","reasoning":{"effort":"max"}}`,
		},
		{
			name:    "late payload override",
			config:  codexLateMaxOverrideConfig(),
			payload: `{"model":"gpt-5.5","input":"hello"}`,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			for _, route := range routes {
				t.Run(route.name, func(t *testing.T) {
					var gotBody []byte
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						gotBody, _ = io.ReadAll(r.Body)
						if route.compact {
							w.Header().Set("Content-Type", "application/json")
							_, _ = w.Write([]byte(`{"id":"resp_1","object":"response.compaction","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
							return
						}
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
					}))
					defer server.Close()

					exec := NewCodexExecutor(scenario.config)
					auth := codexReasoningEffortTestAuth(server.URL)
					req := cliproxyexecutor.Request{
						Model:   "gpt-5.5",
						Payload: []byte(scenario.payload),
					}
					opts := cliproxyexecutor.Options{
						SourceFormat: sdktranslator.FromString("openai-response"),
						Stream:       route.stream,
					}
					if route.compact {
						opts.Alt = "responses/compact"
					}

					if route.stream {
						result, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
						if errExecute != nil {
							t.Fatalf("ExecuteStream() error = %v", errExecute)
						}
						for range result.Chunks {
						}
					} else if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
						t.Fatalf("Execute() error = %v", errExecute)
					}

					if effort := gjson.GetBytes(gotBody, "reasoning.effort").String(); effort != "xhigh" {
						t.Fatalf("upstream reasoning.effort = %q, want xhigh; body=%s", effort, gotBody)
					}
				})
			}
		})
	}
}

func TestCodexWebsocketExecutorsClampMaxReasoningEffort(t *testing.T) {
	scenarios := []struct {
		name    string
		config  *config.Config
		payload string
	}{
		{
			name:    "direct client max",
			config:  &config.Config{},
			payload: `{"model":"gpt-5.5","input":"hello","reasoning":{"effort":"max"}}`,
		},
		{
			name:    "late payload override",
			config:  codexLateMaxOverrideConfig(),
			payload: `{"model":"gpt-5.5","input":"hello"}`,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				name := "execute"
				if stream {
					name = "stream"
				}
				t.Run(name, func(t *testing.T) {
					upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
					captured := make(chan []byte, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						conn, errUpgrade := upgrader.Upgrade(w, r, nil)
						if errUpgrade != nil {
							t.Errorf("upgrade websocket: %v", errUpgrade)
							return
						}
						defer func() { _ = conn.Close() }()
						_, payload, errRead := conn.ReadMessage()
						if errRead != nil {
							t.Errorf("read websocket request: %v", errRead)
							return
						}
						captured <- payload
						completed := []byte(`{"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
						if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
							t.Errorf("write websocket response: %v", errWrite)
						}
					}))
					defer server.Close()

					exec := NewCodexWebsocketsExecutor(scenario.config)
					auth := codexReasoningEffortTestAuth(server.URL)
					req := cliproxyexecutor.Request{
						Model:   "gpt-5.5",
						Payload: []byte(scenario.payload),
					}
					opts := cliproxyexecutor.Options{
						SourceFormat: sdktranslator.FromString("openai-response"),
						Stream:       stream,
					}
					if stream {
						result, errExecute := exec.ExecuteStream(context.Background(), auth, req, opts)
						if errExecute != nil {
							t.Fatalf("ExecuteStream() error = %v", errExecute)
						}
						for range result.Chunks {
						}
					} else if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
						t.Fatalf("Execute() error = %v", errExecute)
					}

					upstreamBody := <-captured
					if effort := gjson.GetBytes(upstreamBody, "reasoning.effort").String(); effort != "xhigh" {
						t.Fatalf("websocket reasoning.effort = %q, want xhigh; body=%s", effort, upstreamBody)
					}
				})
			}
		})
	}
}

func TestCodexCountTokensClampsInboundMaxReasoningEffort(t *testing.T) {
	exec := NewCodexExecutor(&config.Config{})
	response, errCount := exec.CountTokens(context.Background(), nil, cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","input":"hello","reasoning":{"effort":"max"}}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")})
	if errCount != nil {
		t.Fatalf("CountTokens() error = %v", errCount)
	}
	if len(response.Payload) == 0 {
		t.Fatal("CountTokens() returned an empty response")
	}
}

func codexLateMaxOverrideConfig() *config.Config {
	return &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{
			{Name: "gpt-5.5", Protocol: "codex"},
			{Name: "gpt-5.5", Protocol: "openai-response"},
		},
		Params: map[string]any{"reasoning.effort": "max"},
	}}}}
}

func codexReasoningEffortTestAuth(baseURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url": baseURL,
		"api_key":  "test",
	}}
}

func BenchmarkNormalizeCodexReasoningEffortForModel(b *testing.B) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "canonical-high", body: []byte(`{"reasoning":{"effort":"high"},"input":"hello"}`)},
		{name: "old-model-max", body: []byte(`{"reasoning":{"effort":"max"},"input":"hello"}`)},
		{
			name: "old-model-max-after-1mb-input",
			body: []byte(`{"input":"` + strings.Repeat("x", 1<<20) + `","reasoning":{"effort":"max"}}`),
		},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.body)))
			for b.Loop() {
				benchmarkCodexReasoningEffortBody = normalizeCodexReasoningEffortForModel(test.body, "gpt-5.5")
			}
		})
	}
}
