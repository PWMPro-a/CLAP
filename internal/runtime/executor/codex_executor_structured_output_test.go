package executor

import (
	"bytes"
	"context"
	"io"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestNormalizeCodexStructuredOutputCompatibility(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		unchanged bool
		assert    func(t *testing.T, body []byte)
	}{
		{
			name: "string input",
			body: `{"model":"gpt-5.5","input":"Return one object.","text":{"format":{"type":"json_object"}}}`,
			assert: func(t *testing.T, body []byte) {
				if got := gjson.GetBytes(body, "input").String(); got != "Return one object.\n\n"+codexJSONOutputInstruction {
					t.Fatalf("input = %q", got)
				}
			},
		},
		{
			name: "array input",
			body: `{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"Return one object."}]}],"text":{"format":{"type":"json_object"}}}`,
			assert: func(t *testing.T, body []byte) {
				input := gjson.GetBytes(body, "input").Array()
				if len(input) != 2 || input[1].Get("role").String() != "developer" ||
					input[1].Get("content.0.text").String() != codexJSONOutputInstruction {
					t.Fatalf("developer JSON instruction missing: %s", body)
				}
			},
		},
		{
			name: "top level instructions do not satisfy input requirement",
			body: `{"model":"gpt-5.5","instructions":"Respond using JSON.","input":"Return one object.","text":{"format":{"type":"json_object"}}}`,
			assert: func(t *testing.T, body []byte) {
				if got := gjson.GetBytes(body, "input").String(); got != "Return one object.\n\n"+codexJSONOutputInstruction {
					t.Fatalf("top-level instructions suppressed JSON input repair: %s", body)
				}
			},
		},
		{
			name:      "non json object format",
			body:      `{"model":"gpt-5.5","input":"Return one object.","text":{"format":{"type":"text"}}}`,
			unchanged: true,
		},
		{
			name: "structural JSON name does not satisfy prompt requirement",
			body: `{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"Return one object."}]},{"type":"function_call","call_id":"call_1","name":"json_lookup","arguments":"{}"}],"text":{"format":{"type":"json_object"}}}`,
			assert: func(t *testing.T, body []byte) {
				input := gjson.GetBytes(body, "input").Array()
				if len(input) != 3 || input[2].Get("content.0.text").String() != codexJSONOutputInstruction {
					t.Fatalf("structural JSON string suppressed prompt repair: %s", body)
				}
			},
		},
		{
			name: "assistant JSON history does not satisfy prompt requirement",
			body: `{"model":"gpt-5.5","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Prior JSON response."}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"Return one object."}]}],"text":{"format":{"type":"json_object"}}}`,
			assert: func(t *testing.T, body []byte) {
				input := gjson.GetBytes(body, "input").Array()
				if len(input) != 3 || input[2].Get("role").String() != "developer" ||
					input[2].Get("content.0.text").String() != codexJSONOutputInstruction {
					t.Fatalf("assistant history suppressed JSON prompt repair: %s", body)
				}
			},
		},
		{
			name:      "developer JSON prompt remains unchanged",
			body:      `{"model":"gpt-5.5","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"Return JSON."}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"Return one object."}]}],"text":{"format":{"type":"json_object"}}}`,
			unchanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := []byte(tt.body)
			got := normalizeCodexStructuredOutputCompatibility(original)
			if tt.unchanged && !bytes.Equal(got, original) {
				t.Fatalf("request changed:\noriginal: %s\nupdated:  %s", original, got)
			}
			if tt.assert != nil {
				tt.assert(t, got)
			}
		})
	}
}

func TestNormalizeCodexToolChoiceCompatibility(t *testing.T) {
	t.Run("removes choice when tools are absent", func(t *testing.T) {
		body := []byte(`{"tool_choice":{"type":"function","name":"lookup"},"parallel_tool_calls":true,"input":"hello"}`)
		got := normalizeCodexToolChoiceCompatibility(body)
		if gjson.GetBytes(got, "tool_choice").Exists() || gjson.GetBytes(got, "parallel_tool_calls").Exists() {
			t.Fatalf("orphan tool choice was not removed: %s", got)
		}
	})

	t.Run("falls back to auto when named tool is missing", func(t *testing.T) {
		body := []byte(`{"tools":[{"type":"function","name":"other","parameters":{"type":"object"}}],"tool_choice":{"type":"function","name":"lookup"},"input":"hello"}`)
		got := normalizeCodexToolChoiceCompatibility(body)
		if choice := gjson.GetBytes(got, "tool_choice"); choice.Type != gjson.String || choice.String() != "auto" {
			t.Fatalf("invalid named choice did not fall back to auto: %s", got)
		}
	})

	t.Run("keeps valid named tool byte for byte", func(t *testing.T) {
		body := []byte(`{"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"tool_choice":{"type":"function","name":"lookup"},"input":"hello"}`)
		got := normalizeCodexToolChoiceCompatibility(body)
		if !bytes.Equal(got, body) {
			t.Fatalf("valid named tool choice changed:\noriginal: %s\nupdated:  %s", body, got)
		}
	})

	t.Run("keeps standard mode byte for byte", func(t *testing.T) {
		body := []byte(`{"tool_choice":"required","tools":[{"type":"function","name":"lookup"}],"input":"hello"}`)
		got := normalizeCodexToolChoiceCompatibility(body)
		if !bytes.Equal(got, body) {
			t.Fatalf("standard tool mode changed:\noriginal: %s\nupdated:  %s", body, got)
		}
	})
}

func TestNormalizeCodexOrphanToolCalls(t *testing.T) {
	t.Run("synthesizes missing function output in place", func(t *testing.T) {
		body := []byte(`{"input":[{"type":"message","role":"user","content":"start"},{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"message","role":"user","content":"continue"}]}`)
		got := normalizeCodexOrphanToolCalls(body)
		input := gjson.GetBytes(got, "input").Array()
		if len(input) != 4 || input[2].Get("type").String() != "function_call_output" ||
			input[2].Get("call_id").String() != "call_1" ||
			input[2].Get("output").String() != codexMissingToolOutput ||
			input[3].Get("role").String() != "user" {
			t.Fatalf("orphan function call was not repaired in place: %s", got)
		}
	})

	t.Run("synthesizes matching custom tool output", func(t *testing.T) {
		body := []byte(`{"input":[{"type":"custom_tool_call","call_id":"call_custom","name":"search","input":"query"}]}`)
		got := normalizeCodexOrphanToolCalls(body)
		output := gjson.GetBytes(got, "input.1")
		if output.Get("type").String() != "custom_tool_call_output" ||
			output.Get("call_id").String() != "call_custom" {
			t.Fatalf("orphan custom tool call was not repaired: %s", got)
		}
	})

	t.Run("keeps valid pair byte for byte", func(t *testing.T) {
		body := []byte(`{"input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"ok"}]}`)
		got := normalizeCodexOrphanToolCalls(body)
		if !bytes.Equal(got, body) {
			t.Fatalf("valid tool transcript changed:\noriginal: %s\nupdated:  %s", body, got)
		}
	})

	t.Run("keeps non array input unchanged", func(t *testing.T) {
		body := []byte(`{"input":"hello"}`)
		if got := normalizeCodexOrphanToolCalls(body); !bytes.Equal(got, body) {
			t.Fatalf("string input changed: %s", got)
		}
	})
}

func TestCodexStructuredOutputCompatibilityTransportBoundaries(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","input":"Return one object.","text":{"format":{"type":"json_object"}}}`)
	req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: body}

	httpReq, upstreamBody, _, err := (&CodexExecutor{}).cacheHelper(
		context.Background(),
		sdktranslator.FormatCodex,
		"https://example.com/responses",
		nil,
		req,
		body,
		body,
	)
	if err != nil {
		t.Fatalf("cacheHelper() error = %v", err)
	}
	httpBody, errRead := io.ReadAll(httpReq.Body)
	if errRead != nil {
		t.Fatalf("read HTTP request body: %v", errRead)
	}
	for name, candidate := range map[string][]byte{"returned": upstreamBody, "http": httpBody} {
		if got := gjson.GetBytes(candidate, "input").String(); got != "Return one object.\n\n"+codexJSONOutputInstruction {
			t.Fatalf("%s transport input = %q", name, got)
		}
	}

	websocketBody, _, err := applyCodexPromptCacheHeadersWithContext(
		context.Background(),
		sdktranslator.FormatCodex,
		req,
		body,
	)
	if err != nil {
		t.Fatalf("applyCodexPromptCacheHeadersWithContext() error = %v", err)
	}
	if got := gjson.GetBytes(websocketBody, "input").String(); got != "Return one object.\n\n"+codexJSONOutputInstruction {
		t.Fatalf("websocket transport input = %q", got)
	}
}
