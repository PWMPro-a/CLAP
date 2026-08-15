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
			name:      "existing JSON hint",
			body:      `{"model":"gpt-5.5","instructions":"Respond using JSON.","input":"Return one object.","text":{"format":{"type":"json_object"}}}`,
			unchanged: true,
		},
		{
			name:      "non json object format",
			body:      `{"model":"gpt-5.5","input":"Return one object.","text":{"format":{"type":"text"}}}`,
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
