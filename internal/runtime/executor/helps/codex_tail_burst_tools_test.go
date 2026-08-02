package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestInjectCodexTailBurstTool(t *testing.T) {
	body := []byte(`{"model":"gpt-5-codex","input":"hello"}`)
	updated, injected := InjectCodexTailBurstTool(body, "gpt-5-codex", nil, false)
	if !injected {
		t.Fatal("expected tail-burst tool injection")
	}
	if got := gjson.GetBytes(updated, "tools.0.name").String(); got != "cpa_internal_continue" {
		t.Fatalf("tool name = %q", got)
	}
	if got := gjson.GetBytes(updated, "tool_choice").String(); got != "none" {
		t.Fatalf("tool_choice = %q, want none", got)
	}
	if gjson.GetBytes(updated, "parallel_tool_calls").Bool() {
		t.Fatalf("parallel_tool_calls = true, want false")
	}
}

func TestInjectCodexTailBurstToolPreservesExistingTools(t *testing.T) {
	body := []byte(`{"input":"hello","tools":[{"type":"function","name":"lookup"}]}`)
	updated, injected := InjectCodexTailBurstTool(body, "gpt-5-codex", nil, false)
	if injected {
		t.Fatal("existing tools must not receive an injected tool")
	}
	if string(updated) != string(body) {
		t.Fatalf("existing body changed: %s", updated)
	}
}

func TestInjectCodexTailBurstToolResponsesLitePrependsAdditionalTools(t *testing.T) {
	body := []byte(`{"input":[{"type":"message","role":"user","content":"hello"}]}`)
	updated, injected := InjectCodexTailBurstTool(body, "gpt-5-codex", nil, true)
	if !injected {
		t.Fatal("expected responses-lite injection")
	}
	if got := gjson.GetBytes(updated, "input.0.type").String(); got != "additional_tools" {
		t.Fatalf("input.0.type = %q", got)
	}
	if got := gjson.GetBytes(updated, "input.0.tools.0.name").String(); got != "cpa_internal_continue" {
		t.Fatalf("injected tool name = %q", got)
	}
	if got := gjson.GetBytes(updated, "input.1.type").String(); got != "message" {
		t.Fatalf("original input type = %q", got)
	}
}

func TestInjectCodexTailBurstToolSkipsContinuation(t *testing.T) {
	body := []byte(`{"previous_response_id":"resp_1","input":"hello"}`)
	_, injected := InjectCodexTailBurstTool(body, "gpt-5-codex", nil, false)
	if injected {
		t.Fatal("continuation request received an injected tool")
	}
}
