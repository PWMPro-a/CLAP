package helps

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const codexTailBurstToolJSON = `{"type":"function","name":"cpa_internal_continue","description":"Reserved gateway compatibility declaration. Do not call this tool.","parameters":{"type":"object","properties":{},"additionalProperties":false},"strict":true}`
const codexTailBurstToolArrayJSON = `[` + codexTailBurstToolJSON + `]`
const codexTailBurstAdditionalToolsItemJSON = `{"type":"additional_tools","role":"developer","tools":` + codexTailBurstToolArrayJSON + `}`

// InjectCodexTailBurstTool adds one internal function declaration to an
// otherwise tool-free Codex request. It explicitly disables tool execution:
// the declaration is a Codex request-shape compatibility hint, not a user
// tool, so it must never introduce an internal function-call continuation or
// change the response's first-token path. The returned flag records whether
// this function changed the body.
func InjectCodexTailBurstTool(body []byte, model string, allowlist []string, responsesLite bool) ([]byte, bool) {
	if len(body) == 0 || !gjson.ValidBytes(body) || !codexTailBurstToolModelAllowed(model, allowlist) {
		return body, false
	}
	root := gjson.ParseBytes(body)
	if root.Get("previous_response_id").Exists() || root.Get("tool_choice").Exists() || codexTailBurstRequestHasTools(root) {
		return body, false
	}

	var changed bool
	if responsesLite {
		updated, ok := prependCodexTailBurstAdditionalTools(body, root.Get("input"))
		if !ok {
			return body, false
		}
		body = updated
		changed = true
	} else {
		updated, errSet := sjson.SetRawBytes(body, "tools", []byte(codexTailBurstToolArrayJSON))
		if errSet != nil {
			return body, false
		}
		body = updated
		changed = true
	}
	if changed {
		body, _ = sjson.SetBytes(body, "tool_choice", "none")
		body, _ = sjson.SetBytes(body, "parallel_tool_calls", false)
	}
	return body, changed
}

func codexTailBurstToolModelAllowed(model string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	model = strings.TrimSpace(strings.ToLower(model))
	for _, candidate := range allowlist {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "*" || candidate == model {
			return true
		}
	}
	return false
}

func codexTailBurstRequestHasTools(root gjson.Result) bool {
	if tools := root.Get("tools"); tools.IsArray() && len(tools.Array()) > 0 {
		return true
	}
	input := root.Get("input")
	if !input.IsArray() {
		return false
	}
	for _, item := range input.Array() {
		switch item.Get("type").String() {
		case "additional_tools", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
			return true
		}
	}
	return false
}

func prependCodexTailBurstAdditionalTools(body []byte, input gjson.Result) ([]byte, bool) {
	if !input.IsArray() {
		return body, false
	}
	items := input.Array()
	var rebuilt bytes.Buffer
	rebuilt.Grow(len(input.Raw) + len(codexTailBurstAdditionalToolsItemJSON) + 1)
	rebuilt.WriteByte('[')
	rebuilt.WriteString(codexTailBurstAdditionalToolsItemJSON)
	for _, item := range items {
		rebuilt.WriteByte(',')
		rebuilt.WriteString(item.Raw)
	}
	rebuilt.WriteByte(']')
	updated, errSet := sjson.SetRawBytes(body, "input", rebuilt.Bytes())
	if errSet != nil {
		return body, false
	}
	return updated, true
}
