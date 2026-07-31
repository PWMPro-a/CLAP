package executor

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/tidwall/gjson"
)

func validOpenAIResponsesReasoningEncryptedContentForTest() string {
	payload := make([]byte, 1+8+16+16+32)
	payload[0] = 0x80
	for i := 9; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_StripsOrphanIDsWhenStoreDisabled(t *testing.T) {
	valid := validOpenAIResponsesReasoningEncryptedContentForTest()
	body := []byte(`{"store":false,"input":[` +
		`{"id":"rs_bad","type":"reasoning","encrypted_content":"bad","summary":[]},` +
		`{"id":"rs_orphan","type":"reasoning","summary":[]},` +
		`{"id":"rs_good","type":"reasoning","encrypted_content":"` + valid + `","summary":[]},` +
		`{"id":"msg_1","type":"message","role":"user","content":"hi"}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gjson.GetBytes(got, "input.0.encrypted_content").Exists() {
		t.Fatalf("invalid encrypted_content still present: %s", got)
	}
	if gjson.GetBytes(got, "input.0.id").Exists() {
		t.Fatalf("invalid reasoning id should be stripped when store=false: %s", got)
	}
	if gjson.GetBytes(got, "input.1.id").Exists() {
		t.Fatalf("orphan reasoning id should be stripped when store=false: %s", got)
	}
	if gotID := gjson.GetBytes(got, "input.2.id").String(); gotID != "rs_good" {
		t.Fatalf("valid reasoning id = %q, want rs_good; body=%s", gotID, got)
	}
	if gotEC := gjson.GetBytes(got, "input.2.encrypted_content").String(); gotEC != valid {
		t.Fatalf("valid encrypted_content not preserved: %s", got)
	}
	if gotID := gjson.GetBytes(got, "input.3.id").String(); gotID != "msg_1" {
		t.Fatalf("non-reasoning id should stay: %s", got)
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_KeepsIDsWhenStoreEnabled(t *testing.T) {
	body := []byte(`{"store":true,"input":[` +
		`{"id":"rs_bad","type":"reasoning","encrypted_content":"bad","summary":[]},` +
		`{"id":"rs_orphan","type":"reasoning","summary":[]}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gjson.GetBytes(got, "input.0.encrypted_content").Exists() {
		t.Fatalf("invalid encrypted_content still present: %s", got)
	}
	if gotID := gjson.GetBytes(got, "input.0.id").String(); gotID != "rs_bad" {
		t.Fatalf("store=true should keep reasoning id after dropping invalid encrypted_content, got %q body=%s", gotID, got)
	}
	if gotID := gjson.GetBytes(got, "input.1.id").String(); gotID != "rs_orphan" {
		t.Fatalf("store=true should keep orphan reasoning id, got %q body=%s", gotID, got)
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_NoopReturnsOriginalBody(t *testing.T) {
	valid := validOpenAIResponsesReasoningEncryptedContentForTest()
	body := []byte(`{"store":false,"input":[{"id":"rs_good","type":"reasoning","encrypted_content":"` + valid + `","summary":[]},{"role":"user","content":"hi"}]}`)
	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)
	if string(got) != string(body) {
		t.Fatalf("noop path should return original body unchanged\ngot=%s\nwant=%s", got, body)
	}
	if len(got) > 0 && len(body) > 0 && &got[0] != &body[0] {
		t.Fatalf("noop path should return the original body slice")
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_StripsInvalidMessageIDs(t *testing.T) {
	body := []byte(`{"store":false,"input":[` +
		`{"id":"item_123","type":"message","role":"assistant","content":[{"type":"output_text","text":"old"}]},` +
		`{"id":"msg_456","type":"message","role":"user","content":"new"},` +
		`{"id":"fc_789","type":"function_call","call_id":"call_1","name":"tool","arguments":"{}"}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gjson.GetBytes(got, "input.0.id").Exists() {
		t.Fatalf("invalid item_* message id should be stripped: %s", got)
	}
	if gotID := gjson.GetBytes(got, "input.1.id").String(); gotID != "msg_456" {
		t.Fatalf("valid message id = %q, want msg_456; body=%s", gotID, got)
	}
	if gotID := gjson.GetBytes(got, "input.2.id").String(); gotID != "fc_789" {
		t.Fatalf("non-message id = %q, want fc_789; body=%s", gotID, got)
	}
	if gotText := gjson.GetBytes(got, "input.0.content.0.text").String(); gotText != "old" {
		t.Fatalf("message content changed while stripping id: %s", got)
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_NormalizesLegacyFunctionCallIDs(t *testing.T) {
	body := []byte(`{"store":false,"input":[` +
		`{"id":"item_legacy_call","type":"function_call","call_id":"call_123","name":"lookup","arguments":"{}"},` +
		`{"id":"item_legacy_call_output","type":"function_call_output","call_id":"call_123","output":"ok"},` +
		`{"id":"item_legacy_custom","type":"custom_tool_call","call_id":"custom_123","name":"apply_patch","input":"{}"},` +
		`{"id":"item_legacy_custom_output","type":"custom_tool_call_output","call_id":"custom_123","output":"ok"}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gotID := gjson.GetBytes(got, "input.0.id").String(); gotID != "fc_legacy_call" {
		t.Fatalf("function call id = %q, want fc_legacy_call; body=%s", gotID, got)
	}
	if gotCallID := gjson.GetBytes(got, "input.0.call_id").String(); gotCallID != "call_123" {
		t.Fatalf("function call call_id = %q, want call_123; body=%s", gotCallID, got)
	}
	if gotID := gjson.GetBytes(got, "input.1.id").String(); gotID != "fco_legacy_call_output" {
		t.Fatalf("function call output id = %q, want fco_legacy_call_output; body=%s", gotID, got)
	}
	if gotOutputCallID := gjson.GetBytes(got, "input.1.call_id").String(); gotOutputCallID != "call_123" {
		t.Fatalf("function call output call_id = %q, want call_123; body=%s", gotOutputCallID, got)
	}
	if gotID := gjson.GetBytes(got, "input.2.id").String(); gotID != "ctc_legacy_custom" {
		t.Fatalf("custom tool call id = %q, want ctc_legacy_custom; body=%s", gotID, got)
	}
	if gotID := gjson.GetBytes(got, "input.3.id").String(); gotID != "ctco_legacy_custom_output" {
		t.Fatalf("custom tool call output id = %q, want ctco_legacy_custom_output; body=%s", gotID, got)
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_NormalizesLegacyReasoningIDs(t *testing.T) {
	valid := validOpenAIResponsesReasoningEncryptedContentForTest()
	body := []byte(`{"store":false,"input":[` +
		`{"id":"item_null_signature","type":"reasoning","encrypted_content":null,"summary":[]},` +
		`{"id":"item_valid_signature","type":"reasoning","encrypted_content":"` + valid + `","summary":[]}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gjson.GetBytes(got, "input.0.id").Exists() {
		t.Fatalf("store=false invalid reasoning id should be stripped: %s", got)
	}
	if gjson.GetBytes(got, "input.0.encrypted_content").Exists() {
		t.Fatalf("null encrypted_content should be stripped: %s", got)
	}
	if gotID := gjson.GetBytes(got, "input.1.id").String(); gotID != "rs_valid_signature" {
		t.Fatalf("valid legacy reasoning id = %q, want rs_valid_signature; body=%s", gotID, got)
	}
	if gotEncryptedContent := gjson.GetBytes(got, "input.1.encrypted_content").String(); gotEncryptedContent != valid {
		t.Fatalf("valid encrypted_content changed: %s", got)
	}

	storeEnabled := []byte(`{"store":true,"input":[{"id":"item_null_signature","type":"reasoning","encrypted_content":null,"summary":[]}]}`)
	storeEnabledGot := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", storeEnabled)
	if gotID := gjson.GetBytes(storeEnabledGot, "input.0.id").String(); gotID != "rs_null_signature" {
		t.Fatalf("store=true invalid reasoning id = %q, want rs_null_signature; body=%s", gotID, storeEnabledGot)
	}
	if gjson.GetBytes(storeEnabledGot, "input.0.encrypted_content").Exists() {
		t.Fatalf("store=true null encrypted_content should be stripped: %s", storeEnabledGot)
	}
}

func TestSanitizeOpenAIResponsesReasoningEncryptedContent_NormalizesLegacyTextContent(t *testing.T) {
	body := []byte(`{"input":[` +
		`{"role":"user","content":[{"type":"text","text":"question"},{"type":"image_url","image_url":"https://example.test/image.png"}]},` +
		`{"type":"message","role":"assistant","content":[{"type":"text","text":"answer"}]},` +
		`{"id":"item_legacy_message","type":"message","role":"assistant","content":[{"type":"text","text":"history"}]}` +
		`]}`)

	got := sanitizeOpenAIResponsesReasoningEncryptedContent(context.Background(), "test", body)

	if gotType := gjson.GetBytes(got, "input.0.content.0.type").String(); gotType != "input_text" {
		t.Fatalf("user text content type = %q, want input_text; body=%s", gotType, got)
	}
	if gotType := gjson.GetBytes(got, "input.0.content.1.type").String(); gotType != "image_url" {
		t.Fatalf("image content type = %q, want image_url; body=%s", gotType, got)
	}
	if gotType := gjson.GetBytes(got, "input.1.content.0.type").String(); gotType != "output_text" {
		t.Fatalf("assistant text content type = %q, want output_text; body=%s", gotType, got)
	}
	if gjson.GetBytes(got, "input.2.id").Exists() {
		t.Fatalf("legacy assistant message id should be stripped: %s", got)
	}
	if gotType := gjson.GetBytes(got, "input.2.content.0.type").String(); gotType != "output_text" {
		t.Fatalf("legacy assistant content type = %q, want output_text; body=%s", gotType, got)
	}
}
