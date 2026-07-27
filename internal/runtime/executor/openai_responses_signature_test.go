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
