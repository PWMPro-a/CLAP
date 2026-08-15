package executor

import (
	"bytes"
	"testing"

	"github.com/tidwall/gjson"
)

func TestNormalizeCodexImageInputCompatibility(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.6-sol",
		"input":[
			{"type":"message","role":"user","quality":"original","content":[
				{"type":"input_text","text":"Inspect images."},
				{"type":"image_url","image_url":"data:image/png;base64,AA==","quality":"original"},
				{"type":"input_image","image_url":{"url":"https://example.com/a.png","detail":"low"},"quality":"hd"},
				{"type":"input_image","quality":"standard"}
			]},
			{"type":"image_url","image_url":{"file_id":"file-image-1"},"quality":"standard"}
		]
	}`)
	out := normalizeCodexImageInputCompatibility(body)
	if bytes.Contains(out, []byte(`"quality"`)) {
		t.Fatalf("quality field survived normalization: %s", out)
	}
	if got := gjson.GetBytes(out, "input.0.content.#").Int(); got != 3 {
		t.Fatalf("message content count = %d, want invalid empty image removed: %s", got, out)
	}
	if got := gjson.GetBytes(out, "input.0.content.1.type").String(); got != "input_image" {
		t.Fatalf("string image type = %q, want input_image", got)
	}
	if got := gjson.GetBytes(out, "input.0.content.1.image_url").String(); got != "data:image/png;base64,AA==" {
		t.Fatalf("string image URL = %q", got)
	}
	if got := gjson.GetBytes(out, "input.0.content.1.detail").String(); got != "original" {
		t.Fatalf("quality-derived detail = %q, want original", got)
	}
	if got := gjson.GetBytes(out, "input.0.content.2.image_url").String(); got != "https://example.com/a.png" {
		t.Fatalf("object image URL = %q", got)
	}
	if got := gjson.GetBytes(out, "input.0.content.2.detail").String(); got != "low" {
		t.Fatalf("existing detail = %q, want low", got)
	}
	if got := gjson.GetBytes(out, "input.1.file_id").String(); got != "file-image-1" {
		t.Fatalf("file-backed image = %q", got)
	}
	if gjson.GetBytes(out, "input.1.image_url").Exists() {
		t.Fatalf("file-backed image retained object image_url: %s", out)
	}
	if got := gjson.GetBytes(out, "input.1.detail").String(); got != "auto" {
		t.Fatalf("standard quality detail = %q, want auto", got)
	}
}

func TestNormalizeCodexImageInputCompatibilityNoopPreservesBytes(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	out := normalizeCodexImageInputCompatibility(body)
	if &out[0] != &body[0] || !bytes.Equal(out, body) {
		t.Fatalf("ordinary request changed: got %s want %s", out, body)
	}
}
