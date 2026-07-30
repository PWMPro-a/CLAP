package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestBuildOpenAIResponsesStreamErrorChunk(t *testing.T) {
	chunk := BuildOpenAIResponsesStreamErrorChunk(http.StatusInternalServerError, "unexpected EOF", 0)
	var payload map[string]any
	if err := json.Unmarshal(chunk, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["type"] != "error" {
		t.Fatalf("type = %v, want %q", payload["type"], "error")
	}
	if payload["code"] != "internal_server_error" {
		t.Fatalf("code = %v, want %q", payload["code"], "internal_server_error")
	}
	if payload["message"] != "unexpected EOF" {
		t.Fatalf("message = %v, want %q", payload["message"], "unexpected EOF")
	}
	if payload["sequence_number"] != float64(0) {
		t.Fatalf("sequence_number = %v, want %v", payload["sequence_number"], 0)
	}
}

func TestBuildOpenAIResponsesStreamErrorChunkExtractsHTTPErrorBody(t *testing.T) {
	chunk := BuildOpenAIResponsesStreamErrorChunk(
		http.StatusInternalServerError,
		`{"error":{"message":"oops","type":"server_error","code":"internal_server_error"}}`,
		0,
	)
	var payload map[string]any
	if err := json.Unmarshal(chunk, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["type"] != "error" {
		t.Fatalf("type = %v, want %q", payload["type"], "error")
	}
	if payload["code"] != "internal_server_error" {
		t.Fatalf("code = %v, want %q", payload["code"], "internal_server_error")
	}
	if payload["message"] != "oops" {
		t.Fatalf("message = %v, want %q", payload["message"], "oops")
	}
}

func TestBuildOpenAIResponsesStreamFailedChunk(t *testing.T) {
	chunk := BuildOpenAIResponsesStreamFailedChunk(
		http.StatusTooManyRequests,
		`{"error":{"message":"limit hit","type":"usage_limit_reached","code":"usage_limit_reached"}}`,
		7,
	)
	var payload map[string]any
	if err := json.Unmarshal(chunk, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["type"] != "response.failed" {
		t.Fatalf("type = %v, want response.failed", payload["type"])
	}
	if payload["sequence_number"] != float64(7) {
		t.Fatalf("sequence_number = %v, want 7", payload["sequence_number"])
	}
	resp, ok := payload["response"].(map[string]any)
	if !ok {
		t.Fatalf("response missing or invalid: %#v", payload["response"])
	}
	if resp["status"] != "failed" {
		t.Fatalf("response.status = %v, want failed", resp["status"])
	}
	errPayload, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("response.error missing or invalid: %#v", resp["error"])
	}
	if errPayload["message"] != "limit hit" {
		t.Fatalf("error.message = %v, want limit hit", errPayload["message"])
	}
	if errPayload["type"] != "usage_limit_reached" {
		t.Fatalf("error.type = %v, want usage_limit_reached", errPayload["type"])
	}
	if errPayload["code"] != "usage_limit_reached" {
		t.Fatalf("error.code = %v, want usage_limit_reached", errPayload["code"])
	}
}
