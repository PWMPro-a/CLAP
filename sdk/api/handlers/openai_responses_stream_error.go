package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type openAIResponsesStreamErrorChunk struct {
	Type           string `json:"type"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	SequenceNumber int    `json:"sequence_number"`
}

type openAIResponsesStreamErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

type openAIResponsesStreamFailedChunk struct {
	Type           string `json:"type"`
	SequenceNumber int    `json:"sequence_number,omitempty"`
	Response       struct {
		ID        string                           `json:"id"`
		Object    string                           `json:"object"`
		CreatedAt int64                            `json:"created_at"`
		Status    string                           `json:"status"`
		Error     openAIResponsesStreamErrorDetail `json:"error"`
	} `json:"response"`
}

func openAIResponsesStreamErrorCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "invalid_api_key"
	case http.StatusForbidden:
		return "insufficient_quota"
	case http.StatusTooManyRequests:
		return "rate_limit_exceeded"
	case http.StatusNotFound:
		return "model_not_found"
	case http.StatusRequestTimeout:
		return "request_timeout"
	default:
		if status >= http.StatusInternalServerError {
			return "internal_server_error"
		}
		if status >= http.StatusBadRequest {
			return "invalid_request_error"
		}
		return "unknown_error"
	}
}

func openAIResponsesStreamErrorType(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	default:
		if status >= http.StatusInternalServerError {
			return "server_error"
		}
		if status >= http.StatusBadRequest {
			return "invalid_request_error"
		}
		return "server_error"
	}
}

func openAIResponsesStreamErrorDetailFromText(status int, errText string) openAIResponsesStreamErrorDetail {
	message := strings.TrimSpace(errText)
	if message == "" {
		message = http.StatusText(status)
	}
	code := openAIResponsesStreamErrorCode(status)
	errType := openAIResponsesStreamErrorType(status)

	trimmed := strings.TrimSpace(errText)
	if trimmed != "" && json.Valid([]byte(trimmed)) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			if t, ok := payload["type"].(string); ok && strings.TrimSpace(t) == "error" {
				if m, ok := payload["message"].(string); ok && strings.TrimSpace(m) != "" {
					message = strings.TrimSpace(m)
				}
				if v, ok := payload["code"]; ok && v != nil {
					if c, ok := v.(string); ok && strings.TrimSpace(c) != "" {
						code = strings.TrimSpace(c)
					} else {
						code = strings.TrimSpace(fmt.Sprint(v))
					}
				}
			}
			if e, ok := payload["error"].(map[string]any); ok {
				if m, ok := e["message"].(string); ok && strings.TrimSpace(m) != "" {
					message = strings.TrimSpace(m)
				}
				if t, ok := e["type"].(string); ok && strings.TrimSpace(t) != "" {
					errType = strings.TrimSpace(t)
				}
				if v, ok := e["code"]; ok && v != nil {
					if c, ok := v.(string); ok && strings.TrimSpace(c) != "" {
						code = strings.TrimSpace(c)
					} else {
						code = strings.TrimSpace(fmt.Sprint(v))
					}
				}
			}
		}
	}

	if strings.TrimSpace(code) == "" {
		code = "unknown_error"
	}
	if strings.TrimSpace(errType) == "" {
		errType = openAIResponsesStreamErrorType(status)
	}
	return openAIResponsesStreamErrorDetail{
		Message: message,
		Type:    errType,
		Code:    code,
	}
}

// BuildOpenAIResponsesStreamErrorChunk builds an OpenAI Responses streaming error chunk.
//
// Important: OpenAI's HTTP error bodies are shaped like {"error":{...}}; those are valid for
// non-streaming responses, but streaming clients validate SSE `data:` payloads against a union
// of chunks that requires a top-level `type` field.
func BuildOpenAIResponsesStreamErrorChunk(status int, errText string, sequenceNumber int) []byte {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if sequenceNumber < 0 {
		sequenceNumber = 0
	}

	detail := openAIResponsesStreamErrorDetailFromText(status, errText)
	trimmed := strings.TrimSpace(errText)
	if trimmed != "" && json.Valid([]byte(trimmed)) {
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			if v, ok := payload["sequence_number"].(float64); ok && sequenceNumber == 0 {
				sequenceNumber = int(v)
			}
		}
	}

	data, err := json.Marshal(openAIResponsesStreamErrorChunk{
		Type:           "error",
		Code:           detail.Code,
		Message:        detail.Message,
		SequenceNumber: sequenceNumber,
	})
	if err == nil {
		return data
	}

	// Extremely defensive fallback.
	data, _ = json.Marshal(openAIResponsesStreamErrorChunk{
		Type:           "error",
		Code:           "internal_server_error",
		Message:        detail.Message,
		SequenceNumber: sequenceNumber,
	})
	if len(data) > 0 {
		return data
	}
	return []byte(`{"type":"error","code":"internal_server_error","message":"internal error","sequence_number":0}`)
}

// BuildOpenAIResponsesStreamFailedChunk builds the terminal SSE payload used by
// the Responses API when a stream fails after headers or structure events have
// already been sent. Using response.failed instead of a top-level type:error is
// important for gateway/proxy parsers that route terminal Responses events by
// event type.
func BuildOpenAIResponsesStreamFailedChunk(status int, errText string, sequenceNumber int) []byte {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	if sequenceNumber < 0 {
		sequenceNumber = 0
	}
	detail := openAIResponsesStreamErrorDetailFromText(status, errText)
	payload := openAIResponsesStreamFailedChunk{
		Type:           "response.failed",
		SequenceNumber: sequenceNumber,
	}
	payload.Response.ID = fmt.Sprintf("resp_failed_%d", time.Now().UnixNano())
	payload.Response.Object = "response"
	payload.Response.CreatedAt = time.Now().Unix()
	payload.Response.Status = "failed"
	payload.Response.Error = detail
	data, err := json.Marshal(payload)
	if err == nil && len(data) > 0 {
		return data
	}
	return []byte(`{"type":"response.failed","response":{"id":"resp_failed","object":"response","status":"failed","error":{"message":"internal error","type":"server_error","code":"internal_server_error"}}}`)
}
