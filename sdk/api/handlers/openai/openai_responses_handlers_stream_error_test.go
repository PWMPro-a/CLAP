package openai

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestForwardResponsesStreamTerminalErrorUsesResponsesErrorChunk(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, nil)
	h := NewOpenAIResponsesAPIHandler(base)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		t.Fatalf("expected gin writer to implement http.Flusher")
	}

	data := make(chan []byte)
	errs := make(chan *interfaces.ErrorMessage, 1)
	errs <- &interfaces.ErrorMessage{StatusCode: http.StatusInternalServerError, Error: errors.New("unexpected EOF")}
	close(errs)

	h.forwardResponsesStream(c, flusher, func(error) {}, data, errs, nil)
	body := recorder.Body.String()
	if !strings.Contains(body, `event: response.failed`) {
		t.Fatalf("expected response.failed SSE event, got: %q", body)
	}
	if !strings.Contains(body, `"type":"response.failed"`) {
		t.Fatalf("expected response.failed payload, got: %q", body)
	}
	if !strings.Contains(body, `"status":"failed"`) {
		t.Fatalf("expected failed response status, got: %q", body)
	}
	if strings.Contains(body, `"error":{`) {
		if !strings.Contains(body, `"response":{`) {
			t.Fatalf("expected Responses failed event, got HTTP error body: %q", body)
		}
	}
}

func TestForwardResponsesStreamTerminalErrorAfterStructureEventUsesResponseFailed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, nil)
	h := NewOpenAIResponsesAPIHandler(base)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		t.Fatalf("expected gin writer to implement http.Flusher")
	}

	data := make(chan []byte, 2)
	errs := make(chan *interfaces.ErrorMessage, 1)
	data <- []byte(`data: {"type":"response.created","response":{"id":"resp-1","status":"in_progress"}}`)
	data <- []byte(`data: {"type":"response.in_progress","response":{"id":"resp-1","status":"in_progress"}}`)
	go func() {
		time.Sleep(10 * time.Millisecond)
		errs <- &interfaces.ErrorMessage{StatusCode: http.StatusInternalServerError, Error: errors.New("unexpected EOF")}
	}()

	h.forwardResponsesStream(c, flusher, func(error) {}, data, errs, nil)
	body := recorder.Body.String()
	if !strings.Contains(body, `"type":"response.created"`) {
		t.Fatalf("expected created event before terminal error, got: %q", body)
	}
	if !strings.Contains(body, `"type":"response.in_progress"`) {
		t.Fatalf("expected in_progress event before terminal error, got: %q", body)
	}
	if !strings.Contains(body, `event: response.failed`) || !strings.Contains(body, `"type":"response.failed"`) {
		t.Fatalf("expected response.failed terminal event, got: %q", body)
	}
	if strings.Contains(body, `"type":"error"`) {
		t.Fatalf("top-level type:error should not be used for terminal Responses errors: %q", body)
	}
}
