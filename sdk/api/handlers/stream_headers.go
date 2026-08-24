package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetSSEHeaders applies the canonical SSE response headers used across streaming handlers.
func SetSSEHeaders(c *gin.Context) {
	if c == nil {
		return
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("X-Accel-Buffering", "no")
}

// CommitStreamResponse commits response headers immediately without writing a body chunk.
func CommitStreamResponse(c *gin.Context) {
	if c == nil || c.Writer == nil || c.Writer.Written() {
		return
	}
	c.Writer.WriteHeaderNow()
}

// BootstrapStreamResponse commits headers and optionally writes an initial payload before flushing.
func BootstrapStreamResponse(c *gin.Context, flusher http.Flusher, payload []byte) {
	if c == nil || c.Writer == nil || flusher == nil {
		return
	}
	CommitStreamResponse(c)
	if len(payload) > 0 {
		_, _ = c.Writer.Write(payload)
	}
	flusher.Flush()
}
