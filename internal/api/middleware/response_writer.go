// Package middleware provides Gin HTTP middleware for the CLI Proxy API server.
// It includes a sophisticated response writer wrapper designed to capture and log request and response data,
// including support for streaming responses, without impacting latency.
package middleware

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	log "github.com/sirupsen/logrus"
)

const requestBodyOverrideContextKey = "REQUEST_BODY_OVERRIDE"
const responseBodyOverrideContextKey = "RESPONSE_BODY_OVERRIDE"
const websocketTimelineOverrideContextKey = "WEBSOCKET_TIMELINE_OVERRIDE"

// RequestInfo holds essential details of an incoming HTTP request for logging purposes.
type RequestInfo struct {
	URL                 string                      // URL is the request URL.
	Method              string                      // Method is the HTTP method (e.g., GET or POST).
	Headers             map[string][]string         // Headers contains the request headers.
	Body                []byte                      // Body is the raw request body.
	RequestID           string                      // RequestID is the unique identifier for the request.
	Timestamp           time.Time                   // Timestamp is when the request was received.
	deferredBodyCapture *deferredRequestBodyCapture // deferredBodyCapture spools large error-only request bodies.
}

// ResponseWriterWrapper wraps the standard gin.ResponseWriter to intercept and log response data.
// It is designed to handle both standard and streaming responses, ensuring that logging operations do not block the client response.
type ResponseWriterWrapper struct {
	gin.ResponseWriter
	body                *bytes.Buffer              // body is a buffer to store the response body for non-streaming responses.
	isStreaming         bool                       // isStreaming indicates whether the response is a streaming type (e.g., text/event-stream).
	streamWriter        logging.StreamingLogWriter // streamWriter is a writer for handling streaming log entries.
	streamWriterMu      sync.Mutex                 // streamWriterMu protects streamWriter while async initialization completes.
	chunkChannel        chan []byte                // chunkChannel is a channel for asynchronously passing response chunks to the logger.
	streamDone          chan struct{}              // streamDone signals when the streaming goroutine completes.
	logger              logging.RequestLogger      // logger is the instance of the request logger service.
	requestInfo         *RequestInfo               // requestInfo holds the details of the original request.
	statusCode          int                        // statusCode stores the HTTP status code of the response.
	headers             map[string][]string        // headers stores the response headers.
	logOnErrorOnly      bool                       // logOnErrorOnly enables logging only when an error response is detected.
	firstChunkTimestamp time.Time                  // firstChunkTimestamp captures TTFB for streaming responses.
}

// NewResponseWriterWrapper creates and initializes a new ResponseWriterWrapper.
// It takes the original gin.ResponseWriter, a logger instance, and request information.
//
// Parameters:
//   - w: The original gin.ResponseWriter to wrap.
//   - logger: The logging service to use for recording requests.
//   - requestInfo: The pre-captured information about the incoming request.
//
// Returns:
//   - A pointer to a new ResponseWriterWrapper.
func NewResponseWriterWrapper(w gin.ResponseWriter, logger logging.RequestLogger, requestInfo *RequestInfo) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		logger:         logger,
		requestInfo:    requestInfo,
		headers:        make(map[string][]string),
	}
}

// Write wraps the underlying ResponseWriter's Write method to capture response data.
// For non-streaming responses, it writes to an internal buffer. For streaming responses,
// it sends data chunks to a non-blocking channel for asynchronous logging.
// CRITICAL: This method prioritizes writing to the client to ensure zero latency,
// handling logging operations subsequently.
func (w *ResponseWriterWrapper) Write(data []byte) (int, error) {
	// Ensure headers are captured before first write
	// This is critical because Write() may trigger WriteHeader() internally
	w.ensureHeadersCaptured()
	if w.ResponseWriter != nil && !w.ResponseWriter.Written() {
		w.WriteHeaderNow()
	}

	// CRITICAL: Write to client first (zero latency)
	n, err := w.ResponseWriter.Write(data)

	// THEN: Handle logging based on response type
	if w.isStreaming && w.chunkChannel != nil {
		// Capture TTFB on first chunk (synchronous, before async channel send)
		if w.firstChunkTimestamp.IsZero() {
			w.firstChunkTimestamp = time.Now()
		}
		// For streaming responses: Send to async logging channel (non-blocking)
		select {
		case w.chunkChannel <- append([]byte(nil), data...): // Non-blocking send with copy
		default: // Channel full, skip logging to avoid blocking
		}
		return n, err
	}

	if w.shouldBufferResponseBody() {
		w.body.Write(data)
	}

	return n, err
}

func (w *ResponseWriterWrapper) shouldBufferResponseBody() bool {
	if w.logger != nil && w.logger.IsEnabled() {
		return true
	}
	if !w.logOnErrorOnly {
		return false
	}
	status := w.statusCode
	if status == 0 {
		if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok && statusWriter != nil {
			status = statusWriter.Status()
		} else {
			status = http.StatusOK
		}
	}
	return status >= http.StatusBadRequest
}

// WriteString wraps the underlying ResponseWriter's WriteString method to capture response data.
// Some handlers (and fmt/io helpers) write via io.StringWriter; without this override, those writes
// bypass Write() and would be missing from request logs.
func (w *ResponseWriterWrapper) WriteString(data string) (int, error) {
	w.ensureHeadersCaptured()
	if w.ResponseWriter != nil && !w.ResponseWriter.Written() {
		w.WriteHeaderNow()
	}

	// CRITICAL: Write to client first (zero latency)
	n, err := w.ResponseWriter.WriteString(data)

	// THEN: Capture for logging
	if w.isStreaming && w.chunkChannel != nil {
		// Capture TTFB on first chunk (synchronous, before async channel send)
		if w.firstChunkTimestamp.IsZero() {
			w.firstChunkTimestamp = time.Now()
		}
		select {
		case w.chunkChannel <- []byte(data):
		default:
		}
		return n, err
	}

	if w.shouldBufferResponseBody() {
		w.body.WriteString(data)
	}
	return n, err
}

// WriteHeader wraps the underlying ResponseWriter's WriteHeader method.
// It captures the status code, detects if the response is streaming based on the Content-Type header,
// and initializes the appropriate logging mechanism (standard or streaming).
func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	if w.prepareHeader(statusCode) {
		w.startStreamingLogWriter(statusCode)
	}
}

// WriteHeaderNow commits the response through the wrapper so explicit SSE
// bootstrap flushes still initialize streaming logging before body writes.
func (w *ResponseWriterWrapper) WriteHeaderNow() {
	if w.ResponseWriter == nil || w.ResponseWriter.Written() {
		return
	}
	statusCode := w.statusCode
	if statusCode == 0 {
		statusCode = w.ResponseWriter.Status()
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
	}
	if !w.prepareHeader(statusCode) {
		return
	}
	w.ResponseWriter.WriteHeaderNow()
	w.startStreamingLogWriter(statusCode)
}

// Flush commits pending headers through the wrapper before flushing the
// underlying writer, avoiding gin's promoted Flush bypassing WriteHeaderNow.
func (w *ResponseWriterWrapper) Flush() {
	w.WriteHeaderNow()
	if w.ResponseWriter == nil {
		return
	}
	w.ResponseWriter.Flush()
}

func (w *ResponseWriterWrapper) prepareHeader(statusCode int) bool {
	if w.ResponseWriter == nil || w.ResponseWriter.Written() {
		return false
	}
	w.statusCode = statusCode

	// Capture response headers using the new method
	w.captureCurrentHeaders()

	// Detect streaming based on Content-Type
	contentType := w.ResponseWriter.Header().Get("Content-Type")
	w.isStreaming = w.detectStreaming(contentType)

	// Call original WriteHeader before log initialization so SSE bootstrap
	// writes can flush to the client without waiting on filesystem/log I/O.
	w.ResponseWriter.WriteHeader(statusCode)
	return true
}

func (w *ResponseWriterWrapper) startStreamingLogWriter(statusCode int) {
	// If streaming, initialize streaming logging in the background. The chunk
	// channel is installed first so early chunks can be captured without
	// blocking the response path.
	if !w.isStreaming || w.logger == nil || !w.logger.IsEnabled() || w.chunkChannel != nil || w.streamDone != nil {
		return
	}
	w.chunkChannel = make(chan []byte, 100) // Buffered channel for async writes
	doneChan := make(chan struct{})
	w.streamDone = doneChan
	go w.processStreamingChunks(doneChan, statusCode, w.cloneHeaderMap(w.headers), w.chunkChannel)
}

// ensureHeadersCaptured is a helper function to make sure response headers are captured.
// It is safe to call this method multiple times; it will always refresh the headers
// with the latest state from the underlying ResponseWriter.
func (w *ResponseWriterWrapper) ensureHeadersCaptured() {
	// Always capture the current headers to ensure we have the latest state
	w.captureCurrentHeaders()
}

// captureCurrentHeaders reads all headers from the underlying ResponseWriter and stores them
// in the wrapper's headers map. It creates copies of the header values to prevent race conditions.
func (w *ResponseWriterWrapper) captureCurrentHeaders() {
	// Initialize headers map if needed
	if w.headers == nil {
		w.headers = make(map[string][]string)
	}

	// Capture all current headers from the underlying ResponseWriter
	for key, values := range w.ResponseWriter.Header() {
		// Make a copy of the values slice to avoid reference issues
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		w.headers[key] = headerValues
	}
}

// detectStreaming determines if a response should be treated as a streaming response.
// It checks for a "text/event-stream" Content-Type or a '"stream": true'
// field in the original request body.
func (w *ResponseWriterWrapper) detectStreaming(contentType string) bool {
	// Check Content-Type for Server-Sent Events
	if strings.Contains(contentType, "text/event-stream") {
		return true
	}

	// If a concrete Content-Type is already set (e.g., application/json for error responses),
	// treat it as non-streaming instead of inferring from the request payload.
	if strings.TrimSpace(contentType) != "" {
		return false
	}

	// Only fall back to request payload hints when Content-Type is not set yet.
	if w.requestInfo != nil && len(w.requestInfo.Body) > 0 {
		return bytes.Contains(w.requestInfo.Body, []byte(`"stream": true`)) ||
			bytes.Contains(w.requestInfo.Body, []byte(`"stream":true`))
	}

	return false
}

// processStreamingChunks runs in a separate goroutine to process response chunks from the chunkChannel.
// It asynchronously writes each chunk to the streaming log writer.
func (w *ResponseWriterWrapper) processStreamingChunks(done chan struct{}, statusCode int, headers map[string][]string, chunks <-chan []byte) {
	if done == nil {
		return
	}

	defer close(done)

	if w.logger == nil || w.requestInfo == nil || chunks == nil {
		for range chunks {
		}
		return
	}

	streamWriter, err := w.logger.LogStreamingRequest(
		w.requestInfo.URL,
		w.requestInfo.Method,
		w.requestInfo.Headers,
		w.requestInfo.Body,
		w.requestInfo.RequestID,
	)
	if err != nil || streamWriter == nil {
		for range chunks {
		}
		return
	}
	w.setStreamWriter(streamWriter)
	_ = streamWriter.WriteStatus(statusCode, headers)

	for chunk := range chunks {
		streamWriter.WriteChunkAsync(chunk)
	}
}

func (w *ResponseWriterWrapper) setStreamWriter(streamWriter logging.StreamingLogWriter) {
	w.streamWriterMu.Lock()
	w.streamWriter = streamWriter
	w.streamWriterMu.Unlock()
}

func (w *ResponseWriterWrapper) getStreamWriter() logging.StreamingLogWriter {
	w.streamWriterMu.Lock()
	defer w.streamWriterMu.Unlock()
	return w.streamWriter
}

func (w *ResponseWriterWrapper) clearStreamWriter() {
	w.streamWriterMu.Lock()
	w.streamWriter = nil
	w.streamWriterMu.Unlock()
}

// Finalize completes the logging process for the request and response.
// For streaming responses, it closes the chunk channel and the stream writer.
// For non-streaming responses, it logs the complete request and response details,
// including any API-specific request/response data stored in the Gin context.
func (w *ResponseWriterWrapper) Finalize(c *gin.Context) error {
	if w.requestInfo != nil && w.requestInfo.deferredBodyCapture != nil {
		defer w.requestInfo.deferredBodyCapture.Cleanup()
	}
	if w.logger == nil {
		return nil
	}

	finalStatusCode := w.statusCode
	if finalStatusCode == 0 {
		if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok {
			finalStatusCode = statusWriter.Status()
		} else {
			finalStatusCode = 200
		}
	}

	var slicesAPIResponseError []*interfaces.ErrorMessage
	apiResponseError, isExist := c.Get("API_RESPONSE_ERROR")
	if isExist {
		if apiErrors, ok := apiResponseError.([]*interfaces.ErrorMessage); ok {
			slicesAPIResponseError = apiErrors
		}
	}

	hasAPIError := len(slicesAPIResponseError) > 0 || finalStatusCode >= http.StatusBadRequest
	forceLog := w.logOnErrorOnly && hasAPIError && !w.logger.IsEnabled()
	websocketTimelineSource := w.extractWebsocketTimelineSource(c)
	apiRequestSource := w.extractAPIRequestSource(c)
	apiResponseSource := w.extractAPIResponseSource(c)
	apiWebsocketTimelineSource := w.extractAPIWebsocketTimelineSource(c)
	if !w.logger.IsEnabled() && !forceLog {
		cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource, apiWebsocketTimelineSource)
		return nil
	}

	hasStreamLogging := w.chunkChannel != nil || w.streamDone != nil || w.getStreamWriter() != nil
	if w.isStreaming && hasStreamLogging {
		if w.chunkChannel != nil {
			close(w.chunkChannel)
			w.chunkChannel = nil
		}

		if w.streamDone != nil {
			<-w.streamDone
			w.streamDone = nil
		}

		streamWriter := w.getStreamWriter()
		if streamWriter == nil {
			cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource, apiWebsocketTimelineSource)
			return nil
		}

		streamWriter.SetFirstChunkTimestamp(w.firstChunkTimestamp)

		// Write API Request and Response to the streaming log before closing
		apiRequest := w.extractAPIRequest(c)
		apiResponse := w.extractAPIResponse(c)
		if sourceWriter, ok := streamWriter.(interface {
			WriteAPIRequestSource(*logging.FileBodySource) error
			WriteAPIResponseSource(*logging.FileBodySource) error
		}); ok {
			if len(apiRequest) > 0 {
				_ = streamWriter.WriteAPIRequest(apiRequest)
			}
			if apiRequestSource != nil && apiRequestSource.HasPayload() {
				_ = sourceWriter.WriteAPIRequestSource(apiRequestSource)
			}
			if len(apiResponse) > 0 {
				_ = streamWriter.WriteAPIResponse(apiResponse)
			}
			if apiResponseSource != nil && apiResponseSource.HasPayload() {
				_ = sourceWriter.WriteAPIResponseSource(apiResponseSource)
			}
		} else {
			var errMerge error
			apiRequest, errMerge = mergeFileBodySource(apiRequest, apiRequestSource)
			if errMerge != nil {
				cleanupFileBodySources(websocketTimelineSource, apiResponseSource, apiWebsocketTimelineSource)
				return errMerge
			}
			apiResponse, errMerge = mergeFileBodySource(apiResponse, apiResponseSource)
			if errMerge != nil {
				cleanupFileBodySources(websocketTimelineSource, apiWebsocketTimelineSource)
				return errMerge
			}
			if len(apiRequest) > 0 {
				_ = streamWriter.WriteAPIRequest(apiRequest)
			}
			if len(apiResponse) > 0 {
				_ = streamWriter.WriteAPIResponse(apiResponse)
			}
		}
		apiWebsocketTimeline := w.extractAPIWebsocketTimeline(c)
		var errMerge error
		apiWebsocketTimeline, errMerge = mergeFileBodySource(apiWebsocketTimeline, apiWebsocketTimelineSource)
		if errMerge != nil {
			cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource)
			return errMerge
		}
		if len(apiWebsocketTimeline) > 0 {
			_ = streamWriter.WriteAPIWebsocketTimeline(apiWebsocketTimeline)
		}
		if err := streamWriter.Close(); err != nil {
			w.clearStreamWriter()
			cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource)
			return err
		}
		w.clearStreamWriter()
		cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource)
		return nil
	}

	apiRequest := w.extractAPIRequest(c)
	if forceLog && len(apiRequest) == 0 {
		apiRequest = w.extractDeferredAPIRequest(c)
	}
	return w.logRequest(w.extractRequestBody(c), finalStatusCode, w.cloneHeaders(), w.extractResponseBody(c), w.extractWebsocketTimeline(c), websocketTimelineSource, apiRequest, apiRequestSource, w.extractAPIResponse(c), apiResponseSource, w.extractAPIWebsocketTimeline(c), apiWebsocketTimelineSource, w.extractAPIResponseTimestamp(c), slicesAPIResponseError, forceLog)
}

func (w *ResponseWriterWrapper) cloneHeaders() map[string][]string {
	w.ensureHeadersCaptured()
	return w.cloneHeaderMap(w.headers)
}

func (w *ResponseWriterWrapper) cloneHeaderMap(headers map[string][]string) map[string][]string {
	finalHeaders := make(map[string][]string, len(headers))
	for key, values := range headers {
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		finalHeaders[key] = headerValues
	}

	return finalHeaders
}

func (w *ResponseWriterWrapper) extractAPIRequest(c *gin.Context) []byte {
	apiRequest, isExist := c.Get("API_REQUEST")
	if !isExist {
		return nil
	}
	data, ok := apiRequest.([]byte)
	if !ok || len(data) == 0 {
		return nil
	}
	return data
}

func (w *ResponseWriterWrapper) extractDeferredAPIRequest(c *gin.Context) []byte {
	if c == nil {
		return nil
	}
	value, exists := c.Get(logging.DeferredAPIRequestContextKey)
	if !exists {
		return nil
	}
	requests, ok := value.([]logging.DeferredAPIRequest)
	if !ok || len(requests) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, buildRequest := range requests {
		if buildRequest == nil {
			continue
		}
		body.Write(buildRequest())
	}
	return body.Bytes()
}

func (w *ResponseWriterWrapper) extractAPIResponse(c *gin.Context) []byte {
	apiResponse, isExist := c.Get("API_RESPONSE")
	if !isExist {
		return nil
	}
	data, ok := apiResponse.([]byte)
	if !ok || len(data) == 0 {
		return nil
	}
	return data
}

func (w *ResponseWriterWrapper) extractAPIRequestSource(c *gin.Context) *logging.FileBodySource {
	return extractFileBodySource(c, logging.APIRequestSourceContextKey)
}

func (w *ResponseWriterWrapper) extractAPIResponseSource(c *gin.Context) *logging.FileBodySource {
	return extractFileBodySource(c, logging.APIResponseSourceContextKey)
}

func (w *ResponseWriterWrapper) extractAPIWebsocketTimeline(c *gin.Context) []byte {
	apiTimeline, isExist := c.Get("API_WEBSOCKET_TIMELINE")
	if !isExist {
		return nil
	}
	data, ok := apiTimeline.([]byte)
	if !ok || len(data) == 0 {
		return nil
	}
	return bytes.Clone(data)
}

func (w *ResponseWriterWrapper) extractAPIWebsocketTimelineSource(c *gin.Context) *logging.FileBodySource {
	return extractFileBodySource(c, logging.APIWebsocketTimelineSourceContextKey)
}

func (w *ResponseWriterWrapper) extractAPIResponseTimestamp(c *gin.Context) time.Time {
	ts, isExist := c.Get("API_RESPONSE_TIMESTAMP")
	if !isExist {
		return time.Time{}
	}
	if t, ok := ts.(time.Time); ok {
		return t
	}
	return time.Time{}
}

func (w *ResponseWriterWrapper) extractRequestBody(c *gin.Context) []byte {
	if body := extractBodyOverride(c, requestBodyOverrideContextKey); len(body) > 0 {
		return body
	}
	if w.requestInfo == nil {
		return nil
	}
	if len(w.requestInfo.Body) > 0 {
		return w.requestInfo.Body
	}
	if w.requestInfo.deferredBodyCapture == nil {
		return nil
	}
	body, statusMarker, errRead := w.requestInfo.deferredBodyCapture.Bytes()
	if errRead != nil {
		log.WithError(errRead).Warn("failed to read deferred request body capture")
		return nil
	}
	encoding := ""
	for key, values := range w.requestInfo.Headers {
		if strings.EqualFold(key, "Content-Encoding") && len(values) > 0 {
			encoding = values[0]
			break
		}
	}
	body = decodeCapturedRequestBodyForLogWithLimit(body, encoding, maxDeferredErrorRequestBodyBytes)
	if statusMarker == "" {
		return body
	}
	if len(body) > 0 && !bytes.HasSuffix(body, []byte("\n")) {
		body = append(body, '\n')
	}
	return append(body, statusMarker...)
}

func (w *ResponseWriterWrapper) extractResponseBody(c *gin.Context) []byte {
	if body := extractBodyOverride(c, responseBodyOverrideContextKey); len(body) > 0 {
		return body
	}
	if w.body == nil || w.body.Len() == 0 {
		return nil
	}
	return bytes.Clone(w.body.Bytes())
}

func (w *ResponseWriterWrapper) extractWebsocketTimeline(c *gin.Context) []byte {
	return extractBodyOverride(c, websocketTimelineOverrideContextKey)
}

func (w *ResponseWriterWrapper) extractWebsocketTimelineSource(c *gin.Context) *logging.FileBodySource {
	return extractFileBodySource(c, logging.WebsocketTimelineSourceContextKey)
}

func extractFileBodySource(c *gin.Context, key string) *logging.FileBodySource {
	if c == nil {
		return nil
	}
	value, exists := c.Get(key)
	if !exists {
		return nil
	}
	source, ok := value.(*logging.FileBodySource)
	if !ok || source == nil {
		return nil
	}
	return source
}

func extractBodyOverride(c *gin.Context, key string) []byte {
	if c == nil {
		return nil
	}
	bodyOverride, isExist := c.Get(key)
	if !isExist {
		return nil
	}
	switch value := bodyOverride.(type) {
	case []byte:
		if len(value) > 0 {
			return bytes.Clone(value)
		}
	case string:
		if strings.TrimSpace(value) != "" {
			return []byte(value)
		}
	}
	return nil
}

func (w *ResponseWriterWrapper) logRequest(requestBody []byte, statusCode int, headers map[string][]string, body, websocketTimeline []byte, websocketTimelineSource *logging.FileBodySource, apiRequestBody []byte, apiRequestSource *logging.FileBodySource, apiResponseBody []byte, apiResponseSource *logging.FileBodySource, apiWebsocketTimeline []byte, apiWebsocketTimelineSource *logging.FileBodySource, apiResponseTimestamp time.Time, apiResponseErrors []*interfaces.ErrorMessage, forceLog bool) error {
	if w.requestInfo == nil {
		cleanupFileBodySources(websocketTimelineSource, apiRequestSource, apiResponseSource, apiWebsocketTimelineSource)
		return nil
	}

	if loggerWithAllSources, ok := w.logger.(interface {
		LogRequestWithOptionsAndAllSources(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []byte, *logging.FileBodySource, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		return loggerWithAllSources.LogRequestWithOptionsAndAllSources(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			requestBody,
			statusCode,
			headers,
			body,
			websocketTimeline,
			websocketTimelineSource,
			apiRequestBody,
			apiRequestSource,
			apiResponseBody,
			apiResponseSource,
			apiWebsocketTimeline,
			apiWebsocketTimelineSource,
			apiResponseErrors,
			forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			apiResponseTimestamp,
		)
	}

	if loggerWithSources, ok := w.logger.(interface {
		LogRequestWithOptionsAndSources(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, *logging.FileBodySource, []byte, []byte, []byte, *logging.FileBodySource, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		var errMerge error
		apiRequestBody, errMerge = mergeFileBodySource(apiRequestBody, apiRequestSource)
		if errMerge != nil {
			cleanupFileBodySources(websocketTimelineSource, apiResponseSource, apiWebsocketTimelineSource)
			return errMerge
		}
		apiResponseBody, errMerge = mergeFileBodySource(apiResponseBody, apiResponseSource)
		if errMerge != nil {
			cleanupFileBodySources(websocketTimelineSource, apiWebsocketTimelineSource)
			return errMerge
		}
		return loggerWithSources.LogRequestWithOptionsAndSources(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			requestBody,
			statusCode,
			headers,
			body,
			websocketTimeline,
			websocketTimelineSource,
			apiRequestBody,
			apiResponseBody,
			apiWebsocketTimeline,
			apiWebsocketTimelineSource,
			apiResponseErrors,
			forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			apiResponseTimestamp,
		)
	}

	var errMerge error
	websocketTimeline, errMerge = mergeFileBodySource(websocketTimeline, websocketTimelineSource)
	if errMerge != nil {
		cleanupFileBodySources(apiRequestSource, apiResponseSource, apiWebsocketTimelineSource)
		return errMerge
	}
	apiRequestBody, errMerge = mergeFileBodySource(apiRequestBody, apiRequestSource)
	if errMerge != nil {
		cleanupFileBodySources(apiResponseSource, apiWebsocketTimelineSource)
		return errMerge
	}
	apiResponseBody, errMerge = mergeFileBodySource(apiResponseBody, apiResponseSource)
	if errMerge != nil {
		cleanupFileBodySources(apiWebsocketTimelineSource)
		return errMerge
	}
	apiWebsocketTimeline, errMerge = mergeFileBodySource(apiWebsocketTimeline, apiWebsocketTimelineSource)
	if errMerge != nil {
		return errMerge
	}

	if loggerWithOptions, ok := w.logger.(interface {
		LogRequestWithOptions(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, []byte, []byte, []byte, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		return loggerWithOptions.LogRequestWithOptions(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			requestBody,
			statusCode,
			headers,
			body,
			websocketTimeline,
			apiRequestBody,
			apiResponseBody,
			apiWebsocketTimeline,
			apiResponseErrors,
			forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			apiResponseTimestamp,
		)
	}

	return w.logger.LogRequest(
		w.requestInfo.URL,
		w.requestInfo.Method,
		w.requestInfo.Headers,
		requestBody,
		statusCode,
		headers,
		body,
		websocketTimeline,
		apiRequestBody,
		apiResponseBody,
		apiWebsocketTimeline,
		apiResponseErrors,
		w.requestInfo.RequestID,
		w.requestInfo.Timestamp,
		apiResponseTimestamp,
	)
}

func mergeFileBodySource(payload []byte, source *logging.FileBodySource) ([]byte, error) {
	if source == nil {
		return payload, nil
	}
	defer cleanupFileBodySources(source)
	if !source.HasPayload() {
		return payload, nil
	}
	var buf bytes.Buffer
	if len(payload) > 0 {
		buf.Write(payload)
		if !bytes.HasSuffix(payload, []byte("\n")) {
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')
	}
	if errWrite := source.WriteTo(&buf); errWrite != nil {
		return nil, errWrite
	}
	return buf.Bytes(), nil
}

func cleanupFileBodySources(sources ...*logging.FileBodySource) {
	for _, source := range sources {
		if source == nil {
			continue
		}
		if errCleanup := source.Cleanup(); errCleanup != nil {
			log.WithError(errCleanup).Warn("failed to clean up log part files")
		}
	}
}
