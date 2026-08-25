// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements a Codex executor that uses the Responses API WebSocket transport.
package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const codexWebsocketDefaultSafeRequestBytes = 0

// CodexWebsocketsExecutor executes Codex Responses requests using a WebSocket transport.
//
// It preserves the existing CodexExecutor HTTP implementation as a fallback for endpoints
// not available over WebSocket (e.g. /responses/compact) and for websocket upgrade failures.
type CodexWebsocketsExecutor struct {
	*CodexExecutor

	store *codexWebsocketSessionStore
}

func NewCodexWebsocketsExecutor(cfg *config.Config) *CodexWebsocketsExecutor {
	return &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(cfg),
		store:         globalCodexWebsocketSessionStore,
	}
}

// CodexAutoExecutor routes Codex stream requests to the websocket transport
// whenever the selected auth enables websockets. Plain HTTP/SSE callers reuse
// upstream websocket slots too, then keep the downstream response as SSE.
type CodexAutoExecutor struct {
	httpExec *CodexExecutor
	wsExec   *CodexWebsocketsExecutor
}

func NewCodexAutoExecutor(cfg *config.Config) *CodexAutoExecutor {
	return &CodexAutoExecutor{
		httpExec: NewCodexExecutor(cfg),
		wsExec:   NewCodexWebsocketsExecutor(cfg),
	}
}

func (e *CodexAutoExecutor) Identifier() string { return "codex" }

func (e *CodexAutoExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if e == nil || e.httpExec == nil {
		return nil
	}
	return e.httpExec.PrepareRequest(req, auth)
}

func (e *CodexAutoExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.HttpRequest(ctx, auth, req)
}

func (e *CodexAutoExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpExec == nil || e.wsExec == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: executor is nil")
	}
	if cliproxyexecutor.DownstreamWebsocket(ctx) && codexWebsocketsEnabled(auth) {
		return e.wsExec.Execute(ctx, auth, req, opts)
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return cliproxyexecutor.Response{}, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	return e.httpExec.Execute(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e == nil || e.httpExec == nil || e.wsExec == nil {
		return nil, fmt.Errorf("codex auto executor: executor is nil")
	}
	if codexWebsocketStreamEnabled(e.codexConfig(), ctx, auth, req, opts) {
		result, errStream := e.wsExec.ExecuteStream(ctx, auth, req, opts)
		if errStream != nil {
			if codexPlainHTTPWebsocketFallbackAllowed(ctx, opts) && isCodexWebsocketHTTPFallbackError(errStream) {
				return e.httpExec.ExecuteStream(ctx, auth, req, opts)
			}
			return result, errStream
		}
		if codexPlainHTTPWebsocketFallbackAllowed(ctx, opts) {
			return e.maybeFallbackPlainHTTPWebsocketBootstrap(ctx, result, auth, req, opts)
		}
		return result, nil
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return nil, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	return e.httpExec.ExecuteStream(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) codexConfig() *config.Config {
	if e == nil {
		return nil
	}
	if e.wsExec != nil && e.wsExec.CodexExecutor != nil {
		return e.wsExec.CodexExecutor.cfg
	}
	if e.httpExec != nil {
		return e.httpExec.cfg
	}
	return nil
}

func codexWebsocketStreamEnabled(cfg *config.Config, ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	if !codexWebsocketsEnabled(auth) || opts.Alt == "responses/compact" {
		return false
	}
	// Multipart/direct image traffic remains on the dedicated HTTP adapter.
	if isCodexOpenAIImageRequest(opts) {
		return false
	}
	// Very large JSON messages may be rejected by the upstream websocket endpoint
	// with close code 1009. By default no local size precheck is applied: plain
	// HTTP/SSE calls try the fast websocket path first and fall back only after a
	// concrete upstream message-too-big bootstrap error. Operators can still set
	// websocket-safe-request-bytes to a positive value for an environment-specific
	// precheck.
	if !cliproxyexecutor.DownstreamWebsocket(ctx) && !cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		requestBytes := len(req.Payload)
		if len(opts.OriginalRequest) > requestBytes {
			requestBytes = len(opts.OriginalRequest)
		}
		if limit := codexWebsocketSafeRequestBytes(cfg); limit > 0 && requestBytes > limit {
			return false
		}
	}
	return true
}

func codexWebsocketSafeRequestBytes(cfg *config.Config) int {
	if cfg != nil && cfg.Codex.CacheAffinity.WebsocketSafeRequestBytes > 0 {
		return cfg.Codex.CacheAffinity.WebsocketSafeRequestBytes
	}
	return codexWebsocketDefaultSafeRequestBytes
}

func (e *CodexAutoExecutor) maybeFallbackPlainHTTPWebsocketBootstrap(ctx context.Context, result *cliproxyexecutor.StreamResult, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if result == nil || result.Chunks == nil {
		return result, nil
	}
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	for {
		var (
			chunk cliproxyexecutor.StreamChunk
			ok    bool
		)
		if ctx != nil {
			select {
			case <-ctx.Done():
				codexDiscardStreamChunks(result.Chunks)
				return nil, ctx.Err()
			case chunk, ok = <-result.Chunks:
			}
		} else {
			chunk, ok = <-result.Chunks
		}
		if !ok {
			return codexBufferedStreamResult(ctx, result.Headers, buffered, nil), nil
		}
		if chunk.Err != nil {
			codexDiscardStreamChunks(result.Chunks)
			if isCodexWebsocketHTTPFallbackError(chunk.Err) {
				return e.httpExec.ExecuteStream(ctx, auth, req, opts)
			}
			return codexStreamErrorResult(result.Headers, chunk.Err), nil
		}
		buffered = append(buffered, chunk)
		if len(chunk.Payload) > 0 {
			return codexBufferedStreamResult(ctx, result.Headers, buffered, result.Chunks), nil
		}
	}
}

func codexDiscardStreamChunks(ch <-chan cliproxyexecutor.StreamChunk) {
	if ch == nil {
		return
	}
	go func() {
		for range ch {
		}
	}()
}

func codexStreamErrorResult(headers http.Header, err error) *cliproxyexecutor.StreamResult {
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: err}
	close(ch)
	return &cliproxyexecutor.StreamResult{
		Headers: cloneCodexHTTPHeader(headers),
		Chunks:  ch,
	}
}

func codexBufferedStreamResult(ctx context.Context, headers http.Header, buffered []cliproxyexecutor.StreamChunk, remaining <-chan cliproxyexecutor.StreamChunk) *cliproxyexecutor.StreamResult {
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		for _, chunk := range buffered {
			if !codexSendStreamChunk(ctx, out, chunk) {
				codexDiscardStreamChunks(remaining)
				return
			}
		}
		for chunk := range remaining {
			if !codexSendStreamChunk(ctx, out, chunk) {
				codexDiscardStreamChunks(remaining)
				return
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{
		Headers: cloneCodexHTTPHeader(headers),
		Chunks:  out,
	}
}

func codexSendStreamChunk(ctx context.Context, out chan<- cliproxyexecutor.StreamChunk, chunk cliproxyexecutor.StreamChunk) bool {
	if ctx == nil {
		out <- chunk
		return true
	}
	select {
	case out <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func cloneCodexHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func codexPlainHTTPWebsocketFallbackAllowed(ctx context.Context, opts cliproxyexecutor.Options) bool {
	return !cliproxyexecutor.DownstreamWebsocket(ctx) &&
		!cliproxyexecutor.RequiredUpstreamWebsocket(ctx) &&
		opts.ExecutionLifecycle == nil
}

func isCodexWebsocketHTTPFallbackError(err error) bool {
	if err == nil {
		return false
	}
	var tooBig codexWebsocketMessageTooBigError
	if errors.As(err, &tooBig) {
		return true
	}
	type statusCoder interface {
		StatusCode() int
	}
	var sc statusCoder
	return errors.As(err, &sc) && sc != nil && sc.StatusCode() == http.StatusRequestEntityTooLarge && strings.Contains(strings.ToLower(err.Error()), "message_too_big")
}

func (e *CodexAutoExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.Refresh(ctx, auth)
}

func (e *CodexAutoExecutor) RefreshQuota(ctx context.Context, auth *cliproxyauth.Auth) (cliproxyauth.CodexQuotaSnapshot, error) {
	if e == nil || e.httpExec == nil {
		return cliproxyauth.CodexQuotaSnapshot{}, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.RefreshQuota(ctx, auth)
}

func (e *CodexAutoExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpExec == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.CountTokens(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) CloseExecutionSession(sessionID string) {
	if e == nil || e.wsExec == nil {
		return
	}
	e.wsExec.CloseExecutionSession(sessionID)
}

func (e *CodexAutoExecutor) CloseExecutionSessionsForAuthID(authID string, reason string) {
	if e == nil || e.wsExec == nil {
		return
	}
	e.wsExec.CloseExecutionSessionsForAuthID(authID, reason)
}

func (e *CodexAutoExecutor) UpstreamDisconnectChan(sessionID string) <-chan error {
	if e == nil || e.wsExec == nil {
		return nil
	}
	return e.wsExec.UpstreamDisconnectChan(sessionID)
}

func codexWebsocketsEnabled(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}
