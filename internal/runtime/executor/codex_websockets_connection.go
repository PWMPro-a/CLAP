package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/sjson"
)

func (e *CodexWebsocketsExecutor) ensureUpstreamConnWithAgentRecovery(
	ctx context.Context,
	auth *cliproxyauth.Auth,
	sess *codexWebsocketSession,
	authID string,
	wsURL string,
	headers http.Header,
	authClient *http.Client,
	staleTaskID string,
) (*websocket.Conn, *websocketConnectionCloser, *http.Response, error) {
	conn, closer, resp, errDial := e.ensureUpstreamConn(ctx, auth, sess, authID, wsURL, headers)
	if errDial == nil {
		return conn, closer, resp, nil
	}
	runtime, isAgentIdentity := helps.CodexAgentIdentityRuntime(auth)
	if !isAgentIdentity || resp == nil {
		return conn, closer, resp, errDial
	}
	body := websocketHandshakeBody(resp)
	if codexauth.IsAgentIdentityRuntimeDeletedResponse(resp.StatusCode, body) {
		runtime.MarkRuntimeDeleted()
		return conn, closer, restoreWebsocketHandshakeBody(resp, runtime.RedactSensitiveBody(body)), errDial
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return conn, closer, restoreWebsocketHandshakeBody(resp, runtime.RedactSensitiveBody(body)), errDial
	}
	if !codexauth.IsAgentIdentityTaskInvalidResponse(resp.StatusCode, body) {
		return conn, closer, restoreWebsocketHandshakeBody(resp, runtime.RedactSensitiveBody(body)), errDial
	}
	authorization, errRecover := runtime.RecoverAuthorization(ctx, authClient, staleTaskID)
	if errRecover != nil {
		return nil, nil, nil, fmt.Errorf("recover codex websocket agent identity task: %w", errRecover)
	}
	setCodexAuthorizationHeader(headers, authorization)
	conn, closer, resp, errDial = e.ensureUpstreamConn(ctx, auth, sess, authID, wsURL, headers)
	if errDial == nil || resp == nil || resp.Body == nil {
		return conn, closer, resp, errDial
	}
	body = websocketHandshakeBody(resp)
	return conn, closer, restoreWebsocketHandshakeBody(resp, runtime.RedactSensitiveBody(body)), errDial
}

func restoreWebsocketHandshakeBody(resp *http.Response, body []byte) *http.Response {
	if resp == nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if resp.Header != nil {
		resp.Header.Del("Content-Length")
	}
	return resp
}

const (
	codexResponsesWebsocketBetaHeaderValue = "responses_websockets=2026-02-06"
	codexResponsesWebsocketIdleTimeout     = 5 * time.Minute
	codexResponsesWebsocketHandshakeTO     = 30 * time.Second
)

func (e *CodexWebsocketsExecutor) dialCodexWebsocket(ctx context.Context, auth *cliproxyauth.Auth, wsURL string, headers http.Header) (*websocket.Conn, *websocketConnectionCloser, *http.Response, error) {
	dialer := newProxyAwareWebsocketDialer(e.cfg, auth)
	dialer.HandshakeTimeout = codexResponsesWebsocketHandshakeTO
	dialer.EnableCompression = true
	if ctx == nil {
		ctx = context.Background()
	}
	conn, resp, err := dialer.DialContext(ctx, wsURL, headers)
	closer := newWebsocketConnectionCloser(conn)
	if conn != nil {
		// Avoid gorilla/websocket flate tail validation issues on some upstreams/Go versions.
		// Negotiating permessage-deflate is fine; we just don't compress outbound messages.
		conn.EnableWriteCompression(false)
	}
	return conn, closer, resp, err
}

func writeCodexWebsocketMessage(sess *codexWebsocketSession, conn *websocket.Conn, payload []byte) error {
	if sess != nil {
		return sess.writeMessage(conn, websocket.TextMessage, payload)
	}
	if conn == nil {
		return fmt.Errorf("codex websockets executor: websocket conn is nil")
	}
	return conn.WriteMessage(websocket.TextMessage, payload)
}

func mapCodexWebsocketWriteError(sess *codexWebsocketSession, conn *websocket.Conn, err error) error {
	if err == nil || sess == nil || conn == nil {
		return err
	}
	upstreamErr := sess.upstreamDisconnectError(conn)
	var closeErr *websocket.CloseError
	if !errors.As(upstreamErr, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
		return err
	}
	return mapCodexWebsocketReadError(upstreamErr)
}

func shouldRetryCodexWebsocketSend(err error) bool {
	if err == nil {
		return false
	}
	var requestErr cliproxyexecutor.RequestScopedError
	return !errors.As(err, &requestErr) || !requestErr.IsRequestScoped()
}

type codexWebsocketMessageTooBigError struct {
	statusErr
}

func (codexWebsocketMessageTooBigError) IsRequestScoped() bool {
	return true
}

func mapCodexWebsocketReadError(err error) error {
	if err == nil {
		return nil
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) && closeErr.Code == websocket.CloseMessageTooBig {
		return codexWebsocketMessageTooBigError{statusErr: statusErr{
			code: http.StatusRequestEntityTooLarge,
			msg:  `{"error":{"message":"upstream websocket message too big","type":"invalid_request_error","code":"message_too_big"}}`,
		}}
	}
	if isCodexWebsocketTransientReadError(err) {
		return newCodexWebsocketTransientDisconnectError(err)
	}
	return err
}

func newCodexWebsocketTransientDisconnectError(err error) statusErr {
	message := "upstream websocket disconnected before response.completed"
	if err != nil {
		message += ": " + strings.TrimSpace(err.Error())
	}
	return statusErr{
		code: http.StatusBadGateway,
		msg:  fmt.Sprintf(`{"error":{"message":%s,"type":"server_error","code":"websocket_upstream_disconnected"}}`, strconv.Quote(message)),
	}
}

func isCodexWebsocketTransientReadError(err error) bool {
	if err == nil {
		return false
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case websocket.CloseAbnormalClosure, websocket.CloseServiceRestart, websocket.CloseTryAgainLater:
			return true
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	errText := strings.ToLower(strings.TrimSpace(err.Error()))
	for _, fragment := range []string{
		"websocket: close 1006", "websocket: close 1012", "websocket: close 1013",
		"unexpected eof", "i/o timeout", "connection reset by peer", "broken pipe", "use of closed network connection",
	} {
		if strings.Contains(errText, fragment) {
			return true
		}
	}
	return errText == "eof"
}

func normalizeCodexWebsocketParallelToolCalls(body []byte, headers http.Header) []byte {
	if !isCodexResponsesLiteRequest(body, headers) {
		return body
	}
	body = helps.SetBoolIfDifferent(body, "parallel_tool_calls", false)
	return body
}

func buildCodexWebsocketRequestBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}

	// Match codex-rs websocket v2 semantics: every request is `response.create`.
	// Incremental follow-up turns continue on the same websocket using
	// `previous_response_id` + incremental `input`, not `response.append`.
	body = helps.SanitizeCodexInputItemIDs(body)
	wsReqBody, errSet := sjson.SetBytes(body, "type", "response.create")
	if errSet == nil && len(wsReqBody) > 0 {
		return wsReqBody
	}
	return body
}

func readCodexWebsocketMessage(ctx context.Context, sess *codexWebsocketSession, conn *websocket.Conn, readCh chan codexWebsocketRead) (int, []byte, error) {
	if sess == nil {
		if conn == nil {
			return 0, nil, fmt.Errorf("codex websockets executor: websocket conn is nil")
		}
		_ = conn.SetReadDeadline(time.Now().Add(codexResponsesWebsocketIdleTimeout))
		msgType, payload, errRead := conn.ReadMessage()
		return msgType, payload, errRead
	}
	if conn == nil {
		return 0, nil, fmt.Errorf("codex websockets executor: websocket conn is nil")
	}
	if readCh == nil {
		return 0, nil, fmt.Errorf("codex websockets executor: session read channel is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case ev, ok := <-readCh:
			if !ok {
				return 0, nil, fmt.Errorf("codex websockets executor: session read channel closed")
			}
			if ev.conn != conn {
				continue
			}
			if ev.err != nil {
				return 0, nil, ev.err
			}
			return ev.msgType, ev.payload, nil
		}
	}
}

func newProxyAwareWebsocketDialer(cfg *config.Config, auth *cliproxyauth.Auth) *websocket.Dialer {
	dialer := &websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  codexResponsesWebsocketHandshakeTO,
		EnableCompression: true,
		NetDialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	proxyURL, sourceIP := helps.ResolveEgressSettings(cfg, auth)
	if proxyURL == "" && sourceIP == "" {
		return dialer
	}

	setting, errParse := proxyutil.Parse(proxyURL)
	if errParse != nil {
		log.Errorf("codex websockets executor: %v", errParse)
		return dialer
	}

	switch setting.Mode {
	case proxyutil.ModeDirect:
		dialer.Proxy = nil
		if sourceIP != "" {
			setWebsocketSourceDialer(dialer, proxyURL, sourceIP)
		}
		return dialer
	case proxyutil.ModeProxy:
	default:
		if sourceIP != "" {
			dialer.Proxy = nil
			setWebsocketSourceDialer(dialer, proxyURL, sourceIP)
		}
		return dialer
	}

	switch setting.URL.Scheme {
	case "socks5", "socks5h":
		proxyDialer, _, errBuild := proxyutil.BuildDialerWithSourceIP(proxyURL, sourceIP)
		if errBuild != nil {
			log.Errorf("codex websockets executor: create SOCKS dialer failed: %v", errBuild)
			return dialer
		}
		dialer.Proxy = nil
		dialer.NetDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			return proxyDialer.Dial(network, addr)
		}
	case "http", "https":
		dialer.Proxy = http.ProxyURL(setting.URL)
	default:
		log.Errorf("codex websockets executor: unsupported proxy scheme: %s", setting.URL.Scheme)
	}

	return dialer
}

func setWebsocketSourceDialer(dialer *websocket.Dialer, proxyURL string, sourceIP string) {
	if dialer == nil {
		return
	}
	sourceDialer, _, errBuild := proxyutil.BuildDialerWithSourceIP(proxyURL, sourceIP)
	if errBuild != nil {
		log.Errorf("codex websockets executor: create source IP dialer failed: %v", errBuild)
		return
	}
	if sourceDialer == nil {
		return
	}
	dialer.NetDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		return sourceDialer.Dial(network, addr)
	}
}

func buildCodexResponsesWebsocketURL(httpURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(httpURL))
	if err != nil {
		return "", err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("codex websockets executor: unsupported responses websocket URL scheme %q", parsed.Scheme)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("codex websockets executor: responses websocket URL host is empty")
	}
	return parsed.String(), nil
}
