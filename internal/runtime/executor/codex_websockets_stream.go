package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

func (e *CodexWebsocketsExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	log.Debugf("Executing Codex Websockets stream request with auth ID: %s, model: %s", auth.ID, req.Model)
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "streaming not supported for /responses/compact"}
	}

	baseModel := thinking.ParseSuffix(req.Model).ModelName
	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FromString("codex")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated, body := translateCodexRequestPair(from, to, baseModel, originalPayload, req.Payload, true)

	body, err = helps.ApplyRequestThinking(body, req, opts, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	body = helps.SetStringIfDifferent(body, "model", baseModel)
	body = normalizeCodexInstructions(body)
	if e.cfg == nil || e.cfg.DisableImageGeneration == config.DisableImageGenerationOff {
		body = ensureImageGenerationTool(body, baseModel, auth, opts.Headers)
	}
	body = injectCodexTailBurstTool(body, baseModel, opts, e.cfg, opts.Headers)
	body = sanitizeOpenAIResponsesReasoningEncryptedContent(ctx, "codex websockets executor", body)
	body = normalizeCodexWebsocketParallelToolCalls(body, opts.Headers)
	body, optimizeMultiAgentV2 := helps.OptimizeCodexMultiAgentV2RequestForAuth(ctx, opts.Headers, body, e.cfg, auth, baseModel)
	body, replayScope, errReplay := applyCodexReasoningReplayCacheRequired(ctx, from, req, opts, body)
	if errReplay != nil {
		return nil, errReplay
	}

	httpURL := strings.TrimSuffix(baseURL, "/") + "/responses"
	wsURL, err := buildCodexResponsesWebsocketURL(httpURL)
	if err != nil {
		return nil, err
	}

	body, wsHeaders, errPromptCache := applyCodexPromptCacheHeadersWithConfig(ctx, e.cfg, from, req, body, opts.Headers)
	if errPromptCache != nil {
		return nil, errPromptCache
	}
	body, wsHeaders = applyCodexAppServerFingerprint(body, wsHeaders, req.Metadata)
	clientBody := body
	var identityState codexIdentityConfuseState
	upstreamBody, identityState := applyCodexIdentityConfuseBody(e.cfg, auth, originalPayloadSource, body)
	reporter.SetTranslatedReasoningEffort(clientBody, to.String())
	authClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	authorization, agentTaskID, errAuthorization := helps.PrepareCodexAuthorization(ctx, auth, authClient, apiKey)
	if errAuthorization != nil {
		return nil, errAuthorization
	}
	wsHeaders = applyCodexWebsocketHeaders(ctx, wsHeaders, auth, authorization, e.cfg)
	applyModelHeaderOverrides(wsHeaders, baseModel)
	applyCodexIdentityConfuseHeaders(wsHeaders, &identityState)

	var authID, authLabel, authType, authValue string
	authID = auth.ID
	authLabel = auth.Label
	authType, authValue = auth.AccountInfo()

	executionSessionID := executionSessionIDFromOptions(opts)
	parallelPoolKey := codexStatelessWebsocketPoolKey(auth, e.cfg, authID, wsURL, opts.Metadata)
	sess, streamSessionLocked := e.tryAcquireExecutionSession(executionSessionID)
	if executionSessionID != "" && !streamSessionLocked {
		// One logical execution session may use several physical upstream slots;
		// a busy primary borrows a hot standby instead of queueing.
		sess, streamSessionLocked = e.acquireStatelessSession(parallelPoolKey, codexWebsocketPoolSlots(e.cfg))
	} else if executionSessionID == "" && !cliproxyexecutor.DownstreamWebsocket(ctx) {
		// Plain HTTP SSE requests reuse authenticated upstream WebSocket slots.
		sess, streamSessionLocked = e.acquireStatelessSession(parallelPoolKey, codexWebsocketPoolSlots(e.cfg))
	}
	unlockStreamSession := func() {
		if sess != nil && streamSessionLocked {
			streamSessionLocked = false
			sess.reqMu.Unlock()
		}
	}

	wsReqBody := buildCodexWebsocketRequestBody(upstreamBody)
	wsReqLog := helps.UpstreamRequestLog{
		URL:       wsURL,
		Method:    "WEBSOCKET",
		Headers:   wsHeaders.Clone(),
		Body:      wsReqBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	}
	helps.RecordAPIWebsocketRequest(ctx, e.cfg, wsReqLog)

	var conn *websocket.Conn
	var closer *websocketConnectionCloser
	var respHS *http.Response
	var errDial error
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		conn, closer = existingWebsocketSessionConn(sess, authID, wsURL)
		if conn == nil {
			if sess != nil {
				unlockStreamSession()
			}
			return nil, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
		}
	} else {
		conn, closer, respHS, errDial = e.ensureUpstreamConnWithAgentRecovery(ctx, auth, sess, authID, wsURL, wsHeaders, authClient, agentTaskID)
	}
	var upstreamHeaders http.Header
	if respHS != nil {
		upstreamHeaders = respHS.Header.Clone()
	}
	if errDial != nil {
		bodyErr := websocketHandshakeBody(respHS)
		if respHS != nil {
			helps.RecordAPIWebsocketUpgradeRejection(ctx, e.cfg, websocketUpgradeRequestLog(wsReqLog), respHS.StatusCode, respHS.Header.Clone(), bodyErr)
		}
		if respHS != nil && respHS.StatusCode == http.StatusUpgradeRequired {
			if sess != nil {
				unlockStreamSession()
			}
			if opts.ExecutionLifecycle != nil || cliproxyexecutor.DownstreamWebsocket(ctx) {
				return nil, statusErr{code: respHS.StatusCode, msg: string(bodyErr)}
			}
			return e.CodexExecutor.ExecuteStream(ctx, auth, req, opts)
		}
		if respHS != nil && respHS.StatusCode > 0 {
			if sess != nil {
				unlockStreamSession()
			}
			return nil, statusErr{code: respHS.StatusCode, msg: string(bodyErr)}
		}
		helps.RecordAPIWebsocketError(ctx, e.cfg, "dial", errDial)
		if sess != nil {
			unlockStreamSession()
		}
		return nil, errDial
	}
	if errBind := sess.bindExecutionLifecycle(opts, conn, closer, req.Model); errBind != nil {
		if sess != nil {
			unlockStreamSession()
		}
		closeWebsocketAfterBindFailure(sess, conn, closer)
		return nil, errBind
	}
	recordAPIWebsocketHandshake(ctx, e.cfg, respHS)
	reporter.StartResponseTTFT()

	if sess == nil {
		logCodexWebsocketConnected(executionSessionID, authID, wsURL)
	}

	var readCh chan codexWebsocketRead
	if sess != nil {
		readCh = sess.activate(conn)
	}

	if errSend := writeCodexWebsocketMessage(sess, conn, wsReqBody); errSend != nil {
		errSend = mapCodexWebsocketWriteError(sess, conn, errSend)
		helps.RecordAPIWebsocketError(ctx, e.cfg, "send", errSend)
		if sess != nil {
			if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
				e.invalidateUpstreamConnWithoutDisconnectNotify(sess, conn, "send_error", errSend)
				sess.clearActive(conn, readCh)
				unlockStreamSession()
				if !shouldRetryCodexWebsocketSend(errSend) {
					return nil, errSend
				}
				return nil, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
			}
			e.invalidateUpstreamConn(sess, conn, "send_error", errSend)
			if !shouldRetryCodexWebsocketSend(errSend) {
				sess.clearActive(conn, readCh)
				unlockStreamSession()
				return nil, errSend
			}

			// Retry once with a new websocket connection for the same execution session.
			connRetry, closerRetry, respHSRetry, errDialRetry := e.ensureUpstreamConn(ctx, auth, sess, authID, wsURL, wsHeaders)
			if errDialRetry != nil || connRetry == nil {
				closeHTTPResponseBody(respHSRetry, "codex websockets executor: close handshake response body error")
				helps.RecordAPIWebsocketError(ctx, e.cfg, "dial_retry", errDialRetry)
				sess.clearActive(conn, readCh)
				unlockStreamSession()
				return nil, errDialRetry
			}
			previousConn, previousReadCh := conn, readCh
			conn = connRetry
			closer = closerRetry
			if errBind := sess.bindExecutionLifecycle(opts, conn, closer, req.Model); errBind != nil {
				clearRetryActiveState(sess, previousConn, previousReadCh)
				unlockStreamSession()
				closeWebsocketAfterBindFailure(sess, conn, closer)
				return nil, errBind
			}
			readCh = sess.activate(conn)
			wsReqBodyRetry := buildCodexWebsocketRequestBody(upstreamBody)
			helps.RecordAPIWebsocketRequest(ctx, e.cfg, helps.UpstreamRequestLog{
				URL:       wsURL,
				Method:    "WEBSOCKET",
				Headers:   wsHeaders.Clone(),
				Body:      wsReqBodyRetry,
				Provider:  e.Identifier(),
				AuthID:    authID,
				AuthLabel: authLabel,
				AuthType:  authType,
				AuthValue: authValue,
			})
			recordAPIWebsocketHandshake(ctx, e.cfg, respHSRetry)
			reporter.StartResponseTTFT()
			if errSendRetry := writeCodexWebsocketMessage(sess, conn, wsReqBodyRetry); errSendRetry != nil {
				errSendRetry = mapCodexWebsocketWriteError(sess, conn, errSendRetry)
				helps.RecordAPIWebsocketError(ctx, e.cfg, "send_retry", errSendRetry)
				e.invalidateUpstreamConn(sess, conn, "send_error", errSendRetry)
				sess.clearActive(conn, readCh)
				unlockStreamSession()
				return nil, errSendRetry
			}
			wsReqBody = wsReqBodyRetry
		} else {
			logCodexWebsocketDisconnected(executionSessionID, authID, wsURL, "send_error", errSend)
			if errClose := closer.Close(); errClose != nil {
				log.Errorf("codex websockets executor: close websocket error: %v", errClose)
			}
			return nil, errSend
		}
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		terminateReason := "completed"
		var terminateErr error
		requestCompleted := false

		defer close(out)
		defer func() {
			if sess != nil {
				if !requestCompleted {
					incompleteErr := terminateErr
					if incompleteErr == nil {
						incompleteErr = errors.New("codex websockets executor: request ended before terminal response")
					}
					e.invalidateUpstreamConn(sess, conn, "request_incomplete", incompleteErr)
				}
				sess.clearActive(conn, readCh)
				unlockStreamSession()
				return
			}
			logCodexWebsocketDisconnected(executionSessionID, authID, wsURL, terminateReason, terminateErr)
			if errClose := closer.Close(); errClose != nil {
				log.Errorf("codex websockets executor: close websocket error: %v", errClose)
			}
		}()

		send := func(chunk cliproxyexecutor.StreamChunk) bool {
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

		claudeInputTokens := helps.NewClaudeInputTokenState(from, to, responseFormat, originalPayload)
		var param any
		outputItemsByIndex := make(map[int64][]byte)
		var outputItemsFallback [][]byte
		outputText := &codexOutputTextAccumulator{}
		responseScope := &codexWebsocketResponseScope{}
		parallelPrewarmStarted := false
		for {
			if ctx != nil && ctx.Err() != nil {
				terminateReason = "context_done"
				terminateErr = ctx.Err()
				_ = send(cliproxyexecutor.StreamChunk{Err: ctx.Err()})
				return
			}
			msgType, payload, errRead := readCodexWebsocketMessage(ctx, sess, conn, readCh)
			if errRead != nil {
				if sess != nil && ctx != nil && ctx.Err() != nil {
					terminateReason = "context_done"
					terminateErr = ctx.Err()
					_ = send(cliproxyexecutor.StreamChunk{Err: ctx.Err()})
					return
				}
				mappedErr := mapCodexWebsocketReadError(errRead)
				if isCodexWebsocketTransientReadError(errRead) {
					if recoveredPayload := buildCodexSyntheticWebsocketCompleted(baseModel, responseScope, outputItemsByIndex, outputItemsFallback, outputText); len(recoveredPayload) > 0 {
						requestCompleted = true
						terminateReason = "recovered_disconnect"
						terminateErr = mappedErr
						helps.RecordAPIWebsocketError(ctx, e.cfg, "read_recovered", mappedErr)
						clientPayload := applyCodexIdentityExposeResponsePayload(recoveredPayload, identityState)
						if cliproxyexecutor.DownstreamWebsocket(ctx) {
							_ = send(cliproxyexecutor.StreamChunk{Payload: clientPayload})
							return
						}
						line := encodeCodexWebsocketAsSSE(clientPayload)
						chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, clientBody, line, &param, claudeInputTokens)
						for i := range chunks {
							if !send(cliproxyexecutor.StreamChunk{Payload: chunks[i]}) {
								terminateReason = "context_done"
								terminateErr = ctx.Err()
								return
							}
						}
						return
					}
				}
				terminateReason = "read_error"
				terminateErr = mappedErr
				helps.RecordAPIWebsocketError(ctx, e.cfg, "read", mappedErr)
				reporter.PublishFailure(ctx, mappedErr)
				_ = send(cliproxyexecutor.StreamChunk{Err: mappedErr})
				return
			}
			if msgType != websocket.TextMessage {
				if msgType == websocket.BinaryMessage {
					err = fmt.Errorf("codex websockets executor: unexpected binary message")
					terminateReason = "unexpected_binary"
					terminateErr = err
					helps.RecordAPIWebsocketError(ctx, e.cfg, "unexpected_binary", err)
					reporter.PublishFailure(ctx, err)
					if sess != nil {
						e.invalidateUpstreamConn(sess, conn, "unexpected_binary", err)
					}
					_ = send(cliproxyexecutor.StreamChunk{Err: err})
					return
				}
				continue
			}

			payload = bytes.TrimSpace(payload)
			if len(payload) == 0 {
				continue
			}
			if sess != nil {
				if !sess.acceptResponsePayload(payload, responseScope) {
					continue
				}
			} else {
				collectCodexWebsocketResponseScope(payload, responseScope)
			}
			reporter.MarkFirstResponseByte()
			payload = applyCodexIdentityConfuseResponsePayload(payload, identityState)
			helps.AppendAPIWebsocketResponse(ctx, e.cfg, payload)
			payload = helps.RestoreCodexMultiAgentV2Response(payload, optimizeMultiAgentV2)

			if wsErr, ok := parseCodexWebsocketError(payload); ok {
				terminateReason = "upstream_error"
				terminateErr = wsErr
				if sess != nil {
					e.invalidateUpstreamConn(sess, conn, "upstream_error", wsErr)
				}
				if errClearReplay := clearCodexReasoningReplayOnWebsocketError(ctx, replayScope, payload); errClearReplay != nil {
					terminateErr = errClearReplay
					helps.RecordAPIWebsocketError(ctx, e.cfg, "replay_clear_error", errClearReplay)
					reporter.PublishFailure(ctx, errClearReplay)
					_ = send(cliproxyexecutor.StreamChunk{Err: errClearReplay})
					return
				}
				helps.RecordAPIWebsocketError(ctx, e.cfg, "upstream_error", wsErr)
				reporter.PublishFailure(ctx, wsErr)
				_ = send(cliproxyexecutor.StreamChunk{Err: wsErr})
				return
			}
			if streamErr, terminalBody, ok := codexTerminalFailureErr(payload); ok {
				terminateReason = "upstream_error"
				terminateErr = streamErr
				if sess != nil {
					unlockStreamSession()
					e.invalidateUpstreamConn(sess, conn, "terminal_failure", streamErr)
				}
				if errClearReplay := clearCodexReasoningReplayOnInvalidSignature(ctx, replayScope, streamErr.StatusCode(), terminalBody); errClearReplay != nil {
					terminateErr = errClearReplay
					helps.RecordAPIWebsocketError(ctx, e.cfg, "replay_clear_error", errClearReplay)
					reporter.PublishFailure(ctx, errClearReplay)
					_ = send(cliproxyexecutor.StreamChunk{Err: errClearReplay})
					return
				}
				helps.RecordAPIWebsocketError(ctx, e.cfg, "upstream_error", streamErr)
				reporter.PublishFailure(ctx, streamErr)
				_ = send(cliproxyexecutor.StreamChunk{Err: streamErr})
				return
			}
			if !parallelPrewarmStarted && executionSessionID != "" && opts.ExecutionLifecycle == nil {
				parallelPrewarmStarted = true
				e.prewarmParallelSessions(auth, parallelPoolKey, authID, wsURL, wsHeaders)
			}

			eventType := gjson.GetBytes(payload, "type").String()
			collectCodexOutputTextEvent(payload, outputText)
			isTerminalEvent := eventType == "response.completed" || eventType == "response.done" || eventType == "error"
			if eventType == "response.completed" || eventType == "response.done" {
				requestCompleted = true
			}
			if eventType == "response.output_item.done" {
				collectCodexOutputItemDone(payload, outputItemsByIndex, &outputItemsFallback)
			}
			completedPayload := payload
			if eventType == "response.completed" || eventType == "response.done" {
				completedPayload = normalizeCodexWebsocketCompletion(completedPayload)
				completedPayload = patchCodexCompletedOutputWithText(completedPayload, outputItemsByIndex, outputItemsFallback, outputText)
				cacheCodexReasoningReplayFromCompleted(replayScope, completedPayload)
				if detail, ok := helps.ParseCodexUsage(completedPayload); ok {
					reporter.Publish(ctx, detail)
				}
			}

			downstreamPayload := payload
			if eventType == "response.completed" || eventType == "response.done" {
				downstreamPayload = completedPayload
			}
			clientPayload := applyCodexIdentityExposeResponsePayload(downstreamPayload, identityState)
			if cliproxyexecutor.DownstreamWebsocket(ctx) {
				if !send(cliproxyexecutor.StreamChunk{Payload: clientPayload}) {
					terminateReason = "context_done"
					terminateErr = ctx.Err()
					return
				}
				if isTerminalEvent {
					return
				}
				continue
			}

			payload = normalizeCodexWebsocketCompletion(payload)
			if eventType == "response.completed" || eventType == "response.done" {
				payload = completedPayload
			}
			eventType = gjson.GetBytes(payload, "type").String()
			clientPayload = applyCodexIdentityExposeResponsePayload(payload, identityState)
			line := encodeCodexWebsocketAsSSE(clientPayload)
			chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, clientBody, line, &param, claudeInputTokens)
			for i := range chunks {
				if !send(cliproxyexecutor.StreamChunk{Payload: chunks[i]}) {
					terminateReason = "context_done"
					terminateErr = ctx.Err()
					return
				}
			}
			if eventType == "response.completed" || eventType == "response.done" {
				return
			}
		}
	}()

	return &cliproxyexecutor.StreamResult{Headers: upstreamHeaders, Chunks: out}, nil
}
