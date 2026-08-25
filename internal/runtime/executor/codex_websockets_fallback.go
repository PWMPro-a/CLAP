package executor

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	codexWebsocketFallbackExecutorType       = "CodexWebsocketFallbackExecutor"
	codexWebsocketMessageTooBigAdaptiveTTL   = time.Hour
	codexWebsocketMessageTooBigAdaptiveFloor = 512 * 1024
)

type codexWebsocketMessageTooBigAdaptiveLimit struct {
	bytes     int
	expiresAt time.Time
}

var codexWebsocketMessageTooBigAdaptiveLimits sync.Map

func codexWebsocketFallbackContext(ctx context.Context) context.Context {
	return helps.WithUsageExecutorType(ctx, codexWebsocketFallbackExecutorType)
}

func codexRequestApproxBytes(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) int {
	requestBytes := len(req.Payload)
	if len(opts.OriginalRequest) > requestBytes {
		requestBytes = len(opts.OriginalRequest)
	}
	return requestBytes
}

func codexWebsocketAdaptiveMessageTooBigSkip(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	requestBytes := codexRequestApproxBytes(req, opts)
	if requestBytes < codexWebsocketMessageTooBigAdaptiveFloor {
		return false
	}
	key := codexWebsocketMessageTooBigAdaptiveKey(auth)
	now := time.Now()
	raw, ok := codexWebsocketMessageTooBigAdaptiveLimits.Load(key)
	if !ok {
		return false
	}
	limit, ok := raw.(codexWebsocketMessageTooBigAdaptiveLimit)
	if !ok || !limit.expiresAt.After(now) {
		codexWebsocketMessageTooBigAdaptiveLimits.Delete(key)
		return false
	}
	return limit.bytes > 0 && requestBytes >= limit.bytes
}

func codexRecordWebsocketMessageTooBig(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) {
	requestBytes := codexRequestApproxBytes(req, opts)
	if requestBytes < codexWebsocketMessageTooBigAdaptiveFloor {
		return
	}
	key := codexWebsocketMessageTooBigAdaptiveKey(auth)
	limitBytes := requestBytes - requestBytes/20
	if limitBytes < codexWebsocketMessageTooBigAdaptiveFloor {
		limitBytes = codexWebsocketMessageTooBigAdaptiveFloor
	}
	now := time.Now()
	next := codexWebsocketMessageTooBigAdaptiveLimit{
		bytes:     limitBytes,
		expiresAt: now.Add(codexWebsocketMessageTooBigAdaptiveTTL),
	}
	if raw, ok := codexWebsocketMessageTooBigAdaptiveLimits.Load(key); ok {
		if current, ok := raw.(codexWebsocketMessageTooBigAdaptiveLimit); ok && current.expiresAt.After(now) && current.bytes > 0 && current.bytes <= limitBytes {
			next.bytes = current.bytes
		}
	}
	codexWebsocketMessageTooBigAdaptiveLimits.Store(key, next)
}

func codexWebsocketMessageTooBigAdaptiveKey(auth *cliproxyauth.Auth) string {
	_, baseURL := codexCreds(auth)
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}
	return strings.TrimRight(baseURL, "/")
}
