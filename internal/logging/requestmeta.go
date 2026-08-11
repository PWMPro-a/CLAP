package logging

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
)

type endpointKey struct{}
type responseStatusKey struct{}
type responseHeadersKey struct{}
type clientRequestMetadataKey struct{}

// ClientRequestMetadata stores immutable downstream request metadata for asynchronous consumers.
type ClientRequestMetadata struct {
	ClientIP      string
	XForwardedFor string
	UserAgent     string
}

type responseStatusHolder struct {
	status atomic.Int32
}

type responseHeadersHolder struct {
	mu           sync.RWMutex
	headers      http.Header
	routingUsage atomic.Pointer[RoutingUsageMetadata]
}

// RoutingUsageMetadata is request-local diagnostic data emitted only to usage
// sinks. It is never added to downstream HTTP or SSE responses.
type RoutingUsageMetadata struct {
	AffinityOutcome      string
	SessionSource        string
	BindingGeneration    uint64
	QuotaUsedPercent     float64
	QuotaSnapshotPresent bool
	PCKShadowSampled     bool
	PCKOriginalHash      string
	PCKContextRootHash   string
	PCKPrefixGeneration  string
}

func WithEndpoint(ctx context.Context, endpoint string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, endpointKey{}, endpoint)
}

func GetEndpoint(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if endpoint, ok := ctx.Value(endpointKey{}).(string); ok {
		return endpoint
	}
	return ""
}

// WithClientRequestMetadata stores a snapshot of downstream request metadata in ctx.
func WithClientRequestMetadata(ctx context.Context, metadata ClientRequestMetadata) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, clientRequestMetadataKey{}, metadata)
}

// GetClientRequestMetadata returns downstream request metadata stored in ctx.
func GetClientRequestMetadata(ctx context.Context) ClientRequestMetadata {
	if ctx == nil {
		return ClientRequestMetadata{}
	}
	if metadata, ok := ctx.Value(clientRequestMetadataKey{}).(ClientRequestMetadata); ok {
		return metadata
	}
	return ClientRequestMetadata{}
}

func WithResponseStatusHolder(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if holder, ok := ctx.Value(responseStatusKey{}).(*responseStatusHolder); ok && holder != nil {
		return ctx
	}
	return context.WithValue(ctx, responseStatusKey{}, &responseStatusHolder{})
}

func WithResponseHeadersHolder(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if holder, ok := ctx.Value(responseHeadersKey{}).(*responseHeadersHolder); ok && holder != nil {
		return ctx
	}
	return context.WithValue(ctx, responseHeadersKey{}, &responseHeadersHolder{})
}

func SetResponseStatus(ctx context.Context, status int) {
	if ctx == nil || status <= 0 {
		return
	}
	holder, ok := ctx.Value(responseStatusKey{}).(*responseStatusHolder)
	if !ok || holder == nil {
		return
	}
	holder.status.Store(int32(status))
}

func SetResponseHeaders(ctx context.Context, headers http.Header) {
	if ctx == nil {
		return
	}
	holder, ok := ctx.Value(responseHeadersKey{}).(*responseHeadersHolder)
	if !ok || holder == nil {
		return
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	holder.headers = cloneHTTPHeader(headers)
}

// SetRoutingUsageMetadata publishes immutable routing diagnostics for the
// request's eventual usage record without touching the client response path.
func SetRoutingUsageMetadata(ctx context.Context, metadata RoutingUsageMetadata) {
	if ctx == nil {
		return
	}
	holder, ok := ctx.Value(responseHeadersKey{}).(*responseHeadersHolder)
	if !ok || holder == nil {
		return
	}
	holder.routingUsage.Store(&metadata)
}

func GetResponseStatus(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	holder, ok := ctx.Value(responseStatusKey{}).(*responseStatusHolder)
	if !ok || holder == nil {
		return 0
	}
	return int(holder.status.Load())
}

func GetResponseHeaders(ctx context.Context) http.Header {
	if ctx == nil {
		return nil
	}
	holder, ok := ctx.Value(responseHeadersKey{}).(*responseHeadersHolder)
	if !ok || holder == nil {
		return nil
	}
	holder.mu.RLock()
	headers := cloneHTTPHeader(holder.headers)
	holder.mu.RUnlock()
	metadata := holder.routingUsage.Load()
	if metadata == nil {
		return headers
	}
	if headers == nil {
		headers = make(http.Header, 9)
	}
	setRoutingUsageHeaders(headers, *metadata)
	return headers
}

func setRoutingUsageHeaders(headers http.Header, metadata RoutingUsageMetadata) {
	if metadata.AffinityOutcome != "" {
		headers.Set("X-Cpa-Affinity-Outcome", metadata.AffinityOutcome)
	}
	if metadata.SessionSource != "" {
		headers.Set("X-Cpa-Session-Source", metadata.SessionSource)
	}
	if metadata.BindingGeneration > 0 {
		headers.Set("X-Cpa-Binding-Generation", strconv.FormatUint(metadata.BindingGeneration, 10))
	}
	if metadata.QuotaSnapshotPresent {
		headers.Set("X-Cpa-Quota-Used-Percent", strconv.FormatFloat(metadata.QuotaUsedPercent, 'f', 3, 64))
	}
	if metadata.PCKShadowSampled {
		headers.Set("X-Cpa-Pck-Shadow-Sampled", "true")
	}
	if metadata.PCKOriginalHash != "" {
		headers.Set("X-Cpa-Pck-Original-Hash", metadata.PCKOriginalHash)
	}
	if metadata.PCKContextRootHash != "" {
		headers.Set("X-Cpa-Pck-Context-Root-Hash", metadata.PCKContextRootHash)
	}
	if metadata.PCKPrefixGeneration != "" {
		headers.Set("X-Cpa-Pck-Prefix-Generation", metadata.PCKPrefixGeneration)
	}
}

func cloneHTTPHeader(src http.Header) http.Header {
	if len(src) == 0 {
		return nil
	}
	dst := make(http.Header, len(src))
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
	return dst
}
