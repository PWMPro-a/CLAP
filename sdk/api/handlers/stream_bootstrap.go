package handlers

import (
	"context"
	"time"
)

// WaitForStreamBootstrap runs execute in the background when bootstrapDelay is positive,
// allows the caller to emit an early SSE bootstrap write, and then returns the execution
// result once available.
func WaitForStreamBootstrap[T any](
	ctx context.Context,
	bootstrapDelay time.Duration,
	keepAliveInterval time.Duration,
	execute func() T,
	writeBootstrap func(),
	writeKeepAlive func(),
) (T, bool, bool) {
	var zero T
	if execute == nil {
		return zero, false, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if bootstrapDelay <= 0 {
		return execute(), false, false
	}

	resultChan := make(chan T, 1)
	go func() {
		resultChan <- execute()
	}()

	bootstrapTimer := time.NewTimer(bootstrapDelay)
	defer bootstrapTimer.Stop()

	var keepAlive *time.Ticker
	var keepAliveC <-chan time.Time
	defer func() {
		if keepAlive != nil {
			keepAlive.Stop()
		}
	}()

	streamStarted := false
	for {
		select {
		case <-ctx.Done():
			return zero, streamStarted, true
		case result := <-resultChan:
			return result, streamStarted, false
		case <-bootstrapTimer.C:
			if streamStarted {
				continue
			}
			if writeBootstrap != nil {
				writeBootstrap()
			}
			streamStarted = true
			if keepAliveInterval > 0 {
				keepAlive = time.NewTicker(keepAliveInterval)
				keepAliveC = keepAlive.C
			}
		case <-keepAliveC:
			if writeKeepAlive != nil {
				writeKeepAlive()
			}
		}
	}
}
