package handlers

import (
	"context"
	"time"
)

const immediateStreamBootstrapGrace = 5 * time.Millisecond

// WaitForStreamBootstrap runs execute in the background, optionally emits an
// early SSE bootstrap write, and then returns the execution result once available.
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

	resultChan := make(chan T, 1)
	go func() {
		resultChan <- execute()
	}()

	if bootstrapDelay <= 0 {
		graceTimer := time.NewTimer(immediateStreamBootstrapGrace)
		select {
		case <-ctx.Done():
			graceTimer.Stop()
			return zero, false, true
		case result := <-resultChan:
			graceTimer.Stop()
			return result, false, false
		case <-graceTimer.C:
		}

		if writeBootstrap != nil {
			writeBootstrap()
		}
		streamStarted := writeBootstrap != nil

		var keepAlive *time.Ticker
		var keepAliveC <-chan time.Time
		defer func() {
			if keepAlive != nil {
				keepAlive.Stop()
			}
		}()
		if keepAliveInterval > 0 {
			keepAlive = time.NewTicker(keepAliveInterval)
			keepAliveC = keepAlive.C
		}

		for {
			select {
			case <-ctx.Done():
				return zero, streamStarted, true
			case result := <-resultChan:
				return result, streamStarted, false
			case <-keepAliveC:
				if writeKeepAlive != nil {
					writeKeepAlive()
				}
			}
		}
	}

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
