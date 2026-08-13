package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	defaultRuntimeSelectionFreezeSeconds = 30
	defaultRuntimeRateLimitWindowSeconds = 60
	runtimeSkipReasonQuotaPreempt        = "quota_preempt"
	runtimeSkipReasonUsageLimitReached   = "usage_limit_reached"
)

type authRuntimeLimits struct {
	mu sync.Mutex

	currentConcurrency int

	rateWindowStart time.Time
	rateWindowCount int

	frozenUntil                  time.Time
	usageLimitFreezeUntil        time.Time
	quotaPreemptFreezeUntil      time.Time
	rateLimitedUntil             time.Time
	stickyBypassNext             bool
	stickyBypassSessions         map[string]time.Time
	lastSkipReason               string
	lastSkipRecordedAt           time.Time
	lastSkipRecoveryTarget       time.Time
	quotaPreemptFallbackInFlight int

	// codexQuotaSnapshots is replaced atomically by the asynchronous quota
	// collector. Request-time reads remain lock-free.
	codexQuotaSnapshots atomic.Value
}

type runtimeStickyBypassSessionContextKey struct{}

const runtimeStickyBypassTTL = time.Hour

type RuntimeLimitSnapshot struct {
	CurrentConcurrency int       `json:"current_concurrency"`
	FrozenUntil        time.Time `json:"frozen_until"`
	RateLimitedUntil   time.Time `json:"rate_limited_until"`
	LastSkipReason     string    `json:"last_skip_reason,omitempty"`
}

func (a *Auth) ensureRuntimeLimits() *authRuntimeLimits {
	if a == nil {
		return nil
	}
	// Auth is intentionally shallow-copyable, so runtimeLimits remains a plain
	// pointer rather than atomic.Pointer (which must not be copied after use).
	// Access the pointer atomically to keep lazy initialization lock-free and
	// race-free when selectors inspect the same freshly constructed Auth.
	slot := (*unsafe.Pointer)(unsafe.Pointer(&a.runtimeLimits))
	if current := atomic.LoadPointer(slot); current != nil {
		return (*authRuntimeLimits)(current)
	}
	created := &authRuntimeLimits{}
	if atomic.CompareAndSwapPointer(slot, nil, unsafe.Pointer(created)) {
		return created
	}
	return (*authRuntimeLimits)(atomic.LoadPointer(slot))
}

func (a *Auth) runtimeLimitConfig() runtimeLimitConfig {
	hasMaxConcurrency := runtimeLimitHasAny(a, []string{"max_concurrency", "max-concurrency", "maxConcurrency"})
	hasRateLimitMaxRequests := runtimeLimitHasAny(a, []string{"rate_limit_max_requests", "rate-limit-max-requests", "rateLimitMaxRequests"})
	hasRateLimitWindowSeconds := runtimeLimitHasAny(a, []string{"rate_limit_window_seconds", "rate-limit-window-seconds", "rateLimitWindowSeconds"})
	hasSelectionFreeze := runtimeLimitHasAny(a, []string{"selection_error_freeze_seconds", "selection-error-freeze-seconds", "selectionErrorFreezeSeconds"})
	hasStickyBypass := runtimeLimitHasAny(a, []string{"disable_sticky_on_next_request", "disable-sticky-on-next-request", "disableStickyOnNextRequest"})
	cfg := runtimeLimitConfig{
		maxConcurrency:              runtimeLimitIntAny(a, []string{"max_concurrency", "max-concurrency", "maxConcurrency"}),
		rateLimitMaxRequests:        runtimeLimitIntAny(a, []string{"rate_limit_max_requests", "rate-limit-max-requests", "rateLimitMaxRequests"}),
		rateLimitWindowSeconds:      runtimeLimitIntAny(a, []string{"rate_limit_window_seconds", "rate-limit-window-seconds", "rateLimitWindowSeconds"}),
		selectionErrorFreezeSeconds: runtimeLimitIntAny(a, []string{"selection_error_freeze_seconds", "selection-error-freeze-seconds", "selectionErrorFreezeSeconds"}),
		disableStickyOnNextRequest:  runtimeLimitBoolAny(a, []string{"disable_sticky_on_next_request", "disable-sticky-on-next-request", "disableStickyOnNextRequest"}),
	}
	if cfg.maxConcurrency < 0 {
		cfg.maxConcurrency = 0
	}
	if cfg.rateLimitMaxRequests < 0 {
		cfg.rateLimitMaxRequests = 0
	}
	if cfg.rateLimitWindowSeconds <= 0 {
		cfg.rateLimitWindowSeconds = defaultRuntimeRateLimitWindowSeconds
	}
	if cfg.selectionErrorFreezeSeconds < 0 {
		cfg.selectionErrorFreezeSeconds = 0
	} else if !hasSelectionFreeze && (hasMaxConcurrency || hasRateLimitMaxRequests || hasRateLimitWindowSeconds || hasStickyBypass) {
		cfg.selectionErrorFreezeSeconds = defaultRuntimeSelectionFreezeSeconds
	}
	return cfg
}

type runtimeLimitConfig struct {
	maxConcurrency              int
	rateLimitMaxRequests        int
	rateLimitWindowSeconds      int
	selectionErrorFreezeSeconds int
	disableStickyOnNextRequest  bool
}

func (a *Auth) RuntimeLimitSnapshot(now time.Time) RuntimeLimitSnapshot {
	if a == nil {
		return RuntimeLimitSnapshot{}
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return RuntimeLimitSnapshot{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.compactRuntimeWindowLocked(now, a.runtimeLimitConfig())
	frozenUntil, freezeReason := state.activeFreezeLocked(now)
	lastSkipReason := state.lastSkipReason
	if freezeReason != "" {
		lastSkipReason = freezeReason
	}
	return RuntimeLimitSnapshot{
		CurrentConcurrency: state.currentConcurrency,
		FrozenUntil:        frozenUntil,
		RateLimitedUntil:   state.rateLimitedUntil,
		LastSkipReason:     lastSkipReason,
	}
}

func runtimeAuthBlockedForModel(auth *Auth, now time.Time) (bool, blockReason, time.Time) {
	return runtimeAuthBlockedForModelWithTailBurst(auth, now, false)
}

func runtimeAuthBlockedForModelWithTailBurst(auth *Auth, now time.Time, tailBurst bool) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	state := auth.ensureRuntimeLimits()
	if state == nil {
		return false, blockReasonNone, time.Time{}
	}
	cfg := auth.runtimeLimitConfig()
	state.mu.Lock()
	defer state.mu.Unlock()

	state.compactRuntimeWindowLocked(now, cfg)
	if frozenUntil, reason := state.activeFreezeLocked(now); frozenUntil.After(now) {
		if auth.quotaPreemptFallback && state.onlyQuotaPreemptFreezeLocked(now) && state.quotaPreemptFallbackInFlight == 0 {
			// Continue through concurrency and rate checks. The request-local
			// fallback flag only bypasses the collector's quota-preempt freeze.
		} else {
			state.recordSkipLocked(reason, frozenUntil, now)
			return true, blockReasonCooldown, frozenUntil
		}
	}
	if tailBurst && state.currentConcurrency >= 1 {
		state.recordSkipLocked("tail_burst_concurrency_limit", time.Time{}, now)
		return true, blockReasonOther, time.Time{}
	}
	if !tailBurst && cfg.maxConcurrency > 0 && state.currentConcurrency >= cfg.maxConcurrency {
		state.recordSkipLocked("concurrency_limit", time.Time{}, now)
		return true, blockReasonOther, time.Time{}
	}
	if cfg.rateLimitMaxRequests > 0 && state.rateWindowCount >= cfg.rateLimitMaxRequests {
		until := state.rateWindowStart.Add(time.Duration(cfg.rateLimitWindowSeconds) * time.Second)
		if until.Before(now) {
			until = now
		}
		state.rateLimitedUntil = until
		state.recordSkipLocked("rate_limited", until, now)
		return true, blockReasonCooldown, until
	}
	return false, blockReasonNone, time.Time{}
}

func contextWithRuntimeStickyBypassSession(ctx context.Context, sessionKey string) context.Context {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, runtimeStickyBypassSessionContextKey{}, sessionKey)
}

func runtimeStickyBypassSessionFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(runtimeStickyBypassSessionContextKey{}).(string)
	return strings.TrimSpace(value)
}

func (a *Auth) consumeStickyBypass(sessionKey string, now time.Time) bool {
	sessionKey = strings.TrimSpace(sessionKey)
	if a == nil || sessionKey == "" {
		return false
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.pruneStickyBypassSessionsLocked(now)
	if until, ok := state.stickyBypassSessions[sessionKey]; ok {
		delete(state.stickyBypassSessions, sessionKey)
		return until.IsZero() || until.After(now)
	}
	if !state.stickyBypassNext {
		return false
	}
	state.stickyBypassNext = false
	return true
}

func (a *Auth) markStickyBypassForSession(sessionKey string, now time.Time) {
	sessionKey = strings.TrimSpace(sessionKey)
	if a == nil || sessionKey == "" {
		return
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return
	}
	state.mu.Lock()
	state.pruneStickyBypassSessionsLocked(now)
	if state.stickyBypassSessions == nil {
		state.stickyBypassSessions = make(map[string]time.Time, 1)
	}
	state.stickyBypassSessions[sessionKey] = now.Add(runtimeStickyBypassTTL)
	state.mu.Unlock()
}

func (a *Auth) acquireRuntimeSlot(now time.Time) (release func(), ok bool, reason string, retryAt time.Time) {
	return a.acquireRuntimeSlotWithTailBurst(now, false)
}

func (a *Auth) acquireRuntimeSlotWithTailBurst(now time.Time, tailBurst bool) (release func(), ok bool, reason string, retryAt time.Time) {
	if a == nil {
		return nil, false, "missing_auth", time.Time{}
	}
	cfg := a.runtimeLimitConfig()
	state := a.ensureRuntimeLimits()
	if state == nil {
		return nil, true, "", time.Time{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	state.compactRuntimeWindowLocked(now, cfg)
	quotaPreemptFallback := false
	if frozenUntil, reason := state.activeFreezeLocked(now); frozenUntil.After(now) {
		if a.quotaPreemptFallback && state.onlyQuotaPreemptFreezeLocked(now) && state.quotaPreemptFallbackInFlight == 0 {
			quotaPreemptFallback = true
		} else {
			state.recordSkipLocked(reason, frozenUntil, now)
			return nil, false, "frozen", frozenUntil
		}
	}
	if tailBurst && state.currentConcurrency >= 1 {
		state.recordSkipLocked("tail_burst_concurrency_limit", time.Time{}, now)
		return nil, false, "tail_burst_concurrency_limit", time.Time{}
	}
	if !tailBurst && cfg.maxConcurrency > 0 && state.currentConcurrency >= cfg.maxConcurrency {
		state.recordSkipLocked("concurrency_limit", time.Time{}, now)
		return nil, false, "concurrency_limit", time.Time{}
	}
	if cfg.rateLimitMaxRequests > 0 && state.rateWindowCount >= cfg.rateLimitMaxRequests {
		until := state.rateWindowStart.Add(time.Duration(cfg.rateLimitWindowSeconds) * time.Second)
		if until.Before(now) {
			until = now
		}
		state.rateLimitedUntil = until
		state.recordSkipLocked("rate_limited", until, now)
		return nil, false, "rate_limited", until
	}

	state.currentConcurrency++
	if quotaPreemptFallback {
		state.quotaPreemptFallbackInFlight++
		cacheaffinity.RecordQuotaFallback()
	}
	if state.rateWindowStart.IsZero() || now.Sub(state.rateWindowStart) >= time.Duration(cfg.rateLimitWindowSeconds)*time.Second {
		state.rateWindowStart = now
		state.rateWindowCount = 0
	}
	state.rateWindowCount++
	state.lastSkipReason = ""
	state.lastSkipRecordedAt = time.Time{}
	state.lastSkipRecoveryTarget = time.Time{}

	releaseOnce := sync.Once{}
	return func() {
		releaseOnce.Do(func() {
			state.mu.Lock()
			if state.currentConcurrency > 0 {
				state.currentConcurrency--
			}
			if quotaPreemptFallback && state.quotaPreemptFallbackInFlight > 0 {
				state.quotaPreemptFallbackInFlight--
			}
			state.mu.Unlock()
		})
	}, true, "", time.Time{}
}

func (state *authRuntimeLimits) compactRuntimeWindowLocked(now time.Time, cfg runtimeLimitConfig) {
	if state == nil {
		return
	}
	window := time.Duration(cfg.rateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Duration(defaultRuntimeRateLimitWindowSeconds) * time.Second
	}
	if !state.frozenUntil.IsZero() && !state.frozenUntil.After(now) {
		state.frozenUntil = time.Time{}
	}
	if !state.usageLimitFreezeUntil.IsZero() && !state.usageLimitFreezeUntil.After(now) {
		state.usageLimitFreezeUntil = time.Time{}
	}
	if !state.quotaPreemptFreezeUntil.IsZero() && !state.quotaPreemptFreezeUntil.After(now) {
		state.quotaPreemptFreezeUntil = time.Time{}
	}
	if !state.rateLimitedUntil.IsZero() && !state.rateLimitedUntil.After(now) {
		state.rateLimitedUntil = time.Time{}
	}
	if state.rateWindowStart.IsZero() {
		if state.rateWindowCount > 0 {
			state.rateWindowCount = 0
		}
		return
	}
	if now.Sub(state.rateWindowStart) >= window {
		state.rateWindowStart = now
		state.rateWindowCount = 0
		state.rateLimitedUntil = time.Time{}
	}
}

func (state *authRuntimeLimits) recordSkipLocked(reason string, until time.Time, now time.Time) {
	if state == nil {
		return
	}
	state.lastSkipReason = reason
	state.lastSkipRecordedAt = now
	state.lastSkipRecoveryTarget = until
}

func (state *authRuntimeLimits) activeFreezeLocked(now time.Time) (time.Time, string) {
	if state == nil {
		return time.Time{}, ""
	}
	until := state.frozenUntil
	reason := "frozen"
	if state.usageLimitFreezeUntil.After(until) {
		until = state.usageLimitFreezeUntil
		reason = runtimeSkipReasonUsageLimitReached
	}
	if state.quotaPreemptFreezeUntil.After(until) {
		until = state.quotaPreemptFreezeUntil
		reason = runtimeSkipReasonQuotaPreempt
	}
	if !until.After(now) {
		return time.Time{}, ""
	}
	return until, reason
}

// onlyQuotaPreemptFreezeLocked reports whether the collector's preventive
// hard-stop is the sole active runtime freeze. Generic error freezes and real
// upstream usage-limit freezes deliberately remain absolute.
func (state *authRuntimeLimits) onlyQuotaPreemptFreezeLocked(now time.Time) bool {
	if state == nil || !state.quotaPreemptFreezeUntil.After(now) {
		return false
	}
	return !state.frozenUntil.After(now) && !state.usageLimitFreezeUntil.After(now)
}

// runtimeQuotaPreemptFallbackState separates pool-level eligibility from
// request-time capacity. Callers may ignore a busy fallback credential and use
// the next-lowest valid quota snapshot, while acquisition still enforces a
// single fallback request per credential plus its normal concurrency/rate caps.
func runtimeQuotaPreemptFallbackState(auth *Auth, now time.Time) (quotaOnly, hasCapacity bool) {
	if auth == nil {
		return false, false
	}
	state := auth.ensureRuntimeLimits()
	if state == nil {
		return false, false
	}
	cfg := auth.runtimeLimitConfig()
	state.mu.Lock()
	defer state.mu.Unlock()
	state.compactRuntimeWindowLocked(now, cfg)
	if !state.onlyQuotaPreemptFreezeLocked(now) {
		return false, false
	}
	if state.quotaPreemptFallbackInFlight > 0 {
		return true, false
	}
	if cfg.maxConcurrency > 0 && state.currentConcurrency >= cfg.maxConcurrency {
		return true, false
	}
	if cfg.rateLimitMaxRequests > 0 && state.rateWindowCount >= cfg.rateLimitMaxRequests {
		return true, false
	}
	return true, true
}

func runtimeAuthHasPersistentQuotaFreeze(auth *Auth, now time.Time) bool {
	if auth == nil {
		return false
	}
	state := auth.ensureRuntimeLimits()
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.usageLimitFreezeUntil.After(now) || state.quotaPreemptFreezeUntil.After(now)
}

func (state *authRuntimeLimits) pruneStickyBypassSessionsLocked(now time.Time) {
	if state == nil || len(state.stickyBypassSessions) == 0 {
		return
	}
	for key, until := range state.stickyBypassSessions {
		if key == "" || (!until.IsZero() && !until.After(now)) {
			delete(state.stickyBypassSessions, key)
		}
	}
	if len(state.stickyBypassSessions) == 0 {
		state.stickyBypassSessions = nil
	}
}

func (a *Auth) maybeFreezeRuntimeResult(result Result, now time.Time, stickySessionKey string) {
	if a == nil || result.Success {
		return
	}
	if isRequestScopedNotFoundResultError(result.Error) {
		return
	}
	if !shouldFreezeRuntimeAuthResult(result.Error) {
		return
	}
	cfg := a.runtimeLimitConfig()
	if cfg.selectionErrorFreezeSeconds <= 0 {
		return
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return
	}
	frozenUntil := now.Add(time.Duration(cfg.selectionErrorFreezeSeconds) * time.Second)
	state.mu.Lock()
	state.frozenUntil = frozenUntil
	state.recordSkipLocked("frozen", frozenUntil, now)
	if cfg.disableStickyOnNextRequest {
		state.mu.Unlock()
		a.markStickyBypassForSession(stickySessionKey, now)
		return
	}
	state.mu.Unlock()
}

func (a *Auth) freezeUsageLimit(now time.Time, retryAfter *time.Duration) bool {
	if a == nil {
		return false
	}
	until := now.Add(5 * time.Minute)
	if retryAfter != nil && *retryAfter > 0 {
		until = now.Add(*retryAfter)
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return false
	}
	state.mu.Lock()
	// Repeated responses carrying resets_in_seconds calculate nearly identical
	// absolute deadlines from slightly different arrival times. Treat sub-second
	// drift as the same freeze window so a concurrent failure burst is deduplicated.
	extended := state.usageLimitFreezeUntil.Before(until.Add(-time.Second))
	if extended {
		state.usageLimitFreezeUntil = until
	}
	frozenUntil, reason := state.activeFreezeLocked(now)
	state.recordSkipLocked(reason, frozenUntil, now)
	state.mu.Unlock()
	return extended
}

func (a *Auth) updateQuotaPreempt(now time.Time, until time.Time, active bool) {
	if a == nil {
		return
	}
	state := a.ensureRuntimeLimits()
	if state == nil {
		return
	}
	state.mu.Lock()
	if active && !until.IsZero() && until.After(now) {
		if state.quotaPreemptFreezeUntil.Before(until) {
			state.quotaPreemptFreezeUntil = until
		}
	} else {
		state.quotaPreemptFreezeUntil = time.Time{}
	}
	if frozenUntil, reason := state.activeFreezeLocked(now); frozenUntil.After(now) {
		state.recordSkipLocked(reason, frozenUntil, now)
	}
	state.mu.Unlock()
}

func shouldFreezeRuntimeAuthResult(err *Error) bool {
	if err == nil {
		return false
	}
	if isCloudflareChallengeResultError(err) || isModelSupportResultError(err) {
		return true
	}
	switch statusCodeFromResult(err) {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusTooManyRequests,
		http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
	}
	lower := strings.ToLower(strings.TrimSpace(err.Message))
	if lower == "" {
		return false
	}
	for _, needle := range []string{
		"insufficient_quota",
		"quota exhausted",
		"quota",
		"rate limit",
		"too many requests",
		"authentication error",
		"invalid credential",
		"selection",
		"not available for your account",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func runtimeLimitHasAny(a *Auth, keys []string) bool {
	if a == nil {
		return false
	}
	for _, key := range keys {
		if runtimeLimitLookupAny(a, key) != nil {
			return true
		}
	}
	return false
}

func runtimeLimitIntAny(a *Auth, keys []string) int {
	for _, key := range keys {
		if v := runtimeLimitLookupAny(a, key); v != nil {
			if parsed, ok := parseIntAny(v); ok {
				return parsed
			}
		}
	}
	return 0
}

func runtimeLimitBoolAny(a *Auth, keys []string) bool {
	for _, key := range keys {
		if v := runtimeLimitLookupAny(a, key); v != nil {
			if parsed, ok := parseBoolAny(v); ok {
				return parsed
			}
		}
	}
	return false
}

func runtimeLimitLookupAny(a *Auth, key string) any {
	if a == nil {
		return nil
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata[key]; ok {
			return v
		}
	}
	if a.Attributes != nil {
		if v, ok := a.Attributes[key]; ok {
			return v
		}
	}
	return nil
}

func wrapStreamResultWithRuntimeRelease(ctx context.Context, result *cliproxyexecutor.StreamResult, release func()) *cliproxyexecutor.StreamResult {
	if result == nil || release == nil {
		return result
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer release()
		var done <-chan struct{}
		if ctx != nil {
			done = ctx.Done()
		}
		for {
			var chunk cliproxyexecutor.StreamChunk
			var ok bool
			select {
			case <-done:
				// Release capacity immediately, but keep draining the wrapped stream so
				// its accounting/error hooks can observe terminal tail chunks.
				release()
				for range result.Chunks {
				}
				return
			case chunk, ok = <-result.Chunks:
			}
			if !ok {
				return
			}
			select {
			case <-done:
				release()
				for range result.Chunks {
				}
				return
			case out <- chunk:
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{
		Headers: result.Headers,
		Chunks:  out,
	}
}

func releaseRuntimeSlot(release func()) {
	if release != nil {
		release()
	}
}

func withRuntimeLimitAuthSelectionFilter(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	return isAuthBlockedForModel(auth, model, now)
}
