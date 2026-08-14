package auth

import (
	"sort"
	"time"
)

const (
	// authExpiryPriorityWindow is intentionally bounded. Credentials with a
	// distant expiry keep normal balancing semantics; only the near-expiry
	// group becomes a drain lane.
	authExpiryPriorityWindow = 24 * time.Hour
	// authExpiryDrainWindow is the final window in which an account may use a
	// bounded concurrency boost to consume remaining quota before expiry.
	authExpiryDrainWindow = 5 * time.Minute
	// authExpiryDrainMaxConcurrency prevents a configured single-slot account
	// from becoming an unbounded fan-out during the drain window.
	authExpiryDrainMaxConcurrency = 8
)

func authExpiryRemaining(auth *Auth, now time.Time) (time.Duration, bool) {
	if auth == nil {
		return 0, false
	}
	expiresAt, ok := auth.ExpirationTime()
	if !ok || expiresAt.IsZero() {
		return 0, false
	}
	remaining := expiresAt.Sub(now)
	if remaining <= 0 || remaining > authExpiryPriorityWindow {
		return 0, false
	}
	return remaining, true
}

func authExpiryDrainActive(auth *Auth, model string, now time.Time) bool {
	remaining, ok := authExpiryRemaining(auth, now)
	if !ok || remaining > authExpiryDrainWindow {
		return false
	}
	// A provider-level quota failure is stronger evidence than the expiry
	// signal. Once the quota snapshot itself is exhausted, extra concurrency
	// only creates failed requests and does not drain useful capacity.
	if authQuotaExceeded(auth, model) {
		return false
	}
	if snapshot, ok := auth.codexQuotaSnapshot(model, now); ok && snapshot.UsedRatio >= 1 {
		return false
	}
	return true
}

// expiryPriorityAuths narrows a ready candidate set to the near-expiry lane.
// The caller has already applied provider/model availability and priority
// rules. Returning the original slice when no lane exists preserves the hot
// request path's existing allocation and ordering behavior.
func expiryPriorityAuths(auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	priority := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if _, ok := authExpiryRemaining(auth, now); ok {
			priority = append(priority, auth)
		}
	}
	if len(priority) == 0 || len(priority) == len(auths) {
		if len(priority) == len(auths) {
			sort.SliceStable(priority, func(i, j int) bool {
				left, _ := authExpiryRemaining(priority[i], now)
				right, _ := authExpiryRemaining(priority[j], now)
				if left != right {
					return left < right
				}
				return priority[i].ID < priority[j].ID
			})
			return priority
		}
		return auths
	}
	sort.SliceStable(priority, func(i, j int) bool {
		left, _ := authExpiryRemaining(priority[i], now)
		right, _ := authExpiryRemaining(priority[j], now)
		if left != right {
			return left < right
		}
		return priority[i].ID < priority[j].ID
	})
	return priority
}

func expiryDrainConcurrencyLimit(auth *Auth, model string, now time.Time, configured int) int {
	if configured <= 0 || !authExpiryDrainActive(auth, model, now) {
		return configured
	}
	if configured >= authExpiryDrainMaxConcurrency {
		return configured
	}
	boosted := configured * 2
	if boosted < configured+1 {
		boosted = configured + 1
	}
	if boosted > authExpiryDrainMaxConcurrency {
		boosted = authExpiryDrainMaxConcurrency
	}
	return boosted
}

func expiringScheduledEntries(entries []*scheduledAuth, predicate func(*scheduledAuth) bool, now time.Time) []*scheduledAuth {
	if len(entries) == 0 {
		return nil
	}
	out := make([]*scheduledAuth, 0, len(entries))
	cutoff := now.Add(authExpiryPriorityWindow)
	for _, entry := range entries {
		if entry == nil || entry.expiresAt.IsZero() || !entry.expiresAt.After(now) || entry.expiresAt.After(cutoff) {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		out = append(out, entry)
	}
	return out
}
