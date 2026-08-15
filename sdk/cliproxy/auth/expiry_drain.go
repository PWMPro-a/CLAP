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
	// authExpiryCohortWindow keeps one supplier batch moving together while
	// preventing a large short-lived pool from degenerating into round-robin
	// across every account. The next batch enters the lane after the oldest
	// minute-wide cohort is exhausted, blocked, or expired.
	authExpiryCohortWindow = time.Minute
	// authExpiryDrainWindow is the final window in which an account may use a
	// bounded concurrency boost to consume remaining quota before expiry.
	authExpiryDrainWindow = 5 * time.Minute
	// authExpiryPriorityDefaultConcurrency prevents an unconfigured near-expiry
	// account from absorbing the whole request stream. Once the oldest cohort is
	// full, normal availability filtering lets requests spill into the next
	// expiry cohort instead of provoking upstream rate limits on one account.
	authExpiryPriorityDefaultConcurrency = 8
	// The final drain ceiling is selected from the remaining quota. Accounts
	// with substantial unused quota may fan out further, while mostly-consumed
	// accounts stay at the normal near-expiry limit to avoid needless 429s.
	authExpiryDrainMinConcurrency    = 8
	authExpiryDrainNormalConcurrency = 10
	authExpiryDrainUrgentConcurrency = 12
)

var authSupplyLeaseExpiryKeys = [...]string{
	"supply_lease_expires_at_ms",
	"supplyLeaseExpiresAtMs",
	"supply_lease_expires_at",
	"supplyLeaseExpiresAt",
}

// authSupplyLeaseExpirationTime returns the supplier's serving deadline. It is
// intentionally separate from Auth.ExpirationTime: the latter is the OAuth
// token expiry and drives token refresh, while this deadline drives routing.
func authSupplyLeaseExpirationTime(auth *Auth) (time.Time, bool) {
	if auth == nil || auth.Metadata == nil {
		return time.Time{}, false
	}
	for _, key := range authSupplyLeaseExpiryKeys {
		value, exists := auth.Metadata[key]
		if !exists {
			continue
		}
		if expiresAt, ok := parseTimeValue(value); ok && !expiresAt.IsZero() {
			return expiresAt, true
		}
	}
	return time.Time{}, false
}

func authSchedulingExpirationTime(auth *Auth) (time.Time, bool) {
	if expiresAt, ok := authSupplyLeaseExpirationTime(auth); ok {
		return expiresAt, true
	}
	if auth == nil {
		return time.Time{}, false
	}
	return auth.ExpirationTime()
}

func authSupplyLeaseExpired(auth *Auth, now time.Time) bool {
	expiresAt, ok := authSupplyLeaseExpirationTime(auth)
	return ok && !expiresAt.After(now)
}

func authExpiryRemaining(auth *Auth, now time.Time) (time.Duration, bool) {
	if auth == nil {
		return 0, false
	}
	expiresAt, ok := authSchedulingExpirationTime(auth)
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
	// A provider-level quota failure is the authoritative exhaustion signal.
	// Usage percentages are rounded and may report 100% while a small amount of
	// capacity remains, so the final lane continues until the upstream rejects a
	// request rather than stopping on a sampled ratio.
	if authQuotaExceeded(auth, model) {
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
	if len(priority) == 0 {
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
	earliest, _ := authSchedulingExpirationTime(priority[0])
	cutoff := earliest.Add(authExpiryCohortWindow)
	end := 1
	for end < len(priority) {
		expiresAt, _ := authSchedulingExpirationTime(priority[end])
		if expiresAt.After(cutoff) {
			break
		}
		end++
	}
	return priority[:end]
}

func expiryPriorityConcurrencyLimit(auth *Auth, model string, now time.Time, configured int) int {
	if configured < 0 {
		configured = 0
	}
	if _, ok := authExpiryRemaining(auth, now); !ok {
		return configured
	}
	if configured == 0 {
		configured = authExpiryPriorityDefaultConcurrency
	}
	return expiryDrainConcurrencyLimit(auth, model, now, configured)
}

func expiryDrainConcurrencyCeiling(auth *Auth, model string, now time.Time) int {
	snapshot, ok := auth.codexQuotaSnapshot(model, now)
	if !ok {
		return authExpiryDrainNormalConcurrency
	}
	switch {
	case snapshot.UsedRatio < 0.50:
		return authExpiryDrainUrgentConcurrency
	case snapshot.UsedRatio < 0.80:
		return authExpiryDrainNormalConcurrency
	default:
		return authExpiryDrainMinConcurrency
	}
}

func expiryDrainConcurrencyLimit(auth *Auth, model string, now time.Time, configured int) int {
	if configured <= 0 || !authExpiryDrainActive(auth, model, now) {
		return configured
	}
	ceiling := expiryDrainConcurrencyCeiling(auth, model, now)
	if configured >= ceiling {
		return configured
	}
	boosted := configured * 2
	if boosted < configured+1 {
		boosted = configured + 1
	}
	if boosted > ceiling {
		boosted = ceiling
	}
	return boosted
}

// expiryDrainFailoverAuths returns the oldest final-window cohort that should
// temporarily receive a warm session. Normal expiry preference applies only
// to cold bindings so cache affinity stays intact. In the last five minutes,
// however, preserving a later-bound credential can strand the entire balance
// of an older supplier lease. The selector uses this list through its
// failover cache, leaving the primary binding untouched and automatically
// returning to it after the drain credential expires or is exhausted.
func expiryDrainFailoverAuths(auths []*Auth, cached *Auth, model string, now time.Time) []*Auth {
	if len(auths) == 0 {
		return nil
	}
	draining := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil || !authExpiryDrainActive(auth, model, now) {
			continue
		}
		draining = append(draining, auth)
	}
	if len(draining) == 0 {
		return nil
	}
	sort.SliceStable(draining, func(i, j int) bool {
		left, _ := authSchedulingExpirationTime(draining[i])
		right, _ := authSchedulingExpirationTime(draining[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return draining[i].ID < draining[j].ID
	})
	earliest, _ := authSchedulingExpirationTime(draining[0])
	cutoff := earliest.Add(authExpiryCohortWindow)
	if cached != nil && authExpiryDrainActive(cached, model, now) {
		if cachedExpiry, ok := authSchedulingExpirationTime(cached); ok && !cachedExpiry.After(cutoff) {
			return nil
		}
	}
	end := 0
	for end < len(draining) {
		expiresAt, _ := authSchedulingExpirationTime(draining[end])
		if expiresAt.After(cutoff) {
			break
		}
		end++
	}
	result := make([]*Auth, 0, end)
	for _, auth := range draining[:end] {
		if cached == nil || auth.ID != cached.ID {
			result = append(result, auth)
		}
	}
	return result
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
	return narrowScheduledExpiryLane(out)
}

func narrowScheduledExpiryLane(entries []*scheduledAuth) []*scheduledAuth {
	if len(entries) <= 1 {
		return entries
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if !entries[i].expiresAt.Equal(entries[j].expiresAt) {
			return entries[i].expiresAt.Before(entries[j].expiresAt)
		}
		return entries[i].auth.ID < entries[j].auth.ID
	})
	cutoff := entries[0].expiresAt.Add(authExpiryCohortWindow)
	end := 1
	for end < len(entries) && !entries[end].expiresAt.After(cutoff) {
		end++
	}
	return entries[:end]
}
