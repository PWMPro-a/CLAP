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
	// preserving batch boundaries when the active lane is widened for capacity.
	authExpiryCohortWindow = time.Minute
	// authExpiryPriorityMinCandidates starts from the single earliest supplier
	// cohort. Normal runtime concurrency caps make the lane spill into the next
	// cohort only after the oldest one is full, so healthy capacity is not wasted
	// while established affinity bindings remain untouched.
	authExpiryPriorityMinCandidates = 1
	// authExpiryDrainWindow is the final window in which an account may use a
	// bounded concurrency boost to consume remaining quota before expiry.
	authExpiryDrainWindow = 5 * time.Minute
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

// authSupplyLeaseExpirationTime returns the supplier's routing-priority
// timestamp. It is intentionally separate from Auth.ExpirationTime: the latter
// is the OAuth token expiry and drives token refresh, while this value only
// orders healthy credentials for scheduling.
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

func authExpiryRemaining(auth *Auth, now time.Time) (time.Duration, bool) {
	if auth == nil {
		return 0, false
	}
	expiresAt, supplied := authSupplyLeaseExpirationTime(auth)
	if !supplied {
		var ok bool
		expiresAt, ok = auth.ExpirationTime()
		if !ok {
			return 0, false
		}
	}
	if expiresAt.IsZero() {
		return 0, false
	}
	remaining := expiresAt.Sub(now)
	if remaining > authExpiryPriorityWindow {
		return 0, false
	}
	// Supplier lease timestamps are scheduling hints, not credential validity
	// boundaries. Once the timestamp passes, keep the still-healthy account in
	// the most urgent lane until normal runtime health logic rejects it.
	if remaining <= 0 {
		if supplied {
			return remaining, true
		}
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
// The lane starts with the earliest candidate and extends through its supplier
// cohort. Runtime concurrency limits naturally spill cold requests into the
// next cohort after the oldest batch fills.
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
	boundary := authExpiryPriorityMinCandidates
	if boundary > len(priority) {
		boundary = len(priority)
	}
	boundaryExpiry, _ := authSchedulingExpirationTime(priority[boundary-1])
	cutoff := boundaryExpiry.Add(authExpiryCohortWindow)
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
	// Near-expiry priority is a routing decision, not an implicit account cap.
	// An unconfigured credential keeps its normal unlimited concurrency so the
	// final expiry window can consume all available demand. Explicit account
	// limits remain authoritative and may receive the bounded final-drain boost.
	if configured <= 0 {
		return 0
	}
	if _, ok := authExpiryRemaining(auth, now); !ok {
		return configured
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

// expiryDrainFailoverAuths returns the oldest final-window cohort for the
// optional aggressive drain mode. The caller gates this path behind
// expiry-drain-ignore-affinity, so normal operation keeps warm bindings intact.
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

func appendExpiringScheduledEntries(out, entries []*scheduledAuth, predicate func(*scheduledAuth) bool, now time.Time) []*scheduledAuth {
	if len(entries) == 0 {
		return out
	}
	for _, entry := range entries {
		if !scheduledAuthExpiryPriorityEligible(entry, now) {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// scheduledAuthExpiryPriorityEligible mirrors authExpiryRemaining for the
// scheduler's precomputed entries. OAuth/token expirations must still be in
// the future, while supplier lease timestamps remain urgent after they pass.
func scheduledAuthExpiryPriorityEligible(entry *scheduledAuth, now time.Time) bool {
	if entry == nil || entry.expiresAt.IsZero() || entry.expiresAt.After(now.Add(authExpiryPriorityWindow)) {
		return false
	}
	return entry.expiresAt.After(now) || !entry.supplyLeaseExpiresAt.IsZero()
}

// narrowScheduledExpiryLane keeps the earliest healthy credentials in the
// active cold-request lane and extends through the boundary supplier cohort.
// This mirrors expiryPriorityAuths: expiry affects new allocation without
// moving established affinity bindings, while avoiding a one-minute cohort
// monopolizing all incoming sessions.
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
	boundary := authExpiryPriorityMinCandidates
	if boundary > len(entries) {
		boundary = len(entries)
	}
	cutoff := entries[boundary-1].expiresAt.Add(authExpiryCohortWindow)
	end := boundary
	for end < len(entries) && !entries[end].expiresAt.After(cutoff) {
		end++
	}
	return entries[:end]
}
