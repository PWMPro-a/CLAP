package auth

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// schedulerStrategy identifies which built-in routing semantics the scheduler should apply.
type schedulerStrategy int

const (
	schedulerStrategyCurrent            schedulerStrategy = -1
	schedulerStrategyCustom             schedulerStrategy = 0
	schedulerStrategyRoundRobin         schedulerStrategy = 1
	schedulerStrategyFillFirst          schedulerStrategy = 2
	schedulerStrategyWeightedRoundRobin schedulerStrategy = 3

	maxAccountGroupReadyViewCacheEntries = 64
	maxAccountGroupMixedStateEntries     = 256
)

// scheduledState describes how an auth currently participates in a model shard.
type scheduledState int

const (
	scheduledStateReady scheduledState = iota
	scheduledStateCooldown
	scheduledStateBlocked
	scheduledStateDisabled
)

// authScheduler keeps the incremental provider/model scheduling state used by Manager.
type authScheduler struct {
	mu                    sync.Mutex
	strategy              schedulerStrategy
	providers             map[string]*providerScheduler
	authProviders         map[string]string
	mixedCursors          map[string]int
	mixedWeightedStates   map[string]*smoothWeightedState
	mixedExpiryCursors    map[string]int
	mixedExpiryWeighted   map[string]*smoothWeightedState
	mixedGroupStateKeys   map[string]struct{}
	mixedGroupStateOrder  []string
	selectionModelForAuth func(*Auth, string) string
	quotaFallback         func([]*Auth, string, time.Time) *Auth
}

// providerScheduler stores auth metadata and model shards for a single provider.
type providerScheduler struct {
	providerKey string
	auths       map[string]*scheduledAuthMeta
	modelShards map[string]*modelScheduler
}

// scheduledAuthMeta stores the immutable scheduling fields derived from an auth snapshot.
type scheduledAuthMeta struct {
	auth              *Auth
	providerKey       string
	priority          int
	weight            int64
	websocketEnabled  bool
	canonicalIdentity string
	canonicalScore    int
	supportedModelSet map[string]struct{}
	selectionModelSet map[string]string
}

// modelScheduler tracks ready and blocked auths for one provider/model combination.
type modelScheduler struct {
	modelKey        string
	entries         map[string]*scheduledAuth
	priorityOrder   []int
	readyByPriority map[int]*readyBucket
	blocked         cooldownQueue
}

// scheduledAuth stores the runtime scheduling state for a single auth inside a model shard.
type scheduledAuth struct {
	meta                 *scheduledAuthMeta
	auth                 *Auth
	expiresAt            time.Time
	supplyLeaseExpiresAt time.Time
	state                scheduledState
	nextRetryAt          time.Time
}

// readyBucket keeps the ready views for one priority level.
type readyBucket struct {
	all             readyView
	ws              readyView
	groupViews      map[string]*readyView
	websocketGroups map[string]*readyView
	groupViewOrder  []string
	websocketOrder  []string
}

// readyView holds the selection order for flat round-robin traversal.
type readyView struct {
	flat                []*scheduledAuth
	cursor              int
	weightedState       smoothWeightedState
	expiryFlat          []*scheduledAuth
	expiryCursor        int
	expiryWeightedState smoothWeightedState
}

// cooldownQueue is the blocked auth collection ordered by next retry time during rebuilds.
type cooldownQueue []*scheduledAuth

type readyViewCursorState struct {
	cursor              int
	weightedState       smoothWeightedState
	expiryCursor        int
	expiryWeightedState smoothWeightedState
}

type readyBucketCursorState struct {
	all readyViewCursorState
	ws  readyViewCursorState
}

func snapshotReadyViewCursors(view readyView) readyViewCursorState {
	state := readyViewCursorState{cursor: view.cursor, expiryCursor: view.expiryCursor}
	state.weightedState = cloneSmoothWeightedState(view.weightedState)
	state.expiryWeightedState = cloneSmoothWeightedState(view.expiryWeightedState)
	return state
}

func cloneSmoothWeightedState(source smoothWeightedState) smoothWeightedState {
	clone := smoothWeightedState{}
	if len(source.current) > 0 {
		clone.current = make(map[string]int64, len(source.current))
		for authID, current := range source.current {
			clone.current[authID] = current
		}
	}
	if len(source.weights) > 0 {
		clone.weights = make(map[string]int64, len(source.weights))
		for authID, weight := range source.weights {
			clone.weights[authID] = weight
		}
	}
	return clone
}

func restoreReadyViewCursors(view *readyView, state readyViewCursorState) {
	if view == nil {
		return
	}
	if len(view.flat) > 0 {
		view.cursor = normalizeCursor(state.cursor, len(view.flat))
	}
	view.expiryCursor = normalizeCursor(state.expiryCursor, len(view.expiryFlat))
	weights := scheduledWeightVector(view.flat)
	if len(state.weightedState.current) > 0 && weightVectorsEqual(state.weightedState.weights, weights) {
		view.weightedState = state.weightedState
	} else {
		view.weightedState = smoothWeightedState{}
	}
	view.expiryWeightedState = state.expiryWeightedState
}

func normalizeCursor(cursor, size int) int {
	if size <= 0 || cursor <= 0 {
		return 0
	}
	cursor = cursor % size
	if cursor < 0 {
		cursor += size
	}
	return cursor
}

// newAuthScheduler constructs an empty scheduler configured for the supplied selector strategy.
func newAuthScheduler(selector Selector) *authScheduler {
	return &authScheduler{
		strategy:            selectorStrategy(selector),
		providers:           make(map[string]*providerScheduler),
		authProviders:       make(map[string]string),
		mixedCursors:        make(map[string]int),
		mixedWeightedStates: make(map[string]*smoothWeightedState),
		mixedExpiryCursors:  make(map[string]int),
		mixedExpiryWeighted: make(map[string]*smoothWeightedState),
		mixedGroupStateKeys: make(map[string]struct{}),
	}
}

// selectorStrategy maps a selector implementation to the scheduler semantics it should emulate.
func selectorStrategy(selector Selector) schedulerStrategy {
	switch selector.(type) {
	case *FillFirstSelector:
		return schedulerStrategyFillFirst
	case *WeightedRoundRobinSelector:
		return schedulerStrategyWeightedRoundRobin
	case nil, *RoundRobinSelector:
		return schedulerStrategyRoundRobin
	default:
		return schedulerStrategyCustom
	}
}

// setSelector updates the active built-in strategy and resets mixed-provider cursors.
func (s *authScheduler) setSelector(selector Selector) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strategy = selectorStrategy(selector)
	clear(s.mixedCursors)
	clear(s.mixedWeightedStates)
	clear(s.mixedExpiryCursors)
	clear(s.mixedExpiryWeighted)
	clear(s.mixedGroupStateKeys)
	s.mixedGroupStateOrder = s.mixedGroupStateOrder[:0]
}

func (s *authScheduler) setSelectionModelResolver(resolve func(*Auth, string) string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.selectionModelForAuth = resolve
	s.mu.Unlock()
}

func (s *authScheduler) setQuotaFallback(resolve func([]*Auth, string, time.Time) *Auth) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.quotaFallback = resolve
	s.mu.Unlock()
}

func (s *authScheduler) empty() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.authProviders) == 0
}

// rebuild recreates the complete scheduler state from an auth snapshot.
func (s *authScheduler) rebuild(auths []*Auth) {
	s.rebuildWithSelectionModels(auths, nil)
}

// rebuildWithSelectionModels rebuilds the index while retaining auth-specific
// route model keys supplied by Manager. This keeps aliases on the indexed path.
func (s *authScheduler) rebuildWithSelectionModels(auths []*Auth, selectionModels map[string]map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = make(map[string]*providerScheduler)
	s.authProviders = make(map[string]string)
	s.mixedCursors = make(map[string]int)
	s.mixedWeightedStates = make(map[string]*smoothWeightedState)
	s.mixedExpiryCursors = make(map[string]int)
	s.mixedExpiryWeighted = make(map[string]*smoothWeightedState)
	s.mixedGroupStateKeys = make(map[string]struct{})
	s.mixedGroupStateOrder = nil
	now := time.Now()
	for _, auth := range auths {
		var modelSet map[string]string
		if selectionModels != nil && auth != nil {
			modelSet = selectionModels[auth.ID]
		}
		s.upsertAuthLockedWithSelectionModels(auth, now, modelSet)
	}
}

// upsertAuth incrementally synchronizes one auth into the scheduler.
func (s *authScheduler) upsertAuth(auth *Auth) {
	s.upsertAuthWithSelectionModels(auth, nil)
}

func (s *authScheduler) upsertAuthWithSelectionModels(auth *Auth, selectionModels map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertAuthLockedWithSelectionModels(auth, time.Now(), selectionModels)
}

// snapshotCandidates returns indexed auth snapshots for the requested route.
// It is intentionally independent of Manager.auths so request-time selection
// never falls back to a full map scan in new-candidate mode.
func (s *authScheduler) snapshotCandidates(providers []string, model string) []*Auth {
	if s == nil {
		return nil
	}
	normalized := normalizeProviderKeys(providers)
	modelKey := canonicalModelKey(model)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{})
	canonical := make(map[string]*scheduledAuth)
	out := make([]*Auth, 0)
	for _, providerKey := range normalized {
		providerState := s.providers[providerKey]
		if providerState == nil {
			continue
		}
		shard := providerState.ensureModelLocked(modelKey, now)
		if shard == nil {
			continue
		}
		for authID, entry := range shard.entries {
			if _, ok := seen[authID]; ok || entry == nil || entry.auth == nil {
				continue
			}
			seen[authID] = struct{}{}
			identityKey := codexCanonicalIdentityKey(entry.auth)
			if identityKey == "" {
				out = append(out, entry.auth.Clone())
				continue
			}
			canonical[identityKey] = preferScheduledCanonicalEntry(canonical[identityKey], entry)
		}
	}
	for _, entry := range canonical {
		out = append(out, entry.auth.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *authScheduler) snapshotAuth(authID string) *Auth {
	if s == nil {
		return nil
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	providerKey := s.authProviders[authID]
	providerState := s.providers[providerKey]
	if providerState == nil {
		return nil
	}
	meta := providerState.auths[authID]
	if meta == nil || meta.auth == nil {
		return nil
	}
	return meta.auth.Clone()
}

// removeAuth deletes one auth from every scheduler shard that references it.
func (s *authScheduler) removeAuth(authID string) {
	if s == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeAuthLocked(authID)
}

// pickSingle returns the next auth for a single provider/model request using scheduler state.
func (s *authScheduler) pickSingle(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
	return s.pickSingleWithStrategy(ctx, provider, model, opts, tried, schedulerStrategyCurrent)
}

func (s *authScheduler) pickSingleWithStrategy(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, strategy schedulerStrategy) (*Auth, error) {
	if s == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	modelKey := canonicalModelKey(model)
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	preferWebsocket := pinnedAuthID == "" && providerPrefersWebsocketTransport(providerKey) &&
		(cliproxyexecutor.DownstreamWebsocket(ctx) || (opts.Stream && strings.EqualFold(providerKey, "codex")))

	s.mu.Lock()
	defer s.mu.Unlock()
	if strategy == schedulerStrategyCurrent {
		strategy = s.strategy
	}
	providerState := s.providers[providerKey]
	if providerState == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	now := time.Now()
	shard := providerState.ensureModelLocked(modelKey, now)
	if shard == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	predicate := scheduledAuthPredicate(eligibility, tried, pinnedAuthID, strategy == schedulerStrategyWeightedRoundRobin, now)
	groups := eligibility.accountGroups()
	if picked := shard.pickReadyLocked(preferWebsocket, strategy, predicate, groups); picked != nil {
		return picked, nil
	}
	if s.quotaFallback != nil && providerKey == "codex" {
		if fallback := s.quotaFallback(shard.candidateAuthsLocked(predicate), model, now); fallback != nil {
			return fallback, nil
		}
	}
	return nil, shard.unavailableErrorLocked(provider, model, predicate)
}

func providerPrefersWebsocketTransport(providerKey string) bool {
	switch strings.ToLower(strings.TrimSpace(providerKey)) {
	case "codex", "xai":
		return true
	default:
		return false
	}
}

// pickMixed returns the next auth and provider for a mixed-provider request.
func (s *authScheduler) pickMixed(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, string, error) {
	return s.pickMixedWithStrategy(ctx, providers, model, opts, tried, schedulerStrategyCurrent)
}

func (s *authScheduler) pickMixedWithStrategy(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, strategy schedulerStrategy) (*Auth, string, error) {
	if s == nil {
		return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	normalized := normalizeProviderKeys(providers)
	if len(normalized) == 0 {
		return nil, "", &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	if len(normalized) == 1 {
		// When a single provider is eligible, reuse pickSingle so provider-specific preferences
		// (for example Codex websocket transport) are applied consistently.
		providerKey := normalized[0]
		picked, errPick := s.pickSingleWithStrategy(ctx, providerKey, model, opts, tried, strategy)
		if errPick != nil {
			return nil, "", errPick
		}
		if picked == nil {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		return picked, providerKey, nil
	}
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	modelKey := canonicalModelKey(model)

	s.mu.Lock()
	defer s.mu.Unlock()
	if strategy == schedulerStrategyCurrent {
		strategy = s.strategy
	}
	if pinnedAuthID != "" {
		now := time.Now()
		providerKey := s.authProviders[pinnedAuthID]
		if providerKey == "" || !containsProvider(normalized, providerKey) {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		providerState := s.providers[providerKey]
		if providerState == nil {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		shard := providerState.ensureModelLocked(modelKey, now)
		predicate := scheduledAuthPredicate(eligibility, tried, pinnedAuthID, strategy == schedulerStrategyWeightedRoundRobin, now)
		groups := eligibility.accountGroups()
		if picked := shard.pickReadyLocked(false, strategy, predicate, groups); picked != nil {
			return picked, providerKey, nil
		}
		return nil, "", shard.unavailableErrorLocked("mixed", model, predicate)
	}

	now := time.Now()
	predicate := scheduledAuthPredicate(eligibility, tried, "", strategy == schedulerStrategyWeightedRoundRobin, now)
	groups := eligibility.accountGroups()
	candidateShards := make([]*modelScheduler, len(normalized))
	bestPriority := 0
	hasCandidate := false
	for providerIndex, providerKey := range normalized {
		providerState := s.providers[providerKey]
		if providerState == nil {
			continue
		}
		shard := providerState.ensureModelLocked(modelKey, now)
		candidateShards[providerIndex] = shard
		if shard == nil {
			continue
		}
		priorityReady, okPriority := shard.highestReadyPriorityLocked(false, predicate, groups)
		if !okPriority {
			continue
		}
		if !hasCandidate || priorityReady > bestPriority {
			bestPriority = priorityReady
			hasCandidate = true
		}
	}
	if !hasCandidate {
		if s.quotaFallback != nil && containsProvider(normalized, "codex") {
			candidates := make([]*Auth, 0)
			for _, shard := range candidateShards {
				if shard != nil {
					candidates = append(candidates, shard.candidateAuthsLocked(predicate)...)
				}
			}
			if fallback := s.quotaFallback(candidates, model, now); fallback != nil {
				return fallback, executorKeyFromAuth(fallback), nil
			}
		}
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
	}

	cursorKey := strings.Join(normalized, ",") + ":" + modelKey
	if groups != nil && groups.key != "" {
		cursorKey += ":groups=" + groups.key
		if strategy != schedulerStrategyFillFirst {
			s.retainMixedGroupStateKeyLocked(cursorKey)
		}
	}
	expiringEntries := make([]*scheduledAuth, 0)
	for _, shard := range candidateShards {
		if shard == nil {
			continue
		}
		bucket := shard.readyByPriority[bestPriority]
		if bucket == nil {
			continue
		}
		view := bucket.view(false, groups)
		expiringEntries = append(expiringEntries, expiringScheduledEntries(view.flat, predicate, now)...)
	}
	if len(expiringEntries) > 0 {
		expiringEntries = narrowScheduledExpiryLane(expiringEntries)
		switch strategy {
		case schedulerStrategyFillFirst:
			picked := expiringEntries[0]
			return picked.auth, picked.meta.providerKey, nil
		case schedulerStrategyWeightedRoundRobin:
			if s.mixedExpiryWeighted == nil {
				s.mixedExpiryWeighted = make(map[string]*smoothWeightedState)
			}
			state := s.mixedExpiryWeighted[cursorKey]
			if state == nil {
				state = &smoothWeightedState{}
				s.mixedExpiryWeighted[cursorKey] = state
			}
			state.prepare(scheduledWeightVectorMatching(expiringEntries, predicate))
			picked := pickSmoothWeightedScheduled(expiringEntries, state.current, predicate)
			if picked != nil && picked.meta != nil {
				return picked.auth, picked.meta.providerKey, nil
			}
		default:
			start := s.mixedExpiryCursors[cursorKey] % len(expiringEntries)
			picked := expiringEntries[start]
			s.mixedExpiryCursors[cursorKey] = start + 1
			return picked.auth, picked.meta.providerKey, nil
		}
	}

	if strategy == schedulerStrategyFillFirst {
		for providerIndex, providerKey := range normalized {
			shard := candidateShards[providerIndex]
			if shard == nil {
				continue
			}
			picked := shard.pickReadyAtPriorityLocked(false, bestPriority, strategy, predicate, groups)
			if picked != nil {
				return picked, providerKey, nil
			}
		}
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
	}

	if strategy == schedulerStrategyWeightedRoundRobin {
		entries := make([]*scheduledAuth, 0)
		for _, shard := range candidateShards {
			if shard == nil {
				continue
			}
			bucket := shard.readyByPriority[bestPriority]
			if bucket != nil {
				entries = append(entries, bucket.view(false, groups).flat...)
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i] == nil || entries[i].auth == nil {
				return false
			}
			if entries[j] == nil || entries[j].auth == nil {
				return true
			}
			return entries[i].auth.ID < entries[j].auth.ID
		})
		if s.mixedWeightedStates == nil {
			s.mixedWeightedStates = make(map[string]*smoothWeightedState)
		}
		state := s.mixedWeightedStates[cursorKey]
		if state == nil {
			state = &smoothWeightedState{}
			s.mixedWeightedStates[cursorKey] = state
		}
		state.prepare(scheduledWeightVectorMatching(entries, predicate))
		picked := pickSmoothWeightedScheduled(entries, state.current, predicate)
		if picked != nil && picked.meta != nil {
			return picked.auth, picked.meta.providerKey, nil
		}
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
	}

	weights := make([]int, len(normalized))
	segmentStarts := make([]int, len(normalized))
	segmentEnds := make([]int, len(normalized))
	totalWeight := 0
	for providerIndex, shard := range candidateShards {
		segmentStarts[providerIndex] = totalWeight
		if shard != nil {
			weights[providerIndex] = shard.readyCountAtPriorityLocked(false, bestPriority, predicate, groups)
		}
		totalWeight += weights[providerIndex]
		segmentEnds[providerIndex] = totalWeight
	}
	if totalWeight == 0 {
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
	}

	startSlot := s.mixedCursors[cursorKey] % totalWeight
	startProviderIndex := -1
	for providerIndex := range normalized {
		if weights[providerIndex] == 0 {
			continue
		}
		if startSlot < segmentEnds[providerIndex] {
			startProviderIndex = providerIndex
			break
		}
	}
	if startProviderIndex < 0 {
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
	}

	slot := startSlot
	for offset := 0; offset < len(normalized); offset++ {
		providerIndex := (startProviderIndex + offset) % len(normalized)
		if weights[providerIndex] == 0 {
			continue
		}
		if providerIndex != startProviderIndex {
			slot = segmentStarts[providerIndex]
		}
		providerKey := normalized[providerIndex]
		shard := candidateShards[providerIndex]
		if shard == nil {
			continue
		}
		picked := shard.pickReadyAtPriorityLocked(false, bestPriority, schedulerStrategyRoundRobin, predicate, groups)
		if picked == nil {
			continue
		}
		s.mixedCursors[cursorKey] = slot + 1
		return picked, providerKey, nil
	}
	return nil, "", s.mixedUnavailableErrorLocked(normalized, model, predicate)
}

// mixedUnavailableErrorLocked synthesizes the mixed-provider cooldown or unavailable error.
func (s *authScheduler) mixedUnavailableErrorLocked(providers []string, model string, predicate func(*scheduledAuth) bool) error {
	now := time.Now()
	total := 0
	cooldownCount := 0
	earliest := time.Time{}
	for _, providerKey := range providers {
		providerState := s.providers[providerKey]
		if providerState == nil {
			continue
		}
		shard := providerState.ensureModelLocked(canonicalModelKey(model), now)
		if shard == nil {
			continue
		}
		localTotal, localCooldownCount, localEarliest := shard.availabilitySummaryLocked(predicate)
		total += localTotal
		cooldownCount += localCooldownCount
		if !localEarliest.IsZero() && (earliest.IsZero() || localEarliest.Before(earliest)) {
			earliest = localEarliest
		}
	}
	if total == 0 {
		return &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if cooldownCount == total && !earliest.IsZero() {
		resetIn := earliest.Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		return newModelCooldownError(model, "", resetIn)
	}
	return &Error{Code: "auth_unavailable", Message: "no auth available"}
}

// scheduledAuthPredicate filters request-ineligible auths before scheduler state advances.
func scheduledAuthPredicate(eligibility authSelectionEligibility, tried map[string]struct{}, pinnedAuthID string, requirePositiveWeight bool, now time.Time) func(*scheduledAuth) bool {
	return func(entry *scheduledAuth) bool {
		if entry == nil || entry.auth == nil || !eligibility.allows(entry.auth) {
			return false
		}
		if !entry.supplyLeaseExpiresAt.IsZero() && !entry.supplyLeaseExpiresAt.After(now) {
			return false
		}
		if requirePositiveWeight && (entry.meta == nil || entry.meta.weight <= 0) {
			return false
		}
		if pinnedAuthID != "" && entry.auth.ID != pinnedAuthID {
			return false
		}
		if len(tried) > 0 {
			if _, ok := tried[entry.auth.ID]; ok {
				return false
			}
		}
		return true
	}
}

func (s *authScheduler) retainMixedGroupStateKeyLocked(key string) {
	if s == nil || key == "" {
		return
	}
	if s.mixedGroupStateKeys == nil {
		s.mixedGroupStateKeys = make(map[string]struct{})
	}
	if _, exists := s.mixedGroupStateKeys[key]; exists {
		return
	}
	if len(s.mixedGroupStateOrder) >= maxAccountGroupMixedStateEntries {
		oldest := s.mixedGroupStateOrder[0]
		s.mixedGroupStateOrder = s.mixedGroupStateOrder[1:]
		delete(s.mixedGroupStateKeys, oldest)
		delete(s.mixedCursors, oldest)
		delete(s.mixedWeightedStates, oldest)
		delete(s.mixedExpiryCursors, oldest)
		delete(s.mixedExpiryWeighted, oldest)
	}
	s.mixedGroupStateKeys[key] = struct{}{}
	s.mixedGroupStateOrder = append(s.mixedGroupStateOrder, key)
}

// normalizeProviderKeys lowercases, trims, and de-duplicates provider keys while preserving order.
func normalizeProviderKeys(providers []string) []string {
	seen := make(map[string]struct{}, len(providers))
	out := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerKey := strings.ToLower(strings.TrimSpace(provider))
		if providerKey == "" {
			continue
		}
		if _, ok := seen[providerKey]; ok {
			continue
		}
		seen[providerKey] = struct{}{}
		out = append(out, providerKey)
	}
	return out
}

// containsProvider reports whether provider is present in the normalized provider list.
func containsProvider(providers []string, provider string) bool {
	for _, candidate := range providers {
		if candidate == provider {
			return true
		}
	}
	return false
}

// upsertAuthLocked updates one auth in-place while the scheduler mutex is held.
func (s *authScheduler) upsertAuthLocked(auth *Auth, now time.Time) {
	s.upsertAuthLockedWithSelectionModels(auth, now, nil)
}

func (s *authScheduler) upsertAuthLockedWithSelectionModels(auth *Auth, now time.Time, selectionModels map[string]string) {
	if auth == nil {
		return
	}
	authID := strings.TrimSpace(auth.ID)
	providerKey := executorKeyFromAuth(auth)
	if authID == "" || providerKey == "" || auth.Disabled {
		s.removeAuthLocked(authID)
		return
	}
	if previousProvider := s.authProviders[authID]; previousProvider != "" && previousProvider != providerKey {
		if previousState := s.providers[previousProvider]; previousState != nil {
			previousState.removeAuthLocked(authID)
		}
	}
	if selectionModels == nil {
		selectionModels = s.selectionModelsForAuthLocked(auth)
	}
	meta := buildScheduledAuthMetaWithSelectionModels(auth, selectionModels)
	s.authProviders[authID] = providerKey
	s.ensureProviderLocked(providerKey).upsertAuthLocked(meta, now)
}

func (s *authScheduler) selectionModelsForAuthLocked(auth *Auth) map[string]string {
	if auth == nil {
		return nil
	}
	registered := supportedModelSetForAuth(auth.ID)
	if len(registered) == 0 {
		return nil
	}
	out := make(map[string]string, len(registered))
	for routeModel := range registered {
		selectionModel := routeModel
		if s.selectionModelForAuth != nil {
			selectionModel = canonicalModelKey(s.selectionModelForAuth(auth, routeModel))
		}
		if selectionModel == "" {
			selectionModel = routeModel
		}
		out[routeModel] = selectionModel
	}
	return out
}

// removeAuthLocked removes one auth from the scheduler while the scheduler mutex is held.
func (s *authScheduler) removeAuthLocked(authID string) {
	if authID == "" {
		return
	}
	if providerKey := s.authProviders[authID]; providerKey != "" {
		if providerState := s.providers[providerKey]; providerState != nil {
			providerState.removeAuthLocked(authID)
		}
		delete(s.authProviders, authID)
	}
}

// ensureProviderLocked returns the provider scheduler for providerKey, creating it when needed.
func (s *authScheduler) ensureProviderLocked(providerKey string) *providerScheduler {
	if s.providers == nil {
		s.providers = make(map[string]*providerScheduler)
	}
	providerState := s.providers[providerKey]
	if providerState == nil {
		providerState = &providerScheduler{
			providerKey: providerKey,
			auths:       make(map[string]*scheduledAuthMeta),
			modelShards: make(map[string]*modelScheduler),
		}
		s.providers[providerKey] = providerState
	}
	return providerState
}

// buildScheduledAuthMeta extracts the scheduling metadata needed for shard bookkeeping.
func buildScheduledAuthMeta(auth *Auth) *scheduledAuthMeta {
	return buildScheduledAuthMetaWithSelectionModels(auth, nil)
}

func buildScheduledAuthMetaWithSelectionModels(auth *Auth, selectionModels map[string]string) *scheduledAuthMeta {
	// The scheduler owns an immutable credential snapshot. Manager lifecycle
	// workers mutate their stored Auth under a different mutex, so retaining a
	// caller-owned pointer here can race token/quota recovery against request
	// selection and crash on concurrent Metadata map access.
	auth = auth.Clone()
	if auth == nil {
		return nil
	}
	providerKey := executorKeyFromAuth(auth)
	selectionModelSet := make(map[string]string)
	if selectionModels == nil {
		for modelKey := range supportedModelSetForAuth(auth.ID) {
			selectionModelSet[modelKey] = modelKey
		}
	} else {
		for routeModel, selectionModel := range selectionModels {
			routeKey := canonicalModelKey(routeModel)
			selectionKey := canonicalModelKey(selectionModel)
			if routeKey != "" && selectionKey != "" {
				selectionModelSet[routeKey] = selectionKey
			}
		}
	}
	if len(selectionModelSet) == 0 && auth != nil {
		selectionModelSet[""] = ""
	}
	modelSet := make(map[string]struct{}, len(selectionModelSet))
	for routeModel := range selectionModelSet {
		modelSet[routeModel] = struct{}{}
	}
	return &scheduledAuthMeta{
		auth:              auth,
		providerKey:       providerKey,
		priority:          authPriority(auth),
		weight:            authWeight(auth),
		websocketEnabled:  authWebsocketsEnabled(auth),
		canonicalIdentity: codexCanonicalIdentityKey(auth),
		canonicalScore:    canonicalAuthPreferenceScore(auth),
		supportedModelSet: modelSet,
		selectionModelSet: selectionModelSet,
	}
}

// supportedModelSetForAuth snapshots the registry models currently registered for an auth.
func supportedModelSetForAuth(authID string) map[string]struct{} {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil
	}
	models := registry.GetGlobalRegistry().GetModelsForClient(authID)
	if len(models) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelKey := canonicalModelKey(model.ID)
		if modelKey == "" {
			continue
		}
		set[modelKey] = struct{}{}
	}
	return set
}

// upsertAuthLocked updates every existing model shard that can reference the auth metadata.
func (p *providerScheduler) upsertAuthLocked(meta *scheduledAuthMeta, now time.Time) {
	if p == nil || meta == nil || meta.auth == nil {
		return
	}
	p.auths[meta.auth.ID] = meta
	for modelKey, shard := range p.modelShards {
		if shard == nil {
			continue
		}
		if !meta.supportsModel(modelKey) {
			shard.removeEntryLocked(meta.auth.ID)
			continue
		}
		shard.upsertEntryLocked(meta, now)
	}
}

// removeAuthLocked removes an auth from all model shards owned by the provider scheduler.
func (p *providerScheduler) removeAuthLocked(authID string) {
	if p == nil || authID == "" {
		return
	}
	delete(p.auths, authID)
	for _, shard := range p.modelShards {
		if shard != nil {
			shard.removeEntryLocked(authID)
		}
	}
}

// ensureModelLocked returns the shard for modelKey, building it lazily from provider auths.
func (p *providerScheduler) ensureModelLocked(modelKey string, now time.Time) *modelScheduler {
	if p == nil {
		return nil
	}
	modelKey = canonicalModelKey(modelKey)
	if shard, ok := p.modelShards[modelKey]; ok && shard != nil {
		shard.promoteExpiredLocked(now)
		return shard
	}
	shard := &modelScheduler{
		modelKey:        modelKey,
		entries:         make(map[string]*scheduledAuth),
		readyByPriority: make(map[int]*readyBucket),
	}
	for _, meta := range p.auths {
		if meta == nil || !meta.supportsModel(modelKey) {
			continue
		}
		shard.upsertEntryLocked(meta, now)
	}
	p.modelShards[modelKey] = shard
	return shard
}

// supportsModel reports whether the auth metadata currently supports modelKey.
func (m *scheduledAuthMeta) supportsModel(modelKey string) bool {
	modelKey = canonicalModelKey(modelKey)
	if modelKey == "" {
		return true
	}
	if len(m.supportedModelSet) == 0 && len(m.selectionModelSet) == 0 {
		return false
	}
	_, ok := m.supportedModelSet[modelKey]
	if !ok {
		_, ok = m.selectionModelSet[modelKey]
	}
	return ok
}

func (m *scheduledAuthMeta) selectionModelForRoute(routeModel string) string {
	routeModel = canonicalModelKey(routeModel)
	if m != nil && m.selectionModelSet != nil {
		if selectionModel := strings.TrimSpace(m.selectionModelSet[routeModel]); selectionModel != "" {
			return selectionModel
		}
	}
	return routeModel
}

// upsertEntryLocked updates or inserts one auth entry and rebuilds indexes when ordering changes.
func (m *modelScheduler) upsertEntryLocked(meta *scheduledAuthMeta, now time.Time) {
	if m == nil || meta == nil || meta.auth == nil {
		return
	}
	entry, ok := m.entries[meta.auth.ID]
	if !ok || entry == nil {
		entry = &scheduledAuth{}
		m.entries[meta.auth.ID] = entry
	}
	previousState := entry.state
	previousNextRetryAt := entry.nextRetryAt
	previousPriority := 0
	previousWebsocketEnabled := false
	previousCanonicalIdentity := ""
	previousCanonicalScore := 0
	previousExpiresAt := time.Time{}
	previousSupplyLeaseExpiresAt := time.Time{}
	var previousGroupIDs []int64
	if entry.meta != nil {
		previousPriority = entry.meta.priority
		previousWebsocketEnabled = entry.meta.websocketEnabled
		previousCanonicalIdentity = entry.meta.canonicalIdentity
		previousCanonicalScore = entry.meta.canonicalScore
		previousExpiresAt = entry.expiresAt
		previousSupplyLeaseExpiresAt = entry.supplyLeaseExpiresAt
		previousGroupIDs = entry.auth.groupIDs
	}

	entry.meta = meta
	entry.auth = meta.auth
	entry.expiresAt = time.Time{}
	entry.supplyLeaseExpiresAt = time.Time{}
	if expiresAt, ok := authSupplyLeaseExpirationTime(meta.auth); ok {
		entry.supplyLeaseExpiresAt = expiresAt
		entry.expiresAt = expiresAt
	} else if expiresAt, ok := meta.auth.ExpirationTime(); ok {
		entry.expiresAt = expiresAt
	}
	entry.nextRetryAt = time.Time{}
	blocked, reason, next := isAuthBlockedForModel(meta.auth, meta.selectionModelForRoute(m.modelKey), now)
	switch {
	case !blocked:
		entry.state = scheduledStateReady
	case reason == blockReasonCooldown:
		entry.state = scheduledStateCooldown
		entry.nextRetryAt = next
	case reason == blockReasonDisabled:
		entry.state = scheduledStateDisabled
	default:
		entry.state = scheduledStateBlocked
		entry.nextRetryAt = next
	}

	if ok && previousState == entry.state && previousNextRetryAt.Equal(entry.nextRetryAt) && previousPriority == meta.priority &&
		previousWebsocketEnabled == meta.websocketEnabled && previousCanonicalIdentity == meta.canonicalIdentity &&
		previousCanonicalScore == meta.canonicalScore && previousExpiresAt.Equal(entry.expiresAt) &&
		previousSupplyLeaseExpiresAt.Equal(entry.supplyLeaseExpiresAt) && slices.Equal(previousGroupIDs, meta.auth.groupIDs) {
		return
	}
	m.rebuildIndexesLocked()
}

// removeEntryLocked deletes one auth entry and rebuilds the shard indexes if needed.
func (m *modelScheduler) removeEntryLocked(authID string) {
	if m == nil || authID == "" {
		return
	}
	if _, ok := m.entries[authID]; !ok {
		return
	}
	delete(m.entries, authID)
	m.rebuildIndexesLocked()
}

// promoteExpiredLocked reevaluates blocked auths whose retry time has elapsed.
func (m *modelScheduler) promoteExpiredLocked(now time.Time) {
	if m == nil || len(m.blocked) == 0 {
		return
	}
	changed := false
	for _, entry := range m.blocked {
		if entry == nil || entry.auth == nil {
			continue
		}
		if entry.nextRetryAt.IsZero() || entry.nextRetryAt.After(now) {
			continue
		}
		blocked, reason, next := isAuthBlockedForModel(entry.auth, entry.meta.selectionModelForRoute(m.modelKey), now)
		switch {
		case !blocked:
			entry.state = scheduledStateReady
			entry.nextRetryAt = time.Time{}
		case reason == blockReasonCooldown:
			entry.state = scheduledStateCooldown
			entry.nextRetryAt = next
		case reason == blockReasonDisabled:
			entry.state = scheduledStateDisabled
			entry.nextRetryAt = time.Time{}
		default:
			entry.state = scheduledStateBlocked
			entry.nextRetryAt = next
		}
		changed = true
	}
	if changed {
		m.rebuildIndexesLocked()
	}
}

// pickReadyLocked selects the next ready auth from the highest available priority bucket.
func (m *modelScheduler) pickReadyLocked(preferWebsocket bool, strategy schedulerStrategy, predicate func(*scheduledAuth) bool, groups *accountGroupSelection) *Auth {
	if m == nil {
		return nil
	}
	m.promoteExpiredLocked(time.Now())
	priorityReady, okPriority := m.highestReadyPriorityLocked(preferWebsocket, predicate, groups)
	if !okPriority {
		return nil
	}
	return m.pickReadyAtPriorityLocked(preferWebsocket, priorityReady, strategy, predicate, groups)
}

// highestReadyPriorityLocked returns the highest priority bucket that still has a matching ready auth.
// The caller must ensure expired entries are already promoted when needed.
func (m *modelScheduler) highestReadyPriorityLocked(preferWebsocket bool, predicate func(*scheduledAuth) bool, groups *accountGroupSelection) (int, bool) {
	if m == nil {
		return 0, false
	}
	if preferWebsocket {
		// When downstream is websocket and Codex supports websocket transport, prefer websocket-enabled
		// credentials even if they are in a lower priority tier than HTTP-only credentials.
		for _, priority := range m.priorityOrder {
			bucket := m.readyByPriority[priority]
			if bucket == nil {
				continue
			}
			if bucket.view(true, groups).pickFirst(predicate) != nil {
				return priority, true
			}
		}
	}
	for _, priority := range m.priorityOrder {
		bucket := m.readyByPriority[priority]
		if bucket == nil {
			continue
		}
		if bucket.view(false, groups).pickFirst(predicate) != nil {
			return priority, true
		}
	}
	return 0, false
}

// pickReadyAtPriorityLocked selects the next ready auth from a specific priority bucket.
// The caller must ensure expired entries are already promoted when needed.
func (m *modelScheduler) pickReadyAtPriorityLocked(preferWebsocket bool, priority int, strategy schedulerStrategy, predicate func(*scheduledAuth) bool, groups *accountGroupSelection) *Auth {
	if m == nil {
		return nil
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return nil
	}
	view := bucket.view(false, groups)
	if preferWebsocket && bucket.view(true, groups).pickFirst(predicate) != nil {
		view = bucket.view(true, groups)
	}
	if picked := view.pickExpiring(predicate, strategy, time.Now()); picked != nil {
		return picked.auth
	}
	var picked *scheduledAuth
	switch strategy {
	case schedulerStrategyFillFirst:
		picked = view.pickFirst(predicate)
	case schedulerStrategyWeightedRoundRobin:
		picked = view.pickWeighted(predicate)
	default:
		picked = view.pickRoundRobin(predicate)
	}
	if picked == nil || picked.auth == nil {
		return nil
	}
	return picked.auth
}

func (m *modelScheduler) readyCountAtPriorityLocked(preferWebsocket bool, priority int, predicate func(*scheduledAuth) bool, groups *accountGroupSelection) int {
	if m == nil {
		return 0
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return 0
	}
	view := bucket.view(false, groups)
	if preferWebsocket && bucket.view(true, groups).pickFirst(predicate) != nil {
		view = bucket.view(true, groups)
	}
	count := 0
	for _, entry := range view.flat {
		if predicate == nil || predicate(entry) {
			count++
		}
	}
	return count
}

// unavailableErrorLocked returns the correct unavailable or cooldown error for the shard.
func (m *modelScheduler) unavailableErrorLocked(provider, model string, predicate func(*scheduledAuth) bool) error {
	now := time.Now()
	total, cooldownCount, earliest := m.availabilitySummaryLocked(predicate)
	if total == 0 {
		return &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if cooldownCount == total && !earliest.IsZero() {
		providerForError := provider
		if providerForError == "mixed" {
			providerForError = ""
		}
		resetIn := earliest.Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		return newModelCooldownError(model, providerForError, resetIn)
	}
	return &Error{Code: "auth_unavailable", Message: "no auth available"}
}

// availabilitySummaryLocked summarizes total candidates, cooldown count, and earliest retry time.
func (m *modelScheduler) availabilitySummaryLocked(predicate func(*scheduledAuth) bool) (int, int, time.Time) {
	if m == nil {
		return 0, 0, time.Time{}
	}
	total := 0
	cooldownCount := 0
	earliest := time.Time{}
	for _, entry := range m.uniqueCandidateEntriesLocked(predicate) {
		total++
		if entry == nil || entry.auth == nil {
			continue
		}
		if entry.state != scheduledStateCooldown {
			continue
		}
		cooldownCount++
		if !entry.nextRetryAt.IsZero() && (earliest.IsZero() || entry.nextRetryAt.Before(earliest)) {
			earliest = entry.nextRetryAt
		}
	}
	return total, cooldownCount, earliest
}

func (m *modelScheduler) candidateAuthsLocked(predicate func(*scheduledAuth) bool) []*Auth {
	if m == nil {
		return nil
	}
	out := make([]*Auth, 0, len(m.entries))
	for _, entry := range m.uniqueCandidateEntriesLocked(predicate) {
		out = append(out, entry.auth)
	}
	return out
}

func (m *modelScheduler) uniqueCandidateEntriesLocked(predicate func(*scheduledAuth) bool) []*scheduledAuth {
	if m == nil {
		return nil
	}
	out := make([]*scheduledAuth, 0, len(m.entries))
	canonical := make(map[string]*scheduledAuth)
	for _, entry := range m.entries {
		if entry == nil || entry.auth == nil || (predicate != nil && !predicate(entry)) {
			continue
		}
		identityKey := codexCanonicalIdentityKey(entry.auth)
		if identityKey == "" {
			out = append(out, entry)
			continue
		}
		current := canonical[identityKey]
		canonical[identityKey] = preferScheduledCanonicalEntry(current, entry)
	}
	for _, entry := range canonical {
		out = append(out, entry)
	}
	return out
}

// rebuildIndexesLocked reconstructs ready and blocked views from the current entry map.
func (m *modelScheduler) rebuildIndexesLocked() {
	cursorStates := make(map[int]readyBucketCursorState, len(m.readyByPriority))
	for priority, bucket := range m.readyByPriority {
		if bucket == nil {
			continue
		}
		cursorStates[priority] = readyBucketCursorState{
			all: snapshotReadyViewCursors(bucket.all),
			ws:  snapshotReadyViewCursors(bucket.ws),
		}
	}

	m.readyByPriority = make(map[int]*readyBucket)
	m.priorityOrder = m.priorityOrder[:0]
	m.blocked = m.blocked[:0]
	priorityBuckets := make(map[int][]*scheduledAuth)
	for _, entry := range m.uniqueCandidateEntriesLocked(nil) {
		if entry == nil || entry.auth == nil {
			continue
		}
		switch entry.state {
		case scheduledStateReady:
			priority := entry.meta.priority
			priorityBuckets[priority] = append(priorityBuckets[priority], entry)
		case scheduledStateCooldown, scheduledStateBlocked:
			m.blocked = append(m.blocked, entry)
		}
	}
	for priority, entries := range priorityBuckets {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].auth.ID < entries[j].auth.ID
		})
		bucket := buildReadyBucket(entries)
		if cursorState, ok := cursorStates[priority]; ok && bucket != nil {
			restoreReadyViewCursors(&bucket.all, cursorState.all)
			restoreReadyViewCursors(&bucket.ws, cursorState.ws)
		}
		m.readyByPriority[priority] = bucket
		m.priorityOrder = append(m.priorityOrder, priority)
	}
	sort.Slice(m.priorityOrder, func(i, j int) bool {
		return m.priorityOrder[i] > m.priorityOrder[j]
	})
	sort.Slice(m.blocked, func(i, j int) bool {
		left := m.blocked[i]
		right := m.blocked[j]
		if left == nil || right == nil {
			return left != nil
		}
		if left.nextRetryAt.Equal(right.nextRetryAt) {
			return left.auth.ID < right.auth.ID
		}
		if left.nextRetryAt.IsZero() {
			return false
		}
		if right.nextRetryAt.IsZero() {
			return true
		}
		return left.nextRetryAt.Before(right.nextRetryAt)
	})
}

// buildReadyBucket prepares the general and websocket-only ready views for one priority bucket.
func buildReadyBucket(entries []*scheduledAuth) *readyBucket {
	bucket := &readyBucket{
		groupViews:      make(map[string]*readyView),
		websocketGroups: make(map[string]*readyView),
	}
	bucket.all = buildReadyView(entries)
	wsEntries := make([]*scheduledAuth, 0, len(entries))
	for _, entry := range entries {
		if entry != nil && entry.meta != nil && entry.meta.websocketEnabled {
			wsEntries = append(wsEntries, entry)
		}
	}
	bucket.ws = buildReadyView(wsEntries)
	return bucket
}

func (b *readyBucket) view(websocketOnly bool, groups *accountGroupSelection) *readyView {
	if b == nil {
		return &readyView{}
	}
	base := &b.all
	cache := b.groupViews
	order := &b.groupViewOrder
	if websocketOnly {
		base = &b.ws
		cache = b.websocketGroups
		order = &b.websocketOrder
	}
	if groups == nil || len(groups.ids) == 0 {
		return base
	}
	key := strings.TrimSpace(groups.key)
	if key == "" {
		key = accountGroupSelectionKey(groups.ids)
	}
	if cached := cache[key]; cached != nil {
		return cached
	}
	entries := make([]*scheduledAuth, 0)
	for _, entry := range base.flat {
		if entry != nil && entry.auth != nil && entry.auth.matchesAnyGroup(groups.ids) {
			entries = append(entries, entry)
		}
	}
	view := buildReadyView(entries)
	if len(cache) >= maxAccountGroupReadyViewCacheEntries && len(*order) > 0 {
		oldest := (*order)[0]
		*order = (*order)[1:]
		delete(cache, oldest)
	}
	cache[key] = &view
	*order = append(*order, key)
	return &view
}

// buildReadyView creates a flat view for rotation.
func buildReadyView(entries []*scheduledAuth) readyView {
	view := readyView{flat: append([]*scheduledAuth(nil), entries...)}
	for _, entry := range view.flat {
		if entry != nil && !entry.expiresAt.IsZero() {
			view.expiryFlat = append(view.expiryFlat, entry)
		}
	}
	sort.SliceStable(view.expiryFlat, func(i, j int) bool {
		left := view.expiryFlat[i]
		right := view.expiryFlat[j]
		if !left.expiresAt.Equal(right.expiresAt) {
			return left.expiresAt.Before(right.expiresAt)
		}
		return left.auth.ID < right.auth.ID
	})
	return view
}

// pickFirst returns the first ready entry that satisfies predicate without advancing cursors.
func (v *readyView) pickFirst(predicate func(*scheduledAuth) bool) *scheduledAuth {
	for _, entry := range v.flat {
		if predicate == nil || predicate(entry) {
			return entry
		}
	}
	return nil
}

// pickRoundRobin returns the next ready entry using flat round-robin traversal.
func (v *readyView) pickRoundRobin(predicate func(*scheduledAuth) bool) *scheduledAuth {
	if len(v.flat) == 0 {
		return nil
	}
	start := 0
	if len(v.flat) > 0 {
		start = v.cursor % len(v.flat)
	}
	for offset := 0; offset < len(v.flat); offset++ {
		index := (start + offset) % len(v.flat)
		entry := v.flat[index]
		if predicate != nil && !predicate(entry) {
			continue
		}
		v.cursor = index + 1
		return entry
	}
	return nil
}

// pickWeighted returns the next ready entry using smooth weighted round-robin.
func (v *readyView) pickWeighted(predicate func(*scheduledAuth) bool) *scheduledAuth {
	if v == nil || len(v.flat) == 0 {
		return nil
	}
	v.weightedState.prepare(scheduledWeightVectorMatching(v.flat, predicate))
	return pickSmoothWeightedScheduled(v.flat, v.weightedState.current, predicate)
}

func (v *readyView) pickExpiring(predicate func(*scheduledAuth) bool, strategy schedulerStrategy, now time.Time) *scheduledAuth {
	if v == nil || len(v.expiryFlat) == 0 {
		return nil
	}
	isEligible := func(entry *scheduledAuth) bool {
		if entry == nil || entry.expiresAt.IsZero() || !entry.expiresAt.After(now) || entry.expiresAt.After(now.Add(authExpiryPriorityWindow)) {
			return false
		}
		return predicate == nil || predicate(entry)
	}
	var laneCutoff time.Time
	for _, entry := range v.expiryFlat {
		if isEligible(entry) {
			laneCutoff = entry.expiresAt.Add(authExpiryCohortWindow)
			break
		}
	}
	if laneCutoff.IsZero() {
		return nil
	}
	isExpiring := func(entry *scheduledAuth) bool {
		return isEligible(entry) && !entry.expiresAt.After(laneCutoff)
	}
	switch strategy {
	case schedulerStrategyFillFirst:
		for _, entry := range v.expiryFlat {
			if isExpiring(entry) {
				return entry
			}
		}
		return nil
	case schedulerStrategyWeightedRoundRobin:
		v.expiryWeightedState.prepare(scheduledWeightVectorMatching(v.expiryFlat, isExpiring))
		return pickSmoothWeightedScheduled(v.expiryFlat, v.expiryWeightedState.current, isExpiring)
	default:
		start := v.expiryCursor % len(v.expiryFlat)
		for offset := 0; offset < len(v.expiryFlat); offset++ {
			index := (start + offset) % len(v.expiryFlat)
			if !isExpiring(v.expiryFlat[index]) {
				continue
			}
			v.expiryCursor = index + 1
			return v.expiryFlat[index]
		}
	}
	return nil
}

func scheduledWeightVector(entries []*scheduledAuth) map[string]int64 {
	return scheduledWeightVectorMatching(entries, nil)
}

func scheduledWeightVectorMatching(entries []*scheduledAuth, predicate func(*scheduledAuth) bool) map[string]int64 {
	weights := make(map[string]int64, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.auth == nil || entry.meta == nil || entry.meta.weight <= 0 {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		weights[entry.auth.ID] = entry.meta.weight
	}
	return weights
}

func pickSmoothWeightedScheduled(entries []*scheduledAuth, current map[string]int64, predicate func(*scheduledAuth) bool) *scheduledAuth {
	active := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.auth == nil || entry.meta == nil || entry.meta.weight <= 0 {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		active[entry.auth.ID] = struct{}{}
	}
	for authID := range current {
		if _, ok := active[authID]; !ok {
			delete(current, authID)
		}
	}

	var picked *scheduledAuth
	var pickedCurrent int64
	var totalWeight int64
	for _, entry := range entries {
		if entry == nil || entry.auth == nil || entry.meta == nil || entry.meta.weight <= 0 {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		current[entry.auth.ID] = saturatingAddInt64(current[entry.auth.ID], entry.meta.weight)
		totalWeight = saturatingAddInt64(totalWeight, entry.meta.weight)
		if picked == nil || current[entry.auth.ID] > pickedCurrent {
			picked = entry
			pickedCurrent = current[entry.auth.ID]
		}
	}
	if picked == nil {
		return nil
	}
	current[picked.auth.ID] = saturatingAddInt64(current[picked.auth.ID], -totalWeight)
	return picked
}
