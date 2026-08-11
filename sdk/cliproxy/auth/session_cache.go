package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	maxStableSessionAliases = 64
	sessionCacheLockShards  = 1024
)

// SessionBinding is an immutable snapshot of one logical session binding.
// Aliases that represent the same session point to the same atomic slot.
type SessionBinding struct {
	AuthID     string
	Generation uint64
	ExpiresAt  time.Time
	Aliases    []string
}

type sessionBinding struct {
	authID        string
	generation    uint64
	expiresAtUnix int64
	refreshAtUnix int64
	aliases       []string
}

type sessionSlot struct {
	current   atomic.Pointer[sessionBinding]
	lockShard uint32
}

// SessionCacheOptions configures the affinity cache without changing its
// request-time behavior. StateFile is optional; an empty value keeps the cache
// entirely in memory.
type SessionCacheOptions struct {
	TTL             time.Duration
	RefreshInterval time.Duration
	FlushInterval   time.Duration
	StateFile       string
}

type persistedSessionCache struct {
	Version  int                       `json:"version"`
	Bindings []persistedSessionBinding `json:"bindings"`
}

type persistedSessionBinding struct {
	AuthID        string   `json:"auth_id"`
	Generation    uint64   `json:"generation"`
	ExpiresAtUnix int64    `json:"expires_at_unix_nano"`
	Aliases       []string `json:"aliases"`
}

// SessionCache provides lock-free reads for session affinity. Mutations and
// expiry cleanup stay off the normal hit path.
type SessionCache struct {
	entries sync.Map // map[string]*sessionSlot

	mutationMu sync.Mutex
	locks      [sessionCacheLockShards]sync.Mutex

	ttlNanos             atomic.Int64
	refreshIntervalNanos atomic.Int64
	flushInterval        time.Duration
	stateFile            atomic.Pointer[string]

	dirtyCount      atomic.Uint64
	mutationVersion atomic.Uint64
	flushCh         chan struct{}
	stopCh          chan struct{}
	doneCh          chan struct{}
	stopOnce        sync.Once

	persistenceErrorMu      sync.Mutex
	lastPersistenceErrorLog time.Time
	lastPersistenceError    atomic.Pointer[SessionCachePersistenceError]
}

// SessionCachePersistenceError is the latest observable persistence failure.
// It is intentionally secret-free and suitable for management health output.
type SessionCachePersistenceError struct {
	Operation string
	StateFile string
	Message   string
	At        time.Time
}

// NewSessionCache creates an in-memory cache with the specified TTL.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return NewSessionCacheWithOptions(SessionCacheOptions{TTL: ttl})
}

// NewSessionCacheWithOptions creates a cache and restores optional persisted
// bindings before the cache becomes visible to request handling.
func NewSessionCacheWithOptions(options SessionCacheOptions) *SessionCache {
	options = normalizeSessionCacheOptions(options)
	c := &SessionCache{
		flushInterval: options.FlushInterval,
		flushCh:       make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	c.ttlNanos.Store(options.TTL.Nanoseconds())
	c.refreshIntervalNanos.Store(options.RefreshInterval.Nanoseconds())
	c.setStateFile(options.StateFile)
	c.loadState()
	go c.maintenanceLoop()
	return c
}

func normalizeSessionCacheOptions(options SessionCacheOptions) SessionCacheOptions {
	if options.TTL <= 0 {
		options.TTL = 30 * time.Minute
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = min(options.TTL/2, 30*time.Second)
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = time.Millisecond
	}
	if options.FlushInterval <= 0 {
		options.FlushInterval = time.Second
	}
	options.StateFile = strings.TrimSpace(options.StateFile)
	return options
}

// Reconfigure updates request-time cache settings without replacing the cache.
// Existing immutable bindings remain available throughout a routing hot reload.
func (c *SessionCache) Reconfigure(options SessionCacheOptions) {
	if c == nil {
		return
	}
	options = normalizeSessionCacheOptions(options)
	previousStateFile := c.stateFilePath()
	c.ttlNanos.Store(options.TTL.Nanoseconds())
	c.refreshIntervalNanos.Store(options.RefreshInterval.Nanoseconds())
	c.setStateFile(options.StateFile)
	if options.StateFile != "" && options.StateFile != previousStateFile {
		c.dirtyCount.Add(1)
		c.requestFlush()
	}
}

func (c *SessionCache) setStateFile(stateFile string) {
	stateFile = strings.TrimSpace(stateFile)
	if stateFile == "" {
		c.stateFile.Store(nil)
		return
	}
	value := stateFile
	c.stateFile.Store(&value)
}

func (c *SessionCache) stateFilePath() string {
	if c == nil {
		return ""
	}
	value := c.stateFile.Load()
	if value == nil {
		return ""
	}
	return *value
}

// PersistenceError returns the latest persistence failure, if any.
func (c *SessionCache) PersistenceError() *SessionCachePersistenceError {
	if c == nil {
		return nil
	}
	status := c.lastPersistenceError.Load()
	if status == nil {
		return nil
	}
	copyStatus := *status
	return &copyStatus
}

// Get retrieves the auth ID bound to a session without refreshing its TTL.
func (c *SessionCache) Get(sessionID string) (string, bool) {
	binding, ok := c.GetBinding(sessionID, false)
	return binding.AuthID, ok
}

// GetAndRefresh retrieves the auth ID and lazily refreshes the logical session
// TTL. Most hits perform only sync.Map.Load and atomic.Pointer.Load.
func (c *SessionCache) GetAndRefresh(sessionID string) (string, bool) {
	binding, ok := c.GetBinding(sessionID, true)
	return binding.AuthID, ok
}

// GetBinding returns the immutable binding snapshot for sessionID.
func (c *SessionCache) GetBinding(sessionID string, refresh bool) (SessionBinding, bool) {
	if c == nil || sessionID == "" {
		return SessionBinding{}, false
	}
	rawSlot, ok := c.entries.Load(sessionID)
	if !ok {
		return SessionBinding{}, false
	}
	slot, _ := rawSlot.(*sessionSlot)
	if slot == nil {
		return SessionBinding{}, false
	}
	binding := slot.current.Load()
	if binding == nil {
		return SessionBinding{}, false
	}
	nowUnix := time.Now().UnixNano()
	if nowUnix >= binding.expiresAtUnix {
		return SessionBinding{}, false
	}
	if refresh && nowUnix >= binding.refreshAtUnix {
		ttlNanos := c.ttlNanos.Load()
		refreshIntervalNanos := c.refreshIntervalNanos.Load()
		refreshed := &sessionBinding{
			authID:        binding.authID,
			generation:    binding.generation,
			expiresAtUnix: nowUnix + ttlNanos,
			refreshAtUnix: nowUnix + refreshIntervalNanos,
			aliases:       binding.aliases,
		}
		if slot.current.CompareAndSwap(binding, refreshed) {
			binding = refreshed
			c.markDirty()
		} else if current := slot.current.Load(); current != nil && nowUnix < current.expiresAtUnix {
			binding = current
		}
	}
	return bindingView(binding), true
}

func bindingView(binding *sessionBinding) SessionBinding {
	if binding == nil {
		return SessionBinding{}
	}
	return SessionBinding{
		AuthID:     binding.authID,
		Generation: binding.generation,
		ExpiresAt:  time.Unix(0, binding.expiresAtUnix),
		Aliases:    binding.aliases,
	}
}

// lockSession serializes cold binding and failover for one logical session.
// It is intentionally separate from cache mutation so unrelated sessions can
// select credentials concurrently.
func (c *SessionCache) lockSession(sessionID string) func() {
	return c.lockSessions(sessionID)
}

// lockSessions serializes cold binding and failover for every identifier known
// by the current request. Sorting shard indexes keeps overlapping alias groups
// deadlock-free while unrelated sessions continue independently.
func (c *SessionCache) lockSessions(sessionIDs ...string) func() {
	if c == nil {
		return func() {}
	}
	for {
		indexes, lockedIndexes := c.sessionLockIndexes(sessionIDs)
		if len(indexes) == 0 {
			return func() {}
		}
		for _, index := range indexes {
			c.locks[index].Lock()
		}
		valid := true
		for _, sessionID := range sessionIDs {
			if sessionID == "" {
				continue
			}
			rawSlot, ok := c.entries.Load(sessionID)
			if !ok {
				continue
			}
			slot, _ := rawSlot.(*sessionSlot)
			if slot == nil {
				continue
			}
			if _, held := lockedIndexes[int(slot.lockShard)]; !held {
				valid = false
				break
			}
		}
		if valid {
			return func() { c.unlockSessionIndexes(indexes) }
		}
		c.unlockSessionIndexes(indexes)
	}
}

func (c *SessionCache) sessionLockIndexes(sessionIDs []string) ([]int, map[int]struct{}) {
	indexes := make([]int, 0, len(sessionIDs))
	seen := make(map[int]struct{}, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		if sessionID == "" {
			continue
		}
		index := int(sessionCacheShard(sessionID))
		if _, exists := seen[index]; !exists {
			seen[index] = struct{}{}
			indexes = append(indexes, index)
		}
		if rawSlot, ok := c.entries.Load(sessionID); ok {
			slot, _ := rawSlot.(*sessionSlot)
			if slot != nil {
				logicalIndex := int(slot.lockShard)
				if _, exists := seen[logicalIndex]; !exists {
					seen[logicalIndex] = struct{}{}
					indexes = append(indexes, logicalIndex)
				}
			}
		}
	}
	sort.Ints(indexes)
	return indexes, seen
}

func (c *SessionCache) unlockSessionIndexes(indexes []int) {
	for index := len(indexes) - 1; index >= 0; index-- {
		c.locks[indexes[index]].Unlock()
	}
}

func sessionCacheShard(sessionID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sessionID))
	return h.Sum32() % sessionCacheLockShards
}

// Set binds a session to an auth ID with lazy TTL refresh.
func (c *SessionCache) Set(sessionID, authID string) {
	c.SetAliases(authID, sessionID)
}

// SetAliases binds multiple identifiers for one logical session to an auth ID.
func (c *SessionCache) SetAliases(authID string, sessionIDs ...string) {
	_ = c.BindAliases(authID, sessionIDs...)
}

// BindAliases updates a logical binding and returns its resulting generation.
// Generation advances only when the active auth changes.
func (c *SessionCache) BindAliases(authID string, sessionIDs ...string) SessionBinding {
	if c == nil || strings.TrimSpace(authID) == "" {
		return SessionBinding{}
	}
	authID = strings.TrimSpace(authID)
	aliases := mergeSessionAliases(nil, sessionIDs...)
	if len(aliases) == 0 {
		return SessionBinding{}
	}

	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()

	type previousGroup struct {
		slot    *sessionSlot
		binding *sessionBinding
	}
	previous := make([]previousGroup, 0, len(aliases))
	seenSlots := make(map[*sessionSlot]struct{}, len(aliases))
	for _, alias := range aliases {
		rawSlot, ok := c.entries.Load(alias)
		if !ok {
			continue
		}
		slot, _ := rawSlot.(*sessionSlot)
		if slot == nil {
			continue
		}
		binding := slot.current.Load()
		if binding == nil || time.Now().UnixNano() >= binding.expiresAtUnix {
			continue
		}
		if _, exists := seenSlots[slot]; exists {
			continue
		}
		seenSlots[slot] = struct{}{}
		previous = append(previous, previousGroup{slot: slot, binding: binding})
		aliases = mergeSessionAliases(aliases, binding.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	if len(aliases) == 0 {
		return SessionBinding{}
	}

	var target *sessionSlot
	var generation uint64 = 1
	for _, group := range previous {
		if target == nil {
			target = group.slot
		}
		if group.binding.generation >= generation {
			generation = group.binding.generation
		}
	}
	changedAuth := false
	for _, group := range previous {
		if group.binding.authID != authID {
			changedAuth = true
			break
		}
	}
	if changedAuth {
		generation++
	}
	if target == nil {
		target = newSessionSlot(aliases)
	}
	nowUnix := time.Now().UnixNano()
	ttlNanos := c.ttlNanos.Load()
	refreshIntervalNanos := c.refreshIntervalNanos.Load()
	binding := &sessionBinding{
		authID:        authID,
		generation:    generation,
		expiresAtUnix: nowUnix + ttlNanos,
		refreshAtUnix: nowUnix + refreshIntervalNanos,
		aliases:       aliases,
	}
	target.current.Store(binding)

	aliasSet := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		aliasSet[alias] = struct{}{}
		c.entries.Store(alias, target)
	}
	for _, group := range previous {
		for _, alias := range group.binding.aliases {
			if _, keep := aliasSet[alias]; keep {
				continue
			}
			if current, ok := c.entries.Load(alias); ok && current == group.slot {
				c.entries.Delete(alias)
			}
		}
	}
	c.markDirty()
	return bindingView(binding)
}

func newSessionSlot(aliases []string) *sessionSlot {
	lockShard := uint32(0)
	if len(aliases) > 0 {
		lockShard = sessionCacheShard(aliases[0])
	}
	return &sessionSlot{lockShard: lockShard}
}

func compactSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, isLocalPromptCacheSessionAlias)
}

func compactHomeSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, func(alias string) bool {
		return strings.HasPrefix(alias, "pck:")
	})
}

func compactSessionAliasesWith(aliases []string, isPromptCacheAlias func(string) bool) []string {
	compacted := make([]string, 0, len(aliases))
	hasPromptCacheKey := false
	stableAliases := 0
	for _, alias := range aliases {
		if isPromptCacheAlias(alias) {
			if hasPromptCacheKey {
				continue
			}
			hasPromptCacheKey = true
		} else {
			if stableAliases >= maxStableSessionAliases {
				continue
			}
			stableAliases++
		}
		compacted = append(compacted, alias)
	}
	return compacted
}

func isLocalPromptCacheSessionAlias(alias string) bool {
	if strings.HasPrefix(alias, "pck:") {
		return true
	}
	_, sessionAndModel, ok := strings.Cut(alias, "::")
	return ok && strings.HasPrefix(sessionAndModel, "pck:")
}

func mergeSessionAliases(existing []string, candidates ...string) []string {
	aliases := make([]string, 0, len(existing)+len(candidates))
	seen := make(map[string]struct{}, len(existing)+len(candidates))
	add := func(alias string) {
		if alias == "" {
			return
		}
		if _, ok := seen[alias]; ok {
			return
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	for _, alias := range existing {
		add(alias)
	}
	for _, alias := range candidates {
		add(alias)
	}
	return aliases
}

func equalSessionAliases(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Invalidate removes a logical session binding.
func (c *SessionCache) Invalidate(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	rawSlot, ok := c.entries.Load(sessionID)
	if !ok {
		return
	}
	slot, _ := rawSlot.(*sessionSlot)
	if slot == nil {
		return
	}
	binding := slot.current.Load()
	if binding == nil {
		return
	}
	for _, alias := range binding.aliases {
		if current, exists := c.entries.Load(alias); exists && current == slot {
			c.entries.Delete(alias)
		}
	}
	c.markDirty()
}

// InvalidateAuth removes all sessions bound to a specific auth ID.
func (c *SessionCache) InvalidateAuth(authID string) {
	if c == nil || authID == "" {
		return
	}
	c.mutationMu.Lock()
	defer c.mutationMu.Unlock()
	removed := false
	c.entries.Range(func(key, value any) bool {
		slot, _ := value.(*sessionSlot)
		if slot == nil {
			return true
		}
		binding := slot.current.Load()
		if binding != nil && binding.authID == authID {
			c.entries.Delete(key)
			removed = true
		}
		return true
	})
	if removed {
		c.markDirty()
	}
}

// Stop terminates maintenance and flushes pending persisted state.
func (c *SessionCache) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() { close(c.stopCh) })
	<-c.doneCh
}

func (c *SessionCache) maintenanceLoop() {
	defer close(c.doneCh)
	cleanupInterval := min(time.Duration(c.ttlNanos.Load())/2, time.Minute)
	if cleanupInterval < 10*time.Millisecond {
		cleanupInterval = 10 * time.Millisecond
	}
	cleanupTicker := time.NewTicker(cleanupInterval)
	flushTicker := time.NewTicker(c.flushInterval)
	defer cleanupTicker.Stop()
	defer flushTicker.Stop()
	for {
		select {
		case <-c.stopCh:
			c.flushState()
			return
		case <-cleanupTicker.C:
			c.cleanup()
		case <-flushTicker.C:
			c.flushState()
		case <-c.flushCh:
			c.flushState()
		}
	}
}

func (c *SessionCache) cleanup() {
	nowUnix := time.Now().UnixNano()
	removed := false
	c.entries.Range(func(key, value any) bool {
		slot, _ := value.(*sessionSlot)
		binding := (*sessionBinding)(nil)
		if slot != nil {
			binding = slot.current.Load()
		}
		if binding == nil || nowUnix >= binding.expiresAtUnix {
			removed = c.entries.CompareAndDelete(key, value) || removed
		}
		return true
	})
	if removed {
		c.markDirty()
	}
}

func (c *SessionCache) markDirty() {
	if c == nil {
		return
	}
	c.mutationVersion.Add(1)
	if c.stateFilePath() == "" {
		return
	}
	if c.dirtyCount.Add(1) < 100 {
		return
	}
	c.requestFlush()
}

func (c *SessionCache) requestFlush() {
	if c == nil {
		return
	}
	select {
	case c.flushCh <- struct{}{}:
	default:
	}
}

func (c *SessionCache) loadState() {
	stateFile := c.stateFilePath()
	if c == nil || stateFile == "" {
		return
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.recordPersistenceError("load", stateFile, err)
		}
		return
	}
	var state persistedSessionCache
	if err = json.Unmarshal(data, &state); err != nil {
		c.recordPersistenceError("decode", stateFile, err)
		return
	}
	if state.Version != 1 {
		c.recordPersistenceError("decode", stateFile, fmt.Errorf("unsupported session cache version %d", state.Version))
		return
	}
	nowUnix := time.Now().UnixNano()
	for _, item := range state.Bindings {
		aliases := compactSessionAliases(mergeSessionAliases(nil, item.Aliases...))
		if item.AuthID == "" || item.ExpiresAtUnix <= nowUnix || len(aliases) == 0 {
			continue
		}
		generation := item.Generation
		if generation == 0 {
			generation = 1
		}
		binding := &sessionBinding{
			authID:        item.AuthID,
			generation:    generation,
			expiresAtUnix: item.ExpiresAtUnix,
			refreshAtUnix: min(item.ExpiresAtUnix, nowUnix+c.refreshIntervalNanos.Load()),
			aliases:       aliases,
		}
		slot := newSessionSlot(aliases)
		slot.current.Store(binding)
		for _, alias := range aliases {
			c.entries.Store(alias, slot)
		}
	}
}

func (c *SessionCache) flushState() {
	stateFile := c.stateFilePath()
	if c == nil || stateFile == "" || c.dirtyCount.Swap(0) == 0 {
		return
	}
	snapshotVersion := c.mutationVersion.Load()

	state := persistedSessionCache{Version: 1}
	seen := make(map[*sessionSlot]struct{})
	nowUnix := time.Now().UnixNano()
	c.entries.Range(func(_, value any) bool {
		slot, _ := value.(*sessionSlot)
		if slot == nil {
			return true
		}
		if _, exists := seen[slot]; exists {
			return true
		}
		seen[slot] = struct{}{}
		binding := slot.current.Load()
		if binding == nil || binding.expiresAtUnix <= nowUnix {
			return true
		}
		state.Bindings = append(state.Bindings, persistedSessionBinding{
			AuthID:        binding.authID,
			Generation:    binding.generation,
			ExpiresAtUnix: binding.expiresAtUnix,
			Aliases:       append([]string(nil), binding.aliases...),
		})
		return true
	})
	sort.Slice(state.Bindings, func(i, j int) bool {
		if state.Bindings[i].AuthID != state.Bindings[j].AuthID {
			return state.Bindings[i].AuthID < state.Bindings[j].AuthID
		}
		return strings.Join(state.Bindings[i].Aliases, "\x00") < strings.Join(state.Bindings[j].Aliases, "\x00")
	})
	data, err := json.Marshal(state)
	if err != nil {
		c.dirtyCount.Add(1)
		c.recordPersistenceError("encode", stateFile, err)
		return
	}
	if err = os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		c.dirtyCount.Add(1)
		c.recordPersistenceError("mkdir", stateFile, err)
		return
	}
	temporary := stateFile + ".tmp"
	if err = os.WriteFile(temporary, data, 0o600); err != nil {
		c.dirtyCount.Add(1)
		c.recordPersistenceError("write", stateFile, err)
		return
	}
	if err = os.Rename(temporary, stateFile); err != nil {
		_ = os.Remove(temporary)
		c.dirtyCount.Add(1)
		c.recordPersistenceError("rename", stateFile, err)
		return
	}
	c.lastPersistenceError.Store(nil)
	if c.mutationVersion.Load() != snapshotVersion {
		if c.dirtyCount.Load() == 0 {
			c.dirtyCount.Add(1)
		}
		c.requestFlush()
	}
}

func (c *SessionCache) recordPersistenceError(operation, stateFile string, err error) {
	if c == nil || err == nil {
		return
	}
	now := time.Now()
	status := &SessionCachePersistenceError{
		Operation: operation,
		StateFile: stateFile,
		Message:   err.Error(),
		At:        now,
	}
	c.lastPersistenceError.Store(status)

	c.persistenceErrorMu.Lock()
	shouldLog := c.lastPersistenceErrorLog.IsZero() || now.Sub(c.lastPersistenceErrorLog) >= time.Minute
	if shouldLog {
		c.lastPersistenceErrorLog = now
	}
	c.persistenceErrorMu.Unlock()
	if shouldLog {
		log.WithError(err).WithFields(log.Fields{
			"operation":  operation,
			"state_file": stateFile,
		}).Warn("session affinity persistence failed")
	}
}
