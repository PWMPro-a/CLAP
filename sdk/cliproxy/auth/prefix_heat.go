package auth

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	defaultPrefixHeatMaxEntries = 65536
	prefixHeatShardCount        = 64
)

type prefixHeatEntry struct {
	key      string
	authID   string
	lastSeen time.Time
}

type prefixHeatShard struct {
	mu      sync.RWMutex
	entries map[string]*list.Element
	recency *list.List
}

type prefixHeatTracker struct {
	shards     [prefixHeatShardCount]prefixHeatShard
	ttlNanos   atomic.Int64
	maxEntries atomic.Int64
}

func newPrefixHeatTracker(ttl time.Duration, maxEntries int) *prefixHeatTracker {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = defaultPrefixHeatMaxEntries
	}
	tracker := &prefixHeatTracker{}
	tracker.ttlNanos.Store(int64(ttl))
	tracker.maxEntries.Store(int64(maxEntries))
	return tracker
}

func prefixHeatKey(prefixFingerprint, authID string) string {
	return prefixFingerprint + "\x00" + authID
}

func prefixHeatShardIndex(prefixFingerprint string) int {
	hash := uint32(2166136261)
	for index := 0; index < len(prefixFingerprint); index++ {
		hash ^= uint32(prefixFingerprint[index])
		hash *= 16777619
	}
	return int(hash % prefixHeatShardCount)
}

func (t *prefixHeatTracker) shard(prefixFingerprint string) *prefixHeatShard {
	return &t.shards[prefixHeatShardIndex(prefixFingerprint)]
}

func (t *prefixHeatTracker) ttl() time.Duration {
	if t == nil {
		return 10 * time.Minute
	}
	ttl := time.Duration(t.ttlNanos.Load())
	if ttl <= 0 {
		return 10 * time.Minute
	}
	return ttl
}

func (t *prefixHeatTracker) shardCapacity() int {
	if t == nil {
		return defaultPrefixHeatMaxEntries/prefixHeatShardCount + 1
	}
	maxEntries := int(t.maxEntries.Load())
	if maxEntries <= 0 {
		maxEntries = defaultPrefixHeatMaxEntries
	}
	capacity := (maxEntries + prefixHeatShardCount - 1) / prefixHeatShardCount
	if capacity < 1 {
		return 1
	}
	return capacity
}

func (t *prefixHeatTracker) UpdateConfig(ttl time.Duration, maxEntries int) {
	if t == nil {
		return
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = defaultPrefixHeatMaxEntries
	}
	t.ttlNanos.Store(int64(ttl))
	t.maxEntries.Store(int64(maxEntries))
	capacity := t.shardCapacity()
	for index := range t.shards {
		shard := &t.shards[index]
		shard.mu.Lock()
		for len(shard.entries) > capacity {
			removePrefixHeatElementLocked(shard, shard.recency.Back())
		}
		shard.mu.Unlock()
	}
}

func (t *prefixHeatTracker) Record(prefixFingerprint, authID string, now time.Time) {
	if t == nil {
		return
	}
	prefixFingerprint = strings.TrimSpace(prefixFingerprint)
	authID = strings.TrimSpace(authID)
	if prefixFingerprint == "" || authID == "" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := prefixHeatKey(prefixFingerprint, authID)
	shard := t.shard(prefixFingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[string]*list.Element)
		shard.recency = list.New()
	}
	if element := shard.entries[key]; element != nil {
		entry := element.Value.(*prefixHeatEntry)
		entry.lastSeen = now
		shard.recency.MoveToFront(element)
		return
	}
	entry := &prefixHeatEntry{
		key:      key,
		authID:   authID,
		lastSeen: now,
	}
	shard.entries[key] = shard.recency.PushFront(entry)
	for len(shard.entries) > t.shardCapacity() {
		removePrefixHeatElementLocked(shard, shard.recency.Back())
	}
}

func (t *prefixHeatTracker) HotAuths(prefixFingerprint string, auths []*Auth, now time.Time) []*Auth {
	if t == nil || len(auths) == 0 {
		return nil
	}
	prefixFingerprint = strings.TrimSpace(prefixFingerprint)
	if prefixFingerprint == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	shard := t.shard(prefixFingerprint)
	shard.mu.RLock()
	hot := make([]*Auth, 0, len(auths))
	expiredKeys := make([]string, 0)
	ttl := t.ttl()
	for _, auth := range auths {
		if auth == nil || strings.TrimSpace(auth.ID) == "" {
			continue
		}
		key := prefixHeatKey(prefixFingerprint, strings.TrimSpace(auth.ID))
		element := shard.entries[key]
		if element == nil {
			continue
		}
		entry := element.Value.(*prefixHeatEntry)
		if !now.Before(entry.lastSeen.Add(ttl)) {
			expiredKeys = append(expiredKeys, key)
			continue
		}
		hot = append(hot, auth)
	}
	shard.mu.RUnlock()
	if len(expiredKeys) > 0 {
		shard.mu.Lock()
		for _, key := range expiredKeys {
			element := shard.entries[key]
			if element == nil {
				continue
			}
			entry := element.Value.(*prefixHeatEntry)
			if !now.Before(entry.lastSeen.Add(ttl)) {
				removePrefixHeatElementLocked(shard, element)
			}
		}
		shard.mu.Unlock()
	}
	return lowestConcurrencyAuths(hot, now)
}

func (t *prefixHeatTracker) InvalidateAuth(authID string) {
	if t == nil || strings.TrimSpace(authID) == "" {
		return
	}
	authID = strings.TrimSpace(authID)
	for index := range t.shards {
		shard := &t.shards[index]
		shard.mu.Lock()
		if shard.recency == nil {
			shard.mu.Unlock()
			continue
		}
		for element := shard.recency.Back(); element != nil; {
			previous := element.Prev()
			entry := element.Value.(*prefixHeatEntry)
			if entry.authID == authID {
				removePrefixHeatElementLocked(shard, element)
			}
			element = previous
		}
		shard.mu.Unlock()
	}
}

func removePrefixHeatElementLocked(shard *prefixHeatShard, element *list.Element) {
	if shard == nil || element == nil {
		return
	}
	entry, _ := element.Value.(*prefixHeatEntry)
	if entry != nil {
		delete(shard.entries, entry.key)
	}
	shard.recency.Remove(element)
}

func lowestConcurrencyAuths(auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	lowest := 0
	balanced := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		current := auth.RuntimeLimitSnapshot(now).CurrentConcurrency
		switch {
		case len(balanced) == 0 || current < lowest:
			lowest = current
			balanced = balanced[:0]
			balanced = append(balanced, auth)
		case current == lowest:
			balanced = append(balanced, auth)
		}
	}
	return balanced
}

func (s *SessionAffinitySelector) pickPrefixHeatAuth(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth, now time.Time) (*Auth, error) {
	if s == nil || !s.prefixHeatEnabled.Load() || s.prefixHeat == nil {
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}
	shadow := s.prefixHeatShadow.Load()
	prefixFingerprint := cacheaffinity.MetadataValue(opts.Metadata, cliproxyexecutor.CacheAffinityPrefixFingerprintMetadataKey)
	hotAuths := s.prefixHeat.HotAuths(prefixFingerprint, auths, now)
	matched := len(hotAuths) > 0
	cacheaffinity.RecordPrefixHeatLookup(matched, shadow)
	if !matched || shadow {
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}
	selected, errSelected := s.fallback.Pick(ctx, provider, model, opts, hotAuths)
	if errSelected == nil && selected != nil {
		cacheaffinity.RecordPrefixHeatSelection()
		return selected, nil
	}
	return s.fallback.Pick(ctx, provider, model, opts, auths)
}
