package auth

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func BenchmarkSessionAffinityHit(b *testing.B) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Hour})
	b.Cleanup(selector.Stop)
	options := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Affinity": []string{"benchmark-hit"}}}
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	if _, err := selector.Pick(context.Background(), "codex", "gpt-test", options, auths); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := selector.Pick(context.Background(), "codex", "gpt-test", options, auths); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSessionAffinityLazyRefresh(b *testing.B) {
	cache := NewSessionCacheWithOptions(SessionCacheOptions{TTL: time.Hour, RefreshInterval: time.Nanosecond})
	b.Cleanup(cache.Stop)
	cache.Set("session", "auth-a")
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, ok := cache.GetBinding("session", true); !ok {
			b.Fatal("binding expired")
		}
	}
}

func BenchmarkSessionAffinityColdBind(b *testing.B) {
	cache := NewSessionCache(time.Hour)
	b.Cleanup(cache.Stop)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		cache.BindAliases("auth-a", fmt.Sprintf("session-%d", index))
	}
}

func BenchmarkSessionAffinityConcurrentFailover(b *testing.B) {
	cache := NewSessionCache(time.Hour)
	b.Cleanup(cache.Stop)
	cache.Set("session", "auth-a")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			unlock := cache.lockSession("session")
			binding, ok := cache.GetBinding("session", false)
			if !ok || binding.AuthID == "auth-a" {
				cache.BindAliases("auth-b", "session")
			}
			unlock()
		}
	})
}

func BenchmarkSessionCachePersistentFlush10000(b *testing.B) {
	cache := NewSessionCacheWithOptions(SessionCacheOptions{
		TTL:           time.Hour,
		FlushInterval: time.Hour,
	})
	b.Cleanup(cache.Stop)
	for index := 0; index < 10_000; index++ {
		cache.BindAliases("auth-a", fmt.Sprintf("session-%d", index))
	}
	cache.setStateFile(filepath.Join(b.TempDir(), "session-affinity.json"))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		cache.dirtyCount.Store(1)
		cache.flushState()
	}
}

func BenchmarkQuotaSnapshotRead(b *testing.B) {
	auth := &Auth{ID: "auth-a", Provider: "codex"}
	now := time.Now()
	auth.setCodexQuotaSnapshot("*", CodexQuotaSnapshot{UsedRatio: 0.5, SampledAt: now, ExpiresAt: now.Add(time.Hour)})
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, ok := auth.codexQuotaSnapshot("gpt-test", now); !ok {
			b.Fatal("quota snapshot missing")
		}
	}
}
