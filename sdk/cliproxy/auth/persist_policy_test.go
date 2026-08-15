package auth

import (
	"context"
	"sync/atomic"
	"testing"
)

type countingStore struct {
	saveCount atomic.Int32
}

func (s *countingStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *countingStore) Save(context.Context, *Auth) (string, error) {
	s.saveCount.Add(1)
	return "", nil
}

func (s *countingStore) Delete(context.Context, string) error { return nil }

type mutatingStore struct {
	saved *Auth
}

func (s *mutatingStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *mutatingStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.saved = auth
	auth.Metadata["store_only"] = true
	auth.Attributes[AttributePath] = "/tmp/store-only.json"
	return "", nil
}

func (s *mutatingStore) Delete(context.Context, string) error { return nil }

func TestWithSkipPersist_DisablesUpdatePersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}

	if _, err := mgr.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected 1 Save call, got %d", got)
	}

	ctxSkip := WithSkipPersist(context.Background())
	if _, err := mgr.Update(ctxSkip, auth); err != nil {
		t.Fatalf("Update(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected Save call count to remain 1, got %d", got)
	}
}

func TestWithSkipPersist_DisablesRegisterPersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}
}

func TestPersist_SkipsConfigAPIKeyAuth(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "codex:apikey:abc",
		Provider: "codex",
		Attributes: map[string]string{
			"api_key": "secret",
			"source":  "config:codex[abc]",
		},
		Metadata: map[string]any{"disable_cooling": true},
	}
	if _, err := mgr.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls for config api key, got %d", got)
	}
	mgr.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: "codex", Model: "gpt-5", Success: true})
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected MarkResult to skip persist for config api key, got %d Save calls", got)
	}
}

func TestPersistDoesNotExposeManagerOwnedAuthToMutatingStore(t *testing.T) {
	store := &mutatingStore{}
	manager := NewManager(store, nil, nil)
	auth := &Auth{
		ID:         "auth-1",
		Provider:   "codex",
		Attributes: map[string]string{"source": "test"},
		Metadata:   map[string]any{"type": "codex"},
	}

	if err := manager.persist(context.Background(), auth); err != nil {
		t.Fatalf("persist returned error: %v", err)
	}
	if store.saved == nil || store.saved == auth {
		t.Fatalf("store received manager-owned auth: saved=%p auth=%p", store.saved, auth)
	}
	if _, exists := auth.Metadata["store_only"]; exists {
		t.Fatalf("store metadata mutation leaked into manager auth: %#v", auth.Metadata)
	}
	if _, exists := auth.Attributes[AttributePath]; exists {
		t.Fatalf("store attribute mutation leaked into manager auth: %#v", auth.Attributes)
	}
}
