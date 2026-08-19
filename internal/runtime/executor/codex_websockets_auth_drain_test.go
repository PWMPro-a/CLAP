package executor

import (
	"sync/atomic"
	"testing"
	"time"
)

type authDrainLifecycle struct {
	ends   atomic.Int32
	reason chan string
}

func (*authDrainLifecycle) Bind(func() error) error { return nil }

func (l *authDrainLifecycle) End(reason string) {
	if l.ends.Add(1) != 1 {
		return
	}
	l.reason <- reason
}

func TestCodexAuthCloseDrainsActiveSession(t *testing.T) {
	lifecycle := &authDrainLifecycle{reason: make(chan string, 1)}
	sess := &codexWebsocketSession{
		sessionID: "active-auth-session",
		authID:    "auth-a",
		lifecycle: lifecycle,
	}
	sess.reqMu.Lock()
	store := &codexWebsocketSessionStore{
		sessions: map[string]*codexWebsocketSession{sess.sessionID: sess},
	}
	exec := &CodexWebsocketsExecutor{store: store}

	exec.CloseExecutionSessionsForAuthID("auth-a", "auth_disabled")

	store.mu.Lock()
	_, stillStored := store.sessions[sess.sessionID]
	store.mu.Unlock()
	if stillStored {
		t.Fatal("active auth session remained available for reuse")
	}
	select {
	case reason := <-lifecycle.reason:
		t.Fatalf("active session closed before request drained: %s", reason)
	default:
	}

	sess.reqMu.Unlock()
	select {
	case reason := <-lifecycle.reason:
		if reason != "auth_disabled" {
			t.Fatalf("close reason = %q, want auth_disabled", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("active session was not closed after request drained")
	}
}

func TestCodexAuthCloseClosesIdleStatelessSessionImmediately(t *testing.T) {
	lifecycle := &authDrainLifecycle{reason: make(chan string, 1)}
	sess := &codexWebsocketSession{
		sessionID: "idle-auth-session",
		authID:    "auth-a",
		lifecycle: lifecycle,
	}
	store := &codexWebsocketSessionStore{
		sessions: make(map[string]*codexWebsocketSession),
		stateless: map[string][]*codexWebsocketSession{
			"auth-a\x00wss://example.test/responses": {sess},
		},
	}
	exec := &CodexWebsocketsExecutor{store: store}

	exec.CloseExecutionSessionsForAuthID("auth-a", "auth_removed")

	select {
	case reason := <-lifecycle.reason:
		if reason != "auth_removed" {
			t.Fatalf("close reason = %q, want auth_removed", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("idle session was not closed immediately")
	}
	store.mu.Lock()
	_, stillStored := store.stateless["auth-a\x00wss://example.test/responses"]
	store.mu.Unlock()
	if stillStored {
		t.Fatal("idle auth pool remained available for reuse")
	}
}
