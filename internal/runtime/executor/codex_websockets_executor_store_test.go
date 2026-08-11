package executor

import (
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexWebsocketsExecutor_CloseAllReleasesSessions(t *testing.T) {
	sessionID := "test-session-store-survives-replace"
	poolKey := "test-stateless-pool-survives-replace"

	globalCodexWebsocketSessionStore.mu.Lock()
	delete(globalCodexWebsocketSessionStore.sessions, sessionID)
	delete(globalCodexWebsocketSessionStore.stateless, poolKey)
	globalCodexWebsocketSessionStore.mu.Unlock()

	exec1 := NewCodexWebsocketsExecutor(nil)
	sess1 := exec1.getOrCreateSession(sessionID)
	if sess1 == nil {
		t.Fatalf("expected session to be created")
	}

	exec2 := NewCodexWebsocketsExecutor(nil)
	sess2 := exec2.getOrCreateSession(sessionID)
	if sess2 == nil {
		t.Fatalf("expected session to be available across executors")
	}
	if sess1 != sess2 {
		t.Fatalf("expected the same session instance across executors")
	}
	stateless, locked := exec1.acquireStatelessSession(poolKey)
	if stateless == nil || !locked {
		t.Fatalf("expected stateless session to be created and locked")
	}
	stateless.reqMu.Unlock()

	exec1.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)

	globalCodexWebsocketSessionStore.mu.Lock()
	_, stillPresent := globalCodexWebsocketSessionStore.sessions[sessionID]
	_, statelessStillPresent := globalCodexWebsocketSessionStore.stateless[poolKey]
	globalCodexWebsocketSessionStore.mu.Unlock()
	if stillPresent {
		t.Fatalf("expected session to be removed after executor shutdown")
	}
	if statelessStillPresent {
		t.Fatalf("expected stateless pool to be removed after executor shutdown")
	}

	exec2.CloseExecutionSession(sessionID)
}
