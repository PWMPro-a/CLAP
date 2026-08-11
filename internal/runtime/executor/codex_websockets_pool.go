package executor

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	codexStatelessWebsocketPoolSlots  = 30
	codexWebsocketStandbySlots        = 3
	codexWebsocketCompletedRouteLimit = 256
)

type codexWebsocketResponseScope struct {
	responseID string
	itemIDs    map[string]struct{}
}

func buildCodexSyntheticWebsocketCompleted(model string, scope *codexWebsocketResponseScope, outputItemsByIndex map[int64][]byte, outputItemsFallback [][]byte, outputText *codexOutputTextAccumulator) []byte {
	completed := []byte(`{"type":"response.completed","response":{"object":"response","status":"completed","output":[]}}`)
	responseID := ""
	if scope != nil {
		responseID = strings.TrimSpace(scope.responseID)
	}
	if responseID == "" {
		responseID = "resp_recovered_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	completed = helps.SetStringIfDifferent(completed, "response.id", responseID)
	completed, _ = sjson.SetBytes(completed, "response.created_at", time.Now().Unix())
	if model = strings.TrimSpace(model); model != "" {
		completed = helps.SetStringIfDifferent(completed, "response.model", model)
	}
	completed = patchCodexCompletedOutputWithText(completed, outputItemsByIndex, outputItemsFallback, outputText)
	items := codexOutputArrayItems(gjson.GetBytes(completed, "response.output"))
	if len(items) == 0 || !codexOutputItemsHaveVisibleMessageText(items) {
		return nil
	}
	return completed
}

func (s *codexWebsocketSession) acceptResponsePayload(payload []byte, scope *codexWebsocketResponseScope) bool {
	if s == nil || scope == nil || len(payload) == 0 {
		return true
	}
	responseID := strings.TrimSpace(gjson.GetBytes(payload, "response_id").String())
	if responseID == "" {
		responseID = strings.TrimSpace(gjson.GetBytes(payload, "response.id").String())
	}
	itemID := strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
	if itemID == "" {
		itemID = strings.TrimSpace(gjson.GetBytes(payload, "item.id").String())
	}
	eventType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
	trackCompletedRoutes := s.tracksCompletedResponseRoutes()

	s.completedRouteMu.Lock()
	defer s.completedRouteMu.Unlock()
	if trackCompletedRoutes && (s.isCompletedRouteLocked("response", responseID) || s.isCompletedRouteLocked("item", itemID)) {
		return false
	}
	if scope.responseID != "" && responseID != "" && responseID != scope.responseID {
		return false
	}
	if scope.responseID == "" && responseID != "" {
		scope.responseID = responseID
	}
	if itemID != "" {
		if scope.itemIDs == nil {
			scope.itemIDs = make(map[string]struct{})
		}
		scope.itemIDs[itemID] = struct{}{}
	}
	if trackCompletedRoutes && (eventType == "response.completed" || eventType == "response.done") {
		s.rememberCompletedRouteLocked("response", scope.responseID)
		for completedItemID := range scope.itemIDs {
			s.rememberCompletedRouteLocked("item", completedItemID)
		}
	}
	return true
}

func (s *codexWebsocketSession) tracksCompletedResponseRoutes() bool {
	if s == nil {
		return false
	}
	sessionID := strings.TrimSpace(s.sessionID)
	return strings.HasPrefix(sessionID, "stateless-") || strings.HasPrefix(sessionID, "standby-")
}

func collectCodexWebsocketResponseScope(payload []byte, scope *codexWebsocketResponseScope) {
	if scope == nil || len(payload) == 0 {
		return
	}
	responseID := strings.TrimSpace(gjson.GetBytes(payload, "response_id").String())
	if responseID == "" {
		responseID = strings.TrimSpace(gjson.GetBytes(payload, "response.id").String())
	}
	if scope.responseID == "" && responseID != "" {
		scope.responseID = responseID
	}
	itemID := strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
	if itemID == "" {
		itemID = strings.TrimSpace(gjson.GetBytes(payload, "item.id").String())
	}
	if itemID != "" {
		if scope.itemIDs == nil {
			scope.itemIDs = make(map[string]struct{})
		}
		scope.itemIDs[itemID] = struct{}{}
	}
}

func (s *codexWebsocketSession) isCompletedRouteLocked(kind, id string) bool {
	if s == nil || strings.TrimSpace(id) == "" || s.completedRouteIDs == nil {
		return false
	}
	_, ok := s.completedRouteIDs[kind+"\x00"+id]
	return ok
}

func (s *codexWebsocketSession) rememberCompletedRouteLocked(kind, id string) {
	if s == nil || strings.TrimSpace(id) == "" {
		return
	}
	if s.completedRouteIDs == nil {
		s.completedRouteIDs = make(map[string]struct{})
	}
	key := kind + "\x00" + id
	if _, exists := s.completedRouteIDs[key]; exists {
		return
	}
	s.completedRouteIDs[key] = struct{}{}
	s.completedRouteOrder = append(s.completedRouteOrder, key)
	if len(s.completedRouteOrder) <= codexWebsocketCompletedRouteLimit {
		return
	}
	oldest := s.completedRouteOrder[0]
	delete(s.completedRouteIDs, oldest)
	copy(s.completedRouteOrder, s.completedRouteOrder[1:])
	s.completedRouteOrder = s.completedRouteOrder[:len(s.completedRouteOrder)-1]
}

func (e *CodexWebsocketsExecutor) tryAcquireExecutionSession(sessionID string) (*codexWebsocketSession, bool) {
	sess := e.getOrCreateSession(sessionID)
	if sess == nil || !sess.reqMu.TryLock() {
		return nil, false
	}
	return sess, true
}

func codexStatelessWebsocketPoolKey(auth *cliproxyauth.Auth, cfg *config.Config, authID, wsURL string) string {
	authID = strings.TrimSpace(authID)
	wsURL = strings.TrimSpace(wsURL)
	if authID == "" || wsURL == "" {
		return ""
	}
	proxyURL, sourceIP := helps.ResolveEgressSettings(cfg, auth)
	return authID + "\x00" + wsURL + "\x00" + strings.TrimSpace(proxyURL) + "\x00" + strings.TrimSpace(sourceIP)
}

func (e *CodexWebsocketsExecutor) acquireStatelessSession(poolKey string) (*codexWebsocketSession, bool) {
	if e == nil || strings.TrimSpace(poolKey) == "" {
		return nil, false
	}
	store := e.store
	if store == nil {
		store = globalCodexWebsocketSessionStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.stateless == nil {
		store.stateless = make(map[string][]*codexWebsocketSession)
	}
	pool := store.stateless[poolKey]
	for _, sess := range pool {
		if sess != nil && sess.reqMu.TryLock() {
			return sess, true
		}
	}
	if len(pool) >= codexStatelessWebsocketPoolSlots {
		return nil, false
	}
	sess := &codexWebsocketSession{sessionID: "stateless-" + uuid.NewString(), upstreamDisconnectCh: make(chan error, 1)}
	sess.reqMu.Lock()
	store.stateless[poolKey] = append(pool, sess)
	return sess, true
}

func (e *CodexWebsocketsExecutor) prewarmParallelSessions(auth *cliproxyauth.Auth, poolKey, authID, wsURL string, headers http.Header) {
	if e == nil || strings.TrimSpace(poolKey) == "" || strings.TrimSpace(wsURL) == "" {
		return
	}
	store := e.store
	if store == nil {
		store = globalCodexWebsocketSessionStore
	}
	store.mu.Lock()
	if store.stateless == nil {
		store.stateless = make(map[string][]*codexWebsocketSession)
	}
	pool := store.stateless[poolKey]
	standbys := make([]*codexWebsocketSession, 0, codexWebsocketStandbySlots)
	for len(pool) < codexWebsocketStandbySlots && len(pool) < codexStatelessWebsocketPoolSlots {
		sess := &codexWebsocketSession{sessionID: "standby-" + uuid.NewString(), upstreamDisconnectCh: make(chan error, 1)}
		sess.reqMu.Lock()
		pool = append(pool, sess)
		standbys = append(standbys, sess)
	}
	store.stateless[poolKey] = pool
	store.mu.Unlock()

	for _, standby := range standbys {
		standby := standby
		authCopy := auth.Clone()
		headersCopy := headers.Clone()
		go func() {
			conn, _, resp, errDial := e.ensureUpstreamConn(context.Background(), authCopy, standby, authID, wsURL, headersCopy)
			closeHTTPResponseBody(resp, "codex websockets executor: close standby handshake response body error")
			if errDial != nil || conn == nil {
				e.removeStatelessSession(poolKey, standby)
				standby.reqMu.Unlock()
				log.Debugf("codex websockets executor: standby connection failed: %v", errDial)
				return
			}
			if !e.statelessSessionStored(poolKey, standby) {
				closeCodexWebsocketSession(standby, "standby_removed")
				standby.reqMu.Unlock()
				return
			}
			standby.reqMu.Unlock()
		}()
	}
}

func (e *CodexWebsocketsExecutor) removeStatelessSession(poolKey string, target *codexWebsocketSession) {
	if e == nil || target == nil {
		return
	}
	store := e.store
	if store == nil {
		store = globalCodexWebsocketSessionStore
	}
	store.mu.Lock()
	pool := store.stateless[poolKey]
	for i, sess := range pool {
		if sess == target {
			pool = append(pool[:i], pool[i+1:]...)
			break
		}
	}
	if len(pool) == 0 {
		delete(store.stateless, poolKey)
	} else {
		store.stateless[poolKey] = pool
	}
	store.mu.Unlock()
}

func (e *CodexWebsocketsExecutor) statelessSessionStored(poolKey string, target *codexWebsocketSession) bool {
	if e == nil || target == nil {
		return false
	}
	store := e.store
	if store == nil {
		store = globalCodexWebsocketSessionStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, sess := range store.stateless[poolKey] {
		if sess == target {
			return true
		}
	}
	return false
}
