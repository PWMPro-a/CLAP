package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func newTailBurstConfig() *internalconfig.Config {
	return &internalconfig.Config{
		Codex: internalconfig.CodexConfig{
			TailBurst: internalconfig.CodexTailBurstConfig{
				Enabled:          true,
				TriggerUsedRatio: 0.98,
				SnapshotTTL:      "90s",
			},
		},
	}
}

func updateTailBurstSnapshot(t *testing.T, manager *Manager, authID string) {
	t.Helper()
	if _, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot(authID, "", CodexQuotaSnapshot{UsedRatio: 0.99}); errUpdate != nil {
		t.Fatalf("UpdateCodexQuotaSnapshot: %v", errUpdate)
	} else if !accepted {
		t.Fatal("initial quota snapshot was not accepted")
	}
}

func TestCodexTailBurstBypassesAccountConcurrency(t *testing.T) {
	executor := &runtimeLimitTestExecutor{
		blockAuth: "tail-auth",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	manager := newRuntimeLimitManager(t, executor,
		&Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}},
		&Auth{ID: "healthy-auth", Provider: "codex", Status: StatusActive},
	)
	manager.SetConfig(newTailBurstConfig())
	updateTailBurstSnapshot(t, manager, "tail-auth")

	req := cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}
	firstDone := make(chan cliproxyexecutor.Response, 1)
	go func() {
		response, errExecute := manager.Execute(context.Background(), []string{"codex"}, req, cliproxyexecutor.Options{})
		if errExecute != nil {
			t.Errorf("first Execute: %v", errExecute)
		}
		firstDone <- response
	}()

	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("tail request did not start")
	}
	second, errExecute := manager.Execute(context.Background(), []string{"codex"}, req, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("second Execute: %v", errExecute)
	}
	if got := string(second.Payload); got != "tail-auth" {
		t.Fatalf("second payload = %q, want tail-auth", got)
	}

	close(executor.release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
}

func TestCodexTailBurstKeepsExistingToolRequestsOnNormalScheduling(t *testing.T) {
	executor := &runtimeLimitTestExecutor{
		blockAuth: "tail-auth",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	manager := newRuntimeLimitManager(t, executor,
		&Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}},
		&Auth{ID: "healthy-auth", Provider: "codex", Status: StatusActive},
	)
	manager.SetConfig(newTailBurstConfig())
	updateTailBurstSnapshot(t, manager, "tail-auth")

	tailReq := cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}
	firstDone := make(chan cliproxyexecutor.Response, 1)
	go func() {
		response, errExecute := manager.Execute(context.Background(), []string{"codex"}, tailReq, cliproxyexecutor.Options{})
		if errExecute != nil {
			t.Errorf("first Execute: %v", errExecute)
		}
		firstDone <- response
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("tail request did not start")
	}

	toolReq := cliproxyexecutor.Request{Payload: []byte(`{"input":"hello","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`)}
	second, errExecute := manager.Execute(context.Background(), []string{"codex"}, toolReq, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("tool Execute: %v", errExecute)
	}
	if got := string(second.Payload); got != "healthy-auth" {
		t.Fatalf("tool request payload = %q, want healthy-auth", got)
	}

	close(executor.release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
}

type codexTailBurstStreamTestExecutor struct {
	runtimeLimitTestExecutor
}

func (e *codexTailBurstStreamTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	if e.callCount == nil {
		e.callCount = make(map[string]int)
	}
	e.callCount[auth.ID]++
	callNumber := e.callCount[auth.ID]
	block := auth.ID == e.blockAuth && callNumber == 1
	if block && e.started != nil {
		e.startedOnce.Do(func() { close(e.started) })
	}
	e.mu.Unlock()

	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	if block {
		go func() {
			select {
			case <-ctx.Done():
			case <-e.release:
			}
			close(chunks)
		}()
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(auth.ID)}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *codexTailBurstStreamTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Message: "http request not implemented"}
}

func TestCodexTailBurstBypassesAccountConcurrencyForStreams(t *testing.T) {
	executor := &codexTailBurstStreamTestExecutor{runtimeLimitTestExecutor: runtimeLimitTestExecutor{
		blockAuth: "tail-auth",
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	for _, auth := range []*Auth{
		{ID: "tail-auth", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}},
		{ID: "healthy-auth", Provider: "codex", Status: StatusActive},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register: %v", errRegister)
		}
	}
	manager.SetConfig(newTailBurstConfig())
	updateTailBurstSnapshot(t, manager, "tail-auth")

	firstDone := make(chan error, 1)
	go func() {
		_, errStream := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}, cliproxyexecutor.Options{})
		firstDone <- errStream
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("first tail stream did not start")
	}

	second, errStream := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}, cliproxyexecutor.Options{})
	if errStream != nil {
		t.Fatalf("second ExecuteStream: %v", errStream)
	}
	var payload []byte
	for chunk := range second.Chunks {
		if chunk.Err != nil {
			t.Fatalf("second stream chunk: %v", chunk.Err)
		}
		payload = append(payload, chunk.Payload...)
	}
	if string(payload) != "tail-auth" {
		t.Fatalf("second stream payload = %q, want tail-auth", payload)
	}

	close(executor.release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first tail stream did not finish")
	}
}

func TestCodexTailBurstSnapshotExpires(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive}); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	if _, _, errUpdate := manager.UpdateCodexQuotaSnapshot("tail-auth", "", CodexQuotaSnapshot{
		UsedRatio: 0.99,
		SampledAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(-time.Second),
	}); errUpdate != nil {
		t.Fatalf("UpdateCodexQuotaSnapshot: %v", errUpdate)
	}
	if _, ok := manager.CodexQuotaSnapshot("tail-auth", ""); ok {
		t.Fatal("expired quota snapshot remained available")
	}
}

func TestCodexTailBurstRejectsStaleQuotaSnapshots(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive}); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	now := time.Now().UTC()
	if _, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot("tail-auth", "gpt-5-codex", CodexQuotaSnapshot{
		UsedRatio:  0.99,
		SampledAt:  now,
		Generation: 2,
	}); errUpdate != nil || !accepted {
		t.Fatalf("first UpdateCodexQuotaSnapshot = accepted:%t err:%v", accepted, errUpdate)
	}
	stored, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot("tail-auth", "gpt-5-codex", CodexQuotaSnapshot{
		UsedRatio:  0.20,
		SampledAt:  now.Add(time.Minute),
		Generation: 1,
	})
	if errUpdate != nil {
		t.Fatalf("stale UpdateCodexQuotaSnapshot: %v", errUpdate)
	}
	if accepted {
		t.Fatal("stale quota snapshot was accepted")
	}
	if stored.UsedRatio != 0.99 || stored.Generation != 2 {
		t.Fatalf("stored stale-protected snapshot = %#v", stored)
	}
}

func TestCodexTailBurstCandidateIndexRefreshesForAuthLifecycle(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID:       "tail-auth",
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{"tail_burst_enabled": false},
	}); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	updateTailBurstSnapshot(t, manager, "tail-auth")
	if ids := codexTailBurstCandidateIDs(manager, "*"); len(ids) != 0 {
		t.Fatalf("disabled auth entered tail candidate index: %#v", ids)
	}

	auth, ok := manager.GetByID("tail-auth")
	if !ok {
		t.Fatal("tail auth missing")
	}
	auth.Metadata["tail_burst_enabled"] = true
	if _, errUpdate := manager.Update(context.Background(), auth); errUpdate != nil {
		t.Fatalf("Update: %v", errUpdate)
	}
	if ids := codexTailBurstCandidateIDs(manager, "*"); len(ids) != 1 || ids[0] != "tail-auth" {
		t.Fatalf("candidate index after enable = %#v", ids)
	}

	manager.Remove(context.Background(), "tail-auth")
	if ids := codexTailBurstCandidateIDs(manager, "*"); len(ids) != 0 {
		t.Fatalf("removed auth remained in tail candidate index: %#v", ids)
	}
}

func TestUpdateCodexQuotaSnapshotsPublishesBatchWithOneCandidateSet(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	for _, id := range []string{"tail-a", "tail-b"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
	}
	accepted, errUpdate := manager.UpdateCodexQuotaSnapshots([]CodexQuotaSnapshotUpdate{
		{AuthID: "tail-a", Snapshot: CodexQuotaSnapshot{UsedRatio: 0.99}},
		{AuthID: "tail-b", Snapshot: CodexQuotaSnapshot{UsedRatio: 0.985}},
		{AuthID: "missing", Snapshot: CodexQuotaSnapshot{UsedRatio: 0.99}},
	})
	if errUpdate != nil {
		t.Fatalf("UpdateCodexQuotaSnapshots: %v", errUpdate)
	}
	if accepted != 2 {
		t.Fatalf("accepted = %d, want 2", accepted)
	}
	ids := codexTailBurstCandidateIDs(manager, "*")
	if len(ids) != 2 || ids[0] != "tail-a" || ids[1] != "tail-b" {
		t.Fatalf("candidate ids = %#v", ids)
	}
}

func codexTailBurstCandidateIDs(manager *Manager, model string) []string {
	index, _ := manager.codexTailBurstCandidates.Load().(codexTailBurstCandidateIndex)
	return append([]string(nil), index[model]...)
}
