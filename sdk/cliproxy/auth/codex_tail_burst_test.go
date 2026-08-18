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
				Enabled:               true,
				TriggerRemainingRatio: 0.02,
				SnapshotTTL:           "90s",
				ExpiryWindow:          "10m",
				MaxConcurrency:        32,
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

func tailBurstAuthForTest(t *testing.T, manager *Manager, authID string) *Auth {
	t.Helper()
	manager.mu.RLock()
	auth := manager.auths[authID]
	if auth != nil {
		auth = auth.Clone()
	}
	manager.mu.RUnlock()
	if auth == nil {
		t.Fatalf("auth %q was not found", authID)
	}
	return auth
}

func occupyNormalConcurrencyForTest(t *testing.T, manager *Manager, authID string, count int) {
	t.Helper()
	auth := tailBurstAuthForTest(t, manager, authID)
	releases := make([]func(), 0, count)
	for i := 0; i < count; i++ {
		release, acquired, reason, _ := auth.acquireRuntimeSlotForModel(time.Now(), "", false)
		if !acquired {
			t.Fatalf("occupy normal slot %d for %s: %s", i+1, authID, reason)
		}
		releases = append(releases, release)
	}
	t.Cleanup(func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	})
}

func tailBurstAffinityOptions(routeKey string) cliproxyexecutor.Options {
	opts := activeCacheAffinityOptions(routeKey)
	opts.Metadata[codexTailBurstRequestedMetadataKey] = true
	return opts
}

func configureTailBurstAffinityManager(manager *Manager) (*SessionAffinitySelector, *internalconfig.Config) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:             &RoundRobinSelector{},
		TTL:                  time.Hour,
		CacheAffinityEnabled: true,
	})
	manager.SetSelector(selector)
	cfg := newTailBurstConfig()
	cfg.Codex.CacheAffinity = internalconfig.CodexCacheAffinityConfig{
		Enabled:        true,
		MaxConcurrency: 8,
	}
	manager.SetConfig(cfg)
	return selector, cfg
}

func TestCodexTailBurstMigratesNormalWarmBindingIntoTailPool(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "warm-auth", Provider: "codex", Status: StatusActive},
		&Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive},
	)
	selector, _ := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	updateTailBurstSnapshot(t, manager, "tail-auth")

	warmOpts := tailBurstAffinityOptions("warm-route")
	selector.BindAuthSession("codex", "", "cache-affinity:warm-route", "warm-auth")
	warm, errWarm := manager.SelectAuth(context.Background(), "codex", "", warmOpts)
	if errWarm != nil || warm == nil || warm.ID != "tail-auth" {
		t.Fatalf("normal warm binding tail-burst selection = %v, %v; want tail-auth", warm, errWarm)
	}

	cold, errCold := manager.SelectAuth(context.Background(), "codex", "", tailBurstAffinityOptions("cold-route"))
	if errCold != nil || cold == nil || cold.ID != "tail-auth" {
		t.Fatalf("cold tail-burst selection = %v, %v; want tail-auth", cold, errCold)
	}
}

func TestCodexTailBurstWarmTailCredentialKeepsBindingAndBurstCapacity(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "warm-tail", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"max_concurrency": 1}},
		&Auth{ID: "other-tail", Provider: "codex", Status: StatusActive},
	)
	selector, cfg := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	cfg.Codex.TailBurst.MaxConcurrency = 300
	manager.SetConfig(cfg)
	for _, authID := range []string{"warm-tail", "other-tail"} {
		if _, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot(authID, "", CodexQuotaSnapshot{UsedRatio: 0.985}); errUpdate != nil || !accepted {
			t.Fatalf("UpdateCodexQuotaSnapshot(%s) accepted=%t err=%v", authID, accepted, errUpdate)
		}
	}

	actual := tailBurstAuthForTest(t, manager, "warm-tail")
	occupiedRelease, occupied, reason, _ := actual.acquireRuntimeSlotForModel(time.Now(), "", false)
	if !occupied {
		t.Fatalf("occupy warm credential normal slot: %s", reason)
	}
	defer occupiedRelease()

	selector.BindAuthSession("codex", "", "cache-affinity:warm-tail-route", "warm-tail")
	selected, errSelected := manager.SelectAuth(context.Background(), "codex", "", tailBurstAffinityOptions("warm-tail-route"))
	if errSelected != nil || selected == nil || selected.ID != "warm-tail" {
		t.Fatalf("warm tail credential selection = %v, %v; want warm-tail", selected, errSelected)
	}
	burstRelease, acquired, reason, _ := selected.acquireRuntimeSlotForModel(time.Now(), "", true)
	if !acquired {
		t.Fatalf("warm tail credential did not receive burst capacity: %s", reason)
	}
	burstRelease()
}

func TestCodexTailBurstReleasesUnavailableWarmBinding(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "disabled-warm", Provider: "codex", Status: StatusDisabled, Disabled: true},
		&Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive},
	)
	selector, _ := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	updateTailBurstSnapshot(t, manager, "tail-auth")
	selector.BindAuthSession("codex", "", "cache-affinity:disabled-route", "disabled-warm")

	selected, errSelected := manager.SelectAuth(context.Background(), "codex", "", tailBurstAffinityOptions("disabled-route"))
	if errSelected != nil || selected == nil || selected.ID != "tail-auth" {
		t.Fatalf("disabled warm binding selection = %v, %v; want tail-auth", selected, errSelected)
	}
}

func TestCodexTailBurstRetryMayLeaveTriedWarmBinding(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "warm-auth", Provider: "codex", Status: StatusActive},
		&Auth{ID: "tail-auth", Provider: "codex", Status: StatusActive},
	)
	selector, _ := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	updateTailBurstSnapshot(t, manager, "tail-auth")
	opts := tailBurstAffinityOptions("retry-route")
	selector.BindAuthSession("codex", "", "cache-affinity:retry-route", "warm-auth")

	selected, _, errSelected := manager.pickNext(context.Background(), "codex", "", opts, map[string]struct{}{"warm-auth": {}})
	if errSelected != nil || selected == nil || selected.ID != "tail-auth" {
		t.Fatalf("retry tail-burst selection = %v, %v; want tail-auth", selected, errSelected)
	}
}

func TestCodexTailBurstFirstSuccessBecomesWarmBinding(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "tail-a", Provider: "codex", Status: StatusActive},
		&Auth{ID: "tail-b", Provider: "codex", Status: StatusActive},
	)
	selector, _ := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	for _, authID := range []string{"tail-a", "tail-b"} {
		if _, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot(authID, "", CodexQuotaSnapshot{UsedRatio: 0.985}); errUpdate != nil || !accepted {
			t.Fatalf("UpdateCodexQuotaSnapshot(%s) accepted=%t err=%v", authID, accepted, errUpdate)
		}
	}

	opts := tailBurstAffinityOptions("first-success-route")
	req := cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}
	first, errFirst := manager.executeMixedOnce(context.Background(), []string{"codex"}, req, opts, 2)
	if errFirst != nil {
		t.Fatalf("first tail-burst request: %v", errFirst)
	}
	second, errSecond := manager.executeMixedOnce(context.Background(), []string{"codex"}, req, opts, 2)
	if errSecond != nil {
		t.Fatalf("second tail-burst request: %v", errSecond)
	}
	if string(first.Payload) == "" || string(second.Payload) != string(first.Payload) {
		t.Fatalf("tail-burst affinity payloads first=%q second=%q; want identical non-empty auth IDs", first.Payload, second.Payload)
	}
}

func TestCodexTailBurstNormalConcurrencyCapIsIndependent(t *testing.T) {
	now := time.Now().UTC()
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "normal-cap", Provider: "codex", Status: StatusActive},
	)
	cfg := newTailBurstConfig()
	cfg.Codex.TailBurst.MaxConcurrency = 300
	manager.SetConfig(cfg)

	auth := tailBurstAuthForTest(t, manager, "normal-cap")
	settings := manager.codexTailBurstSettings()
	if settings.normalMaxConcurrency != 8 {
		t.Fatalf("normal max concurrency = %d, want default 8", settings.normalMaxConcurrency)
	}
	auth.tailBurstMaxConcurrency = settings.maxConcurrency

	releases := make([]func(), 0, 300)
	for i := 0; i < 8; i++ {
		release, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
		if !acquired {
			t.Fatalf("normal slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}
	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		t.Fatalf("normal slot 9 acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}

	for i := 8; i < 300; i++ {
		release, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", true)
		if !acquired {
			t.Fatalf("tail-burst slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", true); acquired || reason != "tail_burst_concurrency_limit" {
		t.Fatalf("tail-burst slot 301 acquired=%t reason=%q, want false/tail_burst_concurrency_limit", acquired, reason)
	}
}

func TestCodexTailBurstFallbackConcurrencyCapIsIndependent(t *testing.T) {
	now := time.Now().UTC()
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "fallback-cap", Provider: "codex", Status: StatusActive},
	)
	manager.SetConfig(newTailBurstConfig())

	normalAuth := tailBurstAuthForTest(t, manager, "fallback-cap")
	releases := make([]func(), 0, defaultCodexTailBurstFallbackConcurrency)
	for i := 0; i < defaultCodexTailBurstNormalConcurrency; i++ {
		release, acquired, reason, _ := normalAuth.acquireRuntimeSlotForModel(now, "gpt-5", false)
		if !acquired {
			t.Fatalf("normal slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}

	fallbackAuth := tailBurstAuthForTest(t, manager, "fallback-cap")
	fallbackAuth.tailBurstFallbackMaxConcurrency = manager.codexTailBurstSettings().fallbackMaxConcurrency
	for i := defaultCodexTailBurstNormalConcurrency; i < defaultCodexTailBurstFallbackConcurrency; i++ {
		release, acquired, reason, _ := fallbackAuth.acquireRuntimeSlotForModel(now, "gpt-5", false)
		if !acquired {
			t.Fatalf("fallback slot %d not acquired: %s", i+1, reason)
		}
		releases = append(releases, release)
	}
	t.Cleanup(func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	})

	if _, acquired, reason, _ := fallbackAuth.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "tail_burst_fallback_concurrency_limit" {
		t.Fatalf("fallback slot %d acquired=%t reason=%q, want false/tail_burst_fallback_concurrency_limit", defaultCodexTailBurstFallbackConcurrency+1, acquired, reason)
	}
}

func TestCodexTailBurstNormalConcurrencyCapHotReloads(t *testing.T) {
	now := time.Now().UTC()
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "hot-reload-cap", Provider: "codex", Status: StatusActive},
	)
	cfg := newTailBurstConfig()
	cfg.Codex.TailBurst.NormalMaxConcurrency = 2
	manager.SetConfig(cfg)
	auth := tailBurstAuthForTest(t, manager, "hot-reload-cap")

	firstRelease, firstAcquired, firstReason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !firstAcquired {
		t.Fatalf("first normal slot not acquired: %s", firstReason)
	}
	defer firstRelease()
	secondRelease, secondAcquired, secondReason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !secondAcquired {
		t.Fatalf("second normal slot not acquired: %s", secondReason)
	}
	defer secondRelease()
	if _, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false); acquired || reason != "concurrency_limit" {
		t.Fatalf("third slot before reload acquired=%t reason=%q, want false/concurrency_limit", acquired, reason)
	}

	cfg.Codex.TailBurst.NormalMaxConcurrency = 3
	manager.SetConfig(cfg)
	thirdRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatalf("third slot after reload not acquired: %s", reason)
	}
	defer thirdRelease()

	cfg.Codex.TailBurst.Enabled = false
	manager.SetConfig(cfg)
	fourthRelease, acquired, reason, _ := auth.acquireRuntimeSlotForModel(now, "gpt-5", false)
	if !acquired {
		t.Fatalf("fourth slot after disabling tail burst not acquired: %s", reason)
	}
	defer fourthRelease()
}

func TestCodexTailBurstAllowsConfiguredConcurrentRequests(t *testing.T) {
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

func TestCodexTailBurstIncludesExistingToolRequests(t *testing.T) {
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
	if got := string(second.Payload); got != "tail-auth" {
		t.Fatalf("tool request payload = %q, want tail-auth", got)
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

type codexTailBurstFallbackStreamExecutor struct {
	runtimeLimitTestExecutor
	tailBurstSelected map[string]bool
}

func (e *codexTailBurstFallbackStreamExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	if e.callCount == nil {
		e.callCount = make(map[string]int)
	}
	if e.tailBurstSelected == nil {
		e.tailBurstSelected = make(map[string]bool)
	}
	e.callCount[auth.ID]++
	callNumber := e.callCount[auth.ID]
	e.calls = append(e.calls, auth.ID)
	selected, _ := opts.Metadata[cliproxyexecutor.CodexTailBurstMetadataKey].(bool)
	e.tailBurstSelected[auth.ID] = selected
	errFirst := e.firstErrors[auth.ID]
	e.mu.Unlock()

	if errFirst != nil && callNumber == 1 {
		return nil, errFirst
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(auth.ID)}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestCodexTailBurstStreamingMigratesNormalWarmBinding(t *testing.T) {
	executor := &codexTailBurstStreamTestExecutor{}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	for _, auth := range []*Auth{
		{ID: "warm-stream", Provider: "codex", Status: StatusActive},
		{ID: "tail-stream", Provider: "codex", Status: StatusActive},
	} {
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}
	selector, _ := configureTailBurstAffinityManager(manager)
	defer selector.Stop()
	updateTailBurstSnapshot(t, manager, "tail-stream")
	selector.BindAuthSession("codex", "", "cache-affinity:warm-stream-route", "warm-stream")

	result, errStream := manager.executeStreamMixedOnce(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Payload: []byte(`{"input":"hello"}`)}, tailBurstAffinityOptions("warm-stream-route"), 2)
	if errStream != nil {
		t.Fatalf("warm ExecuteStream: %v", errStream)
	}
	var payload []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("warm stream chunk: %v", chunk.Err)
		}
		payload = append(payload, chunk.Payload...)
	}
	if string(payload) != "tail-stream" {
		t.Fatalf("warm stream payload = %q, want tail-stream", payload)
	}
}

func TestCodexTailBurstAllowsConfiguredConcurrentStreams(t *testing.T) {
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

func TestCodexTailBurstActivatesDuringSupplierExpiryWindowWithoutQuotaSnapshot(t *testing.T) {
	now := time.Now()
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	for _, auth := range []*Auth{
		{ID: "expiring", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"supply_lease_expires_at_ms": now.Add(9 * time.Minute).UnixMilli()}},
		{ID: "later", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"supply_lease_expires_at_ms": now.Add(11 * time.Minute).UnixMilli()}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}

	manager.mu.RLock()
	expiring := manager.auths["expiring"].Clone()
	later := manager.auths["later"].Clone()
	manager.mu.RUnlock()
	if !manager.codexTailBurstActive(expiring, "gpt-5-codex", now) {
		t.Fatal("supplier credential inside the final 10 minutes did not enter tail burst")
	}
	if manager.codexTailBurstActive(later, "gpt-5-codex", now) {
		t.Fatal("supplier credential outside the final 10 minutes entered tail burst early")
	}

	opts := manager.withCodexTailBurstRequestMetadata(context.Background(), []string{"codex"}, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"input":"hello"}`),
	}, cliproxyexecutor.Options{})
	if !codexTailBurstRequested(opts) {
		t.Fatal("expiry candidate index did not activate request-time tail routing")
	}
}

func TestCodexTailBurstFailureFallsBackToHighestRecentSuccessRate(t *testing.T) {
	now := time.Now()
	executor := &runtimeLimitTestExecutor{firstErrors: map[string]error{
		"expiring": &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exhausted"},
	}}
	manager := newRuntimeLimitManager(t, executor,
		&Auth{ID: "expiring", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"supply_lease_expires_at_ms": now.Add(5 * time.Minute).UnixMilli()}},
		&Auth{ID: "healthy-high", Provider: "codex", Status: StatusActive},
		&Auth{ID: "healthy-low", Provider: "codex", Status: StatusActive},
	)
	manager.SetConfig(newTailBurstConfig())
	manager.SetRetryConfig(0, 0, 1)
	occupyNormalConcurrencyForTest(t, manager, "healthy-high", defaultCodexTailBurstNormalConcurrency)

	manager.mu.Lock()
	for i := 0; i < 20; i++ {
		manager.auths["healthy-high"].recordRecentRequest(now, true)
	}
	manager.auths["healthy-high"].recordRecentRequest(now, false)
	for i := 0; i < 2; i++ {
		manager.auths["healthy-low"].recordRecentRequest(now, true)
	}
	for i := 0; i < 4; i++ {
		manager.auths["healthy-low"].recordRecentRequest(now, false)
	}
	manager.mu.Unlock()

	response, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{
		Payload: []byte(`{"input":"hello"}`),
	}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("Execute: %v", errExecute)
	}
	if got := string(response.Payload); got != "healthy-high" {
		t.Fatalf("fallback payload = %q, want healthy-high", got)
	}

	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 2 || calls[0] != "expiring" || calls[1] != "healthy-high" {
		t.Fatalf("execution order = %v, want [expiring healthy-high]", calls)
	}
}

func TestCodexTailBurstFrozenCandidateFallsBackAboveNormalConcurrencyCap(t *testing.T) {
	executor := &runtimeLimitTestExecutor{}
	manager := newRuntimeLimitManager(t, executor,
		&Auth{ID: "tail-frozen", Provider: "codex", Status: StatusActive},
		&Auth{ID: "healthy", Provider: "codex", Status: StatusActive},
	)
	manager.SetConfig(newTailBurstConfig())
	updateTailBurstSnapshot(t, manager, "tail-frozen")

	tailAuth := tailBurstAuthForTest(t, manager, "tail-frozen")
	retryAfter := time.Minute
	if !tailAuth.freezeUpstreamRateLimit(time.Now(), &retryAfter) {
		t.Fatal("tail credential was not frozen")
	}
	occupyNormalConcurrencyForTest(t, manager, "healthy", defaultCodexTailBurstNormalConcurrency)

	response, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{
		Payload: []byte(`{"input":"hello"}`),
	}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("Execute: %v", errExecute)
	}
	if got := string(response.Payload); got != "healthy" {
		t.Fatalf("fallback payload = %q, want healthy", got)
	}

	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0] != "healthy" {
		t.Fatalf("execution order = %v, want [healthy]", calls)
	}
}

func TestCodexTailBurstStream429FallsBackAboveNormalConcurrencyCap(t *testing.T) {
	executor := &codexTailBurstFallbackStreamExecutor{runtimeLimitTestExecutor: runtimeLimitTestExecutor{
		firstErrors: map[string]error{
			"tail-stream": &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exhausted"},
		},
	}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	for _, auth := range []*Auth{
		{ID: "tail-stream", Provider: "codex", Status: StatusActive},
		{ID: "healthy-stream", Provider: "codex", Status: StatusActive},
	} {
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}
	cfg := newTailBurstConfig()
	cfg.Routing.NewCandidateMode = true
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 1)
	updateTailBurstSnapshot(t, manager, "tail-stream")
	occupyNormalConcurrencyForTest(t, manager, "healthy-stream", defaultCodexTailBurstNormalConcurrency)

	result, errStream := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{
		Payload: []byte(`{"input":"hello"}`),
	}, cliproxyexecutor.Options{Stream: true})
	if errStream != nil {
		t.Fatalf("ExecuteStream: %v", errStream)
	}
	var payload []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk: %v", chunk.Err)
		}
		payload = append(payload, chunk.Payload...)
	}
	if got := string(payload); got != "healthy-stream" {
		t.Fatalf("fallback stream payload = %q, want healthy-stream", got)
	}

	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	tailSelected := executor.tailBurstSelected["tail-stream"]
	fallbackSelected := executor.tailBurstSelected["healthy-stream"]
	executor.mu.Unlock()
	if len(calls) != 2 || calls[0] != "tail-stream" || calls[1] != "healthy-stream" {
		t.Fatalf("stream execution order = %v, want [tail-stream healthy-stream]", calls)
	}
	if !tailSelected || fallbackSelected {
		t.Fatalf("tail-burst tool metadata tail=%t fallback=%t, want true/false", tailSelected, fallbackSelected)
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

func TestCodexTailBurstKeepsRoundedHundredPercentUntilProviderRejects(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(newTailBurstConfig())
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "rounded-tail", Provider: "codex", Status: StatusActive}); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	if _, accepted, errUpdate := manager.UpdateCodexQuotaSnapshot("rounded-tail", "", CodexQuotaSnapshot{UsedRatio: 1}); errUpdate != nil || !accepted {
		t.Fatalf("UpdateCodexQuotaSnapshot accepted=%t err=%v", accepted, errUpdate)
	}

	manager.mu.RLock()
	auth := manager.auths["rounded-tail"]
	manager.mu.RUnlock()
	if !manager.codexTailBurstActive(auth, "", time.Now()) {
		t.Fatal("rounded 100% snapshot left the tail lane before an upstream quota error")
	}
	if ids := codexTailBurstCandidateIDs(manager, "*"); len(ids) != 1 || ids[0] != auth.ID {
		t.Fatalf("rounded tail candidates = %v, want [%s]", ids, auth.ID)
	}

	auth.Quota = QuotaState{Exceeded: true}
	manager.refreshCodexTailBurstCandidates()
	if manager.codexTailBurstActive(auth, "", time.Now()) {
		t.Fatal("authoritative provider quota failure remained active in the tail lane")
	}
	if ids := codexTailBurstCandidateIDs(manager, "*"); len(ids) != 0 {
		t.Fatalf("provider-exhausted tail candidates = %v, want none", ids)
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
