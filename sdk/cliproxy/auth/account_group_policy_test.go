package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type accountGroupPolicyGinContext map[string]any

func (c accountGroupPolicyGinContext) Get(key string) (any, bool) {
	value, ok := c[key]
	return value, ok
}

func TestAccountGroupPolicyRestrictsSchedulerSelection(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}},
	}})

	for _, auth := range []*Auth{
		{ID: "group-1", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		{ID: "group-2-a", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
		{ID: "group-2-b", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2, 3}}},
		{ID: "ungrouped", Provider: "test", Status: StatusActive, Metadata: map[string]any{}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}

	opts := manager.withAccountGroupPolicy(cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	seen := make(map[string]struct{})
	for range 8 {
		picked, errPick := manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil)
		if errPick != nil {
			t.Fatalf("pickSingle: %v", errPick)
		}
		if picked.ID != "group-2-a" && picked.ID != "group-2-b" {
			t.Fatalf("picked restricted auth %q outside group 2", picked.ID)
		}
		seen[picked.ID] = struct{}{}
	}
	if len(seen) != 2 {
		t.Fatalf("restricted round robin saw %v, want both group-2 auths", seen)
	}

	manager.scheduler.mu.Lock()
	provider := manager.scheduler.providers["test"]
	shard := provider.ensureModelLocked("", testNow())
	bucket := shard.readyByPriority[0]
	cacheSize := len(bucket.groupViews)
	manager.scheduler.mu.Unlock()
	if cacheSize != 1 {
		t.Fatalf("group view cache size = %d, want 1", cacheSize)
	}
}

func TestAccountGroupPolicyWithMissingGroupReturnsNoAuth(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{99},
		}},
	}})
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID: "group-1", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}
	opts := manager.withAccountGroupPolicy(cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	if _, errPick := manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil); errPick == nil {
		t.Fatal("pickSingle succeeded for missing allowed group")
	}
}

func TestAccountGroupMembershipUpdateInvalidatesCachedReadyView(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}},
	}})
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID: "moving", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}
	opts := manager.withAccountGroupPolicy(cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	if _, errPick := manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil); errPick == nil {
		t.Fatal("pickSingle succeeded before the auth joined group 2")
	}
	updated, found := manager.GetByID("moving")
	if !found {
		t.Fatal("moving auth not found")
	}
	updated.Metadata["group_ids"] = []any{2}
	if _, errUpdate := manager.Update(context.Background(), updated); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	picked, errPick := manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil)
	if errPick != nil {
		t.Fatalf("pickSingle after membership update: %v", errPick)
	}
	if picked.ID != "moving" {
		t.Fatalf("picked auth = %q, want moving", picked.ID)
	}
}

func TestAccountGroupPolicyRestrictsHomeDispatch(t *testing.T) {
	dispatcher := &codexRestrictionHomeDispatcher{auths: map[int]Auth{
		1: {ID: "group-1", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		2: {ID: "group-2", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	}}
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}}},
		Home: internalconfig.HomeConfig{Enabled: true},
	})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)

	selection, errSelection := manager.pickHomeDispatchSelection(context.Background(), "gpt", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	if errSelection != nil {
		t.Fatalf("pickHomeDispatchSelection() error = %v", errSelection)
	}
	defer selection.End("test_complete")
	selected := selection.CloneAuth()
	if selected == nil || selected.ID != "group-2" || selection.DispatchCount() != 2 {
		t.Fatalf("selection = %#v count=%d, want group-2 at count 2", selected, selection.DispatchCount())
	}
}

func TestAccountGroupPolicyUsesAuthenticatedContext(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}},
	}})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "test"})
	for _, auth := range []*Auth{
		{ID: "group-1", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		{ID: "group-2", Provider: "test", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	ctx := context.WithValue(context.Background(), "gin", accountGroupPolicyGinContext{"userApiKey": "restricted-key"})
	picked, _, errPick := manager.pickNext(ctx, "test", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickNext: %v", errPick)
	}
	if picked == nil || picked.ID != "group-2" {
		t.Fatalf("pickNext auth = %#v, want group-2", picked)
	}
}

func TestAccountGroupPolicyRestrictsMixedAndPinnedSelection(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}},
	}})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "provider-a"})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "provider-b"})
	for _, auth := range []*Auth{
		{ID: "group-1", Provider: "provider-a", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		{ID: "group-2", Provider: "provider-b", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}}
	picked, _, provider, errPick := manager.pickNextMixed(context.Background(), []string{"provider-a", "provider-b"}, "", opts, nil)
	if errPick != nil {
		t.Fatalf("pickNextMixed: %v", errPick)
	}
	if picked == nil || picked.ID != "group-2" || provider != "provider-b" {
		t.Fatalf("mixed selection = %#v provider=%q, want group-2/provider-b", picked, provider)
	}

	pinnedOpts := opts
	pinnedOpts.Metadata = map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
		cliproxyexecutor.PinnedAuthMetadataKey:           "group-1",
	}
	if pinned, _, _, errPinned := manager.pickNextMixed(context.Background(), []string{"provider-a", "provider-b"}, "", pinnedOpts, nil); errPinned == nil || pinned != nil {
		t.Fatalf("pinned selection = %#v error=%v, want group-restricted failure", pinned, errPinned)
	}
}

func TestAccountGroupPolicyRestrictsQuotaFallback(t *testing.T) {
	now := time.Now()
	manager := newQuotaPreemptFallbackManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "group-1", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		&Auth{ID: "group-2", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	)
	manager.SetConfig(&internalconfig.Config{
		SDKConfig: internalconfig.SDKConfig{APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}}},
		Codex: internalconfig.CodexConfig{CacheAffinity: internalconfig.CodexCacheAffinityConfig{
			Enabled:                true,
			QuotaPreemptUsedRatio:  0.97,
			QuotaHardStopUsedRatio: 0.99,
		}},
	})
	freezeQuotaFallbackAuth(t, manager, "group-1", 0.995, now)
	freezeQuotaFallbackAuth(t, manager, "group-2", 0.996, now)

	response, errExecute := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	if errExecute != nil {
		t.Fatalf("Execute: %v", errExecute)
	}
	if got := string(response.Payload); got != "group-2" {
		t.Fatalf("fallback payload = %q, want group-2", got)
	}
}

func TestAccountGroupPolicyRestrictsTailBurst(t *testing.T) {
	manager := newRuntimeLimitManager(t, &runtimeLimitTestExecutor{},
		&Auth{ID: "tail-group-1", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		&Auth{ID: "normal-group-2", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	)
	cfg := newTailBurstConfig()
	cfg.SDKConfig.APIKeyGroupPolicies = []internalconfig.APIKeyGroupPolicy{{
		APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
		AllowedGroupIDs: []int64{2},
	}}
	manager.SetConfig(cfg)
	updateTailBurstSnapshot(t, manager, "tail-group-1")

	picked, _, errPick := manager.pickNext(context.Background(), "codex", "", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
		codexTailBurstRequestedMetadataKey:               true,
	}}, nil)
	if errPick != nil {
		t.Fatalf("pickNext: %v", errPick)
	}
	if picked == nil || picked.ID != "normal-group-2" {
		t.Fatalf("tail-burst selection = %#v, want normal-group-2", picked)
	}
}

func TestAccountGroupPolicyRestrictsAntigravityCreditsFallbackCandidates(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{2},
		}},
	}})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "antigravity"})
	for _, auth := range []*Auth{
		{ID: "credits-group-1", Provider: "antigravity", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{1}}},
		{ID: "credits-group-2", Provider: "antigravity", Status: StatusActive, Metadata: map[string]any{"group_ids": []any{2}}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	candidates, errCandidates := manager.findAllAntigravityCreditsCandidateAuths(context.Background(), "claude-sonnet-4-6", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	if errCandidates != nil {
		t.Fatalf("findAllAntigravityCreditsCandidateAuths: %v", errCandidates)
	}
	if len(candidates) != 1 || candidates[0].auth.ID != "credits-group-2" {
		t.Fatalf("credits candidates = %#v, want only credits-group-2", candidates)
	}
}

func TestAccountGroupSchedulerCachesAreBounded(t *testing.T) {
	groupCount := maxAccountGroupMixedStateEntries + 20
	groupIDs := make([]any, 0, groupCount)
	for id := 1; id <= groupCount; id++ {
		groupIDs = append(groupIDs, int64(id))
	}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	for _, auth := range []*Auth{
		{ID: "provider-a", Provider: "provider-a", Status: StatusActive, Metadata: map[string]any{"group_ids": groupIDs}},
		{ID: "provider-b", Provider: "provider-b", Status: StatusActive, Metadata: map[string]any{"group_ids": groupIDs}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	for id := 1; id <= groupCount; id++ {
		opts := cliproxyexecutor.Options{Metadata: map[string]any{
			cliproxyexecutor.AccountGroupPolicyEvaluatedMetadataKey: true,
			cliproxyexecutor.AllowedAccountGroupIDsMetadataKey:      []int64{int64(id)},
		}}
		if _, _, errPick := manager.scheduler.pickMixed(context.Background(), []string{"provider-a", "provider-b"}, "", opts, nil); errPick != nil {
			t.Fatalf("pickMixed group %d: %v", id, errPick)
		}
	}

	manager.scheduler.mu.Lock()
	defer manager.scheduler.mu.Unlock()
	if got := len(manager.scheduler.mixedGroupStateKeys); got != maxAccountGroupMixedStateEntries {
		t.Fatalf("mixed group state cache size = %d, want %d", got, maxAccountGroupMixedStateEntries)
	}
	for _, provider := range []string{"provider-a", "provider-b"} {
		shard := manager.scheduler.providers[provider].ensureModelLocked("", time.Now())
		bucket := shard.readyByPriority[0]
		if got := len(bucket.groupViews); got > maxAccountGroupReadyViewCacheEntries {
			t.Fatalf("%s ready-view cache size = %d, max %d", provider, got, maxAccountGroupReadyViewCacheEntries)
		}
	}
}

func BenchmarkAccountGroupPolicySchedulerLargePool(b *testing.B) {
	auths := make([]*Auth, 0, 10000)
	for index := 0; index < 10000; index++ {
		groupID := int64(1)
		if index%100 == 0 {
			groupID = 7
		}
		auths = append(auths, &Auth{
			ID:       fmt.Sprintf("auth-%05d", index),
			Provider: "test",
			Status:   StatusActive,
			Metadata: map[string]any{"group_ids": []any{groupID}},
		})
	}
	manager := NewManager(&schedulerLoadStore{auths: auths}, &RoundRobinSelector{}, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyGroupPolicies: []internalconfig.APIKeyGroupPolicy{{
			APIKeyHash:      internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
			AllowedGroupIDs: []int64{7},
		}},
	}})
	if errLoad := manager.Load(context.Background()); errLoad != nil {
		b.Fatal(errLoad)
	}
	opts := manager.withAccountGroupPolicy(cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.DownstreamAPIKeyHashMetadataKey: internalconfig.HashAPIKeyForGroupPolicy("restricted-key"),
	}})
	_, _ = manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil)
	b.ResetTimer()
	for range b.N {
		if _, errPick := manager.scheduler.pickSingle(context.Background(), "test", "", opts, nil); errPick != nil {
			b.Fatal(errPick)
		}
	}
}

func testNow() time.Time { return time.Now() }
