package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type deactivatedWorkspaceRefreshExecutor struct {
	schedulerTestExecutor
}

func (deactivatedWorkspaceRefreshExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, errors.New(`codex refresh failed: {"detail":{"code":"deactivated_workspace"}}`)
}

func TestNewCandidateModeDeduplicatesCanonicalCodexIdentity(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	duplicate := func(id string, fingerprint bool) *Auth {
		metadata := map[string]any{
			"chatgpt_account_id": "workspace-one",
			"email":              "member@example.com",
			"access_token":       "shared-access-token",
		}
		if fingerprint {
			metadata["codex_identity_fingerprint"] = "stable-fingerprint"
		}
		return &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: metadata}
	}
	if _, errRegister := manager.Register(context.Background(), duplicate("manual-copy", false)); errRegister != nil {
		t.Fatal(errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), duplicate("managed-copy", true)); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.SetConfig(&internalconfig.Config{Routing: internalconfig.RoutingConfig{NewCandidateMode: true}})

	for attempt := 0; attempt < 4; attempt++ {
		got, _, errPick := manager.pickNext(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatal(errPick)
		}
		if got == nil || got.ID != "managed-copy" {
			t.Fatalf("pick #%d = %#v, want managed-copy", attempt, got)
		}
	}
}

func TestNewCandidateModeKeepsReadyDuplicateWhenPreferredCopyIsDisabled(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	shared := map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com"}
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID: "ready-copy", Provider: "codex", Status: StatusActive, Metadata: shared,
	}); errRegister != nil {
		t.Fatal(errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID: "preferred-disabled", Provider: "codex", Status: StatusDisabled, Disabled: true,
		Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com", "codex_identity_fingerprint": "stable"},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.SetConfig(&internalconfig.Config{Routing: internalconfig.RoutingConfig{NewCandidateMode: true}})
	got, _, errPick := manager.pickNext(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if got == nil || got.ID != "ready-copy" {
		t.Fatalf("pick = %#v, want ready-copy", got)
	}
}

func TestCandidateSnapshotKeepsReadyDuplicateWhenPreferredCopyIsCooling(t *testing.T) {
	scheduler := newAuthScheduler(&RoundRobinSelector{})
	scheduler.upsertAuth(&Auth{
		ID: "ready-copy", Provider: "codex", Status: StatusActive,
		Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com"},
	})
	scheduler.upsertAuth(&Auth{
		ID: "preferred-cooling", Provider: "codex", Status: StatusError, Unavailable: true,
		NextRetryAfter: time.Now().Add(time.Hour),
		Metadata:       map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com", "codex_identity_fingerprint": "stable"},
	})

	candidates := scheduler.snapshotCandidates([]string{"codex"}, "")
	if len(candidates) != 1 || candidates[0] == nil || candidates[0].ID != "ready-copy" {
		t.Fatalf("snapshotCandidates() = %#v, want only ready-copy", candidates)
	}
}

func TestDeactivatedWorkspaceDisablesOnlyMatchingMemberCopies(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	for _, auth := range []*Auth{
		{ID: "member-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com", "codex_identity_fingerprint": "fingerprint-a"}},
		{ID: "member-a-copy", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com", "codex_identity_fingerprint": "fingerprint-a"}},
		{ID: "member-b", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "b@example.com", "codex_identity_fingerprint": "fingerprint-b"}},
		{ID: "other", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-two", "email": "c@example.com"}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	manager.MarkResult(context.Background(), Result{
		AuthID:   "member-a",
		Provider: "codex",
		Model:    "gpt-test",
		Error: &Error{
			Code:       terminalCredentialErrorCode,
			Message:    `{"detail":{"code":"deactivated_workspace"}}`,
			HTTPStatus: http.StatusPaymentRequired,
		},
	})

	for _, id := range []string{"member-a", "member-a-copy"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || !got.Disabled || got.Status != StatusDisabled {
			t.Fatalf("%s = %#v, want disabled", id, got)
		}
	}
	for _, id := range []string{"member-b", "other"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || got.Disabled {
			t.Fatalf("%s = %#v, want active", id, got)
		}
	}
}

func TestAccountCooldownPropagatesToCanonicalCodexDuplicate(t *testing.T) {
	tests := []struct {
		name      string
		resultErr *Error
		quota     bool
		reason    blockReason
	}{
		{name: "unauthorized", resultErr: &Error{Code: "unauthorized", Message: "token rejected", HTTPStatus: http.StatusUnauthorized}, reason: blockReasonOther},
		{name: "payment required", resultErr: &Error{Code: "payment_required", Message: "payment required", HTTPStatus: http.StatusPaymentRequired}, reason: blockReasonOther},
		{name: "forbidden", resultErr: &Error{Code: "forbidden", Message: "account forbidden", HTTPStatus: http.StatusForbidden}, reason: blockReasonOther},
		{name: "quota", resultErr: &Error{Code: "rate_limit", Message: "weekly quota reached", HTTPStatus: http.StatusTooManyRequests}, quota: true, reason: blockReasonCooldown},
		{name: "invalid grant", resultErr: &Error{Code: "invalid_grant", Message: "refresh failed: invalid_grant", HTTPStatus: http.StatusBadRequest}, reason: blockReasonOther},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := NewManager(nil, &RoundRobinSelector{}, nil)
			modelRegistry := registry.GetGlobalRegistry()
			for _, auth := range []*Auth{
				{ID: "managed-copy", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com", "codex_identity_fingerprint": "stable"}},
				{ID: "manual-copy", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "member@example.com"}},
				{ID: "other-member", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "other@example.com"}},
			} {
				if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
					t.Fatal(errRegister)
				}
				modelRegistry.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gpt-test"}})
				t.Cleanup(func() { modelRegistry.UnregisterClient(auth.ID) })
			}
			manager.MarkResult(context.Background(), Result{
				AuthID: "managed-copy", Provider: "codex", Model: "gpt-test", Error: test.resultErr,
			})

			for _, id := range []string{"managed-copy", "manual-copy"} {
				got, ok := manager.GetByID(id)
				if !ok || got == nil {
					t.Fatalf("%s missing", id)
				}
				state := got.ModelStates["gpt-test"]
				if state == nil || !state.Unavailable || state.NextRetryAfter.IsZero() {
					t.Fatalf("%s = %#v, state=%#v, want propagated cooldown", id, got, state)
				}
				if state.Quota.Exceeded != test.quota {
					t.Fatalf("%s quota exceeded = %v, want %v", id, state.Quota.Exceeded, test.quota)
				}
				if blocked, reason, _ := isAuthBlockedForModel(got, "gpt-test", time.Now()); !blocked || reason != test.reason {
					t.Fatalf("%s blocked = %v reason = %v, want %v", id, blocked, reason, test.reason)
				}
			}
			wantModelCount := 1
			if test.quota {
				// Registry quota state keeps both a quota marker and a suspension,
				// so GetModelCount conservatively counts each cooling client twice.
				wantModelCount = 0
			}
			if count := modelRegistry.GetModelCount("gpt-test"); count != wantModelCount {
				t.Fatalf("registry model count = %d, want %d", count, wantModelCount)
			}
			other, ok := manager.GetByID("other-member")
			if !ok || other == nil || other.Unavailable || other.ModelStates["gpt-test"] != nil {
				t.Fatalf("other-member = %#v, want unaffected", other)
			}
		})
	}
}

func TestRefreshDeactivatedWorkspaceDisablesOnlyMatchingMemberCopies(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(deactivatedWorkspaceRefreshExecutor{
		schedulerTestExecutor: schedulerTestExecutor{provider: "codex"},
	})
	for _, auth := range []*Auth{
		{ID: "member-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com", "refresh_token": "refresh-a", "codex_identity_fingerprint": "fingerprint-a"}},
		{ID: "member-a-copy", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com", "refresh_token": "refresh-a-copy", "codex_identity_fingerprint": "fingerprint-a"}},
		{ID: "member-b", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "b@example.com", "refresh_token": "refresh-b", "codex_identity_fingerprint": "fingerprint-b"}},
		{ID: "other", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-two", "email": "c@example.com", "refresh_token": "refresh-c"}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	if _, errRefresh := manager.refreshAuthForRequest(context.Background(), "member-a", ""); errRefresh == nil {
		t.Fatal("refreshAuthForRequest() error = nil, want deactivated_workspace")
	}
	for _, id := range []string{"member-a", "member-a-copy"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || !got.Disabled || got.Status != StatusDisabled {
			t.Fatalf("%s = %#v, want disabled", id, got)
		}
	}
	for _, id := range []string{"member-b", "other"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || got.Disabled {
			t.Fatalf("%s = %#v, want active", id, got)
		}
	}
}

func TestCanonicalIdentityUsesFingerprintWithoutMemberClaims(t *testing.T) {
	first := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"codex_identity_fingerprint": "stable-member",
		"access_token":               "access-one",
	}}
	rotated := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"codex_identity_fingerprint": "stable-member",
		"access_token":               "access-two",
	}}
	other := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"codex_identity_fingerprint": "other-member",
		"access_token":               "access-one",
	}}

	if got, want := codexCanonicalIdentityKey(rotated), codexCanonicalIdentityKey(first); got == "" || got != want {
		t.Fatalf("rotated identity = %q, want %q", got, want)
	}
	if got := codexCanonicalIdentityKey(other); got == codexCanonicalIdentityKey(first) {
		t.Fatalf("other fingerprint identity = %q, want distinct", got)
	}
}

func TestSameMemberIdentityUsesFingerprintsAuthoritatively(t *testing.T) {
	managed := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"email":                      "member@example.com",
		"codex_identity_fingerprint": "fingerprint-one",
	}}
	sameMemberCopy := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"email":                      "member@example.com",
		"codex_identity_fingerprint": "fingerprint-one",
	}}
	differentFingerprint := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"email":                      "member@example.com",
		"codex_identity_fingerprint": "fingerprint-two",
	}}
	legacyCopy := &Auth{Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id": "workspace-one",
		"email":              "member@example.com",
	}}
	otherProvider := &Auth{Provider: "claude", Metadata: map[string]any{
		"chatgpt_account_id":         "workspace-one",
		"email":                      "member@example.com",
		"codex_identity_fingerprint": "fingerprint-one",
	}}

	if !codexSameMemberIdentity(managed, sameMemberCopy) {
		t.Fatal("matching fingerprints should identify copies of the same member")
	}
	if codexSameMemberIdentity(managed, differentFingerprint) {
		t.Fatal("different fingerprints must remain isolated even when legacy claims match")
	}
	if !codexSameMemberIdentity(managed, legacyCopy) {
		t.Fatal("a legacy copy without a fingerprint should fall back to member claims")
	}
	if codexSameMemberIdentity(managed, otherProvider) {
		t.Fatal("credentials from another provider must remain isolated")
	}
}

func TestEnsureCodexIdentityFingerprintIsStableAndMemberScoped(t *testing.T) {
	first := &Auth{ID: "first.json", Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id": "workspace-one",
		"chatgpt_user_id":    "user-one",
	}}
	rotated := &Auth{ID: "rotated.json", Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id": "workspace-one",
		"chatgpt_user_id":    "USER-ONE",
	}}
	otherMember := &Auth{ID: "other.json", Provider: "codex", Metadata: map[string]any{
		"chatgpt_account_id": "workspace-one",
		"chatgpt_user_id":    "user-two",
	}}

	firstFingerprint, firstChanged := EnsureCodexIdentityFingerprint(first, first.ID)
	rotatedFingerprint, rotatedChanged := EnsureCodexIdentityFingerprint(rotated, rotated.ID)
	otherFingerprint, otherChanged := EnsureCodexIdentityFingerprint(otherMember, otherMember.ID)
	if !firstChanged || !rotatedChanged || !otherChanged {
		t.Fatalf("fingerprints were not persisted: first=%v rotated=%v other=%v", firstChanged, rotatedChanged, otherChanged)
	}
	if firstFingerprint == "" || firstFingerprint != rotatedFingerprint {
		t.Fatalf("same member fingerprint changed across files: first=%q rotated=%q", firstFingerprint, rotatedFingerprint)
	}
	if firstFingerprint == otherFingerprint {
		t.Fatalf("different Team members share fingerprint %q", firstFingerprint)
	}
	if got, _ := first.Metadata[MetadataCodexIdentityFingerprint].(string); got != firstFingerprint {
		t.Fatalf("persisted fingerprint = %q, want %q", got, firstFingerprint)
	}
}

func TestInheritCodexIdentityFingerprintKeepsExistingNamespace(t *testing.T) {
	existing := &Auth{ID: "account.json", Provider: "codex", Metadata: map[string]any{
		"email":                          "old@example.com",
		MetadataCodexIdentityFingerprint: "stable-fingerprint",
	}}
	incoming := &Auth{ID: "account.json", Provider: "codex", Metadata: map[string]any{
		"email":                          "new@example.com",
		MetadataCodexIdentityFingerprint: "replacement-fingerprint",
	}}
	fingerprint, changed := InheritCodexIdentityFingerprint(incoming, existing, incoming.ID)
	if !changed || fingerprint != "stable-fingerprint" {
		t.Fatalf("inherit fingerprint = %q changed=%v, want stable-fingerprint/true", fingerprint, changed)
	}
	if got := CodexIdentityFingerprint(incoming); got != "stable-fingerprint" {
		t.Fatalf("incoming fingerprint = %q, want stable-fingerprint", got)
	}
}
