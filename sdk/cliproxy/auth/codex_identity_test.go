package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
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

func TestDeactivatedWorkspaceDisablesEveryWorkspaceMember(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	for _, auth := range []*Auth{
		{ID: "member-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com"}},
		{ID: "member-a-copy", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com"}},
		{ID: "member-b", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "b@example.com"}},
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

	for _, id := range []string{"member-a", "member-a-copy", "member-b"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || !got.Disabled || got.Status != StatusDisabled {
			t.Fatalf("%s = %#v, want disabled", id, got)
		}
	}
	other, ok := manager.GetByID("other")
	if !ok || other == nil || other.Disabled {
		t.Fatalf("other = %#v, want active", other)
	}
}

func TestRefreshDeactivatedWorkspaceDisablesEveryWorkspaceMember(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(deactivatedWorkspaceRefreshExecutor{
		schedulerTestExecutor: schedulerTestExecutor{provider: "codex"},
	})
	for _, auth := range []*Auth{
		{ID: "member-a", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "a@example.com", "refresh_token": "refresh-a"}},
		{ID: "member-b", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-one", "email": "b@example.com", "refresh_token": "refresh-b"}},
		{ID: "other", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"chatgpt_account_id": "workspace-two", "email": "c@example.com", "refresh_token": "refresh-c"}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}

	if _, errRefresh := manager.refreshAuthForRequest(context.Background(), "member-a", ""); errRefresh == nil {
		t.Fatal("refreshAuthForRequest() error = nil, want deactivated_workspace")
	}
	for _, id := range []string{"member-a", "member-b"} {
		got, ok := manager.GetByID(id)
		if !ok || got == nil || !got.Disabled || got.Status != StatusDisabled {
			t.Fatalf("%s = %#v, want disabled", id, got)
		}
	}
	other, ok := manager.GetByID("other")
	if !ok || other == nil || other.Disabled {
		t.Fatalf("other = %#v, want active", other)
	}
}
