package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type codexRestrictionHomeDispatcher struct {
	mu     sync.Mutex
	counts []int
	auths  map[int]Auth
}

func (*codexRestrictionHomeDispatcher) HeartbeatOK() bool { return true }

func (d *codexRestrictionHomeDispatcher) RPopAuth(_ context.Context, _ string, _ string, _ http.Header, count int) ([]byte, error) {
	d.mu.Lock()
	d.counts = append(d.counts, count)
	auth, ok := d.auths[count]
	if !ok {
		auth = d.auths[1]
	}
	d.mu.Unlock()
	return json.Marshal(homeAuthDispatchResponse{Auth: auth})
}

func (*codexRestrictionHomeDispatcher) AbortAmbiguousDispatch() {}

func (d *codexRestrictionHomeDispatcher) Counts() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int(nil), d.counts...)
}

func homeCodexAuth(id string, restricted bool) Auth {
	metadata := map[string]any{"access_token": "token-" + id}
	if restricted {
		metadata["codex_cli_only"] = true
	}
	return Auth{
		ID: id, Provider: "codex", Status: StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth},
		Metadata:   metadata,
	}
}

func newCodexRestrictionHomeManager(dispatcher homeAuthDispatcher) *Manager {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{
		Home: internalconfig.HomeConfig{Enabled: true},
		Codex: internalconfig.CodexConfig{ClientRestriction: internalconfig.CodexClientRestrictionConfig{
			EngineFingerprintSignals: []internalconfig.CodexEngineFingerprintSignal{{Type: "header_prefix", Match: []string{"x-codex-"}, Required: true}},
		}},
	})
	manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
	return manager
}

func restrictedHomeOptions() cliproxyexecutor.Options {
	headers := http.Header{"User-Agent": {"curl/8.0"}}
	return cliproxyexecutor.Options{Headers: headers, OriginalHeaders: headers.Clone()}
}

func TestHomeCodexClientRestrictionFallsBackToOrdinaryAuth(t *testing.T) {
	dispatcher := &codexRestrictionHomeDispatcher{auths: map[int]Auth{
		1: homeCodexAuth("team-protected", true),
		2: homeCodexAuth("ordinary", false),
	}}
	manager := newCodexRestrictionHomeManager(dispatcher)
	opts := manager.enrichCodexClientRestriction([]string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5.6"}, restrictedHomeOptions())

	selection, errSelection := manager.pickHomeDispatchSelection(context.Background(), "gpt-5.6", opts)
	if errSelection != nil {
		t.Fatalf("pickHomeDispatchSelection() error = %v", errSelection)
	}
	defer selection.End("test_complete")
	selected := selection.CloneAuth()
	if selected == nil || selected.ID != "ordinary" || selection.DispatchCount() != 2 {
		t.Fatalf("selection = %#v count=%d, want ordinary at count 2", selected, selection.DispatchCount())
	}
	if got := dispatcher.Counts(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("dispatch counts = %#v, want [1 2]", got)
	}
}

func TestHomeCodexClientRestrictionReturnsUniformForbiddenForProtectedPool(t *testing.T) {
	dispatcher := &codexRestrictionHomeDispatcher{auths: map[int]Auth{1: homeCodexAuth("team-protected", true)}}
	manager := newCodexRestrictionHomeManager(dispatcher)
	opts := manager.enrichCodexClientRestriction([]string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5.6"}, restrictedHomeOptions())

	_, errSelection := manager.pickHomeDispatchSelection(context.Background(), "gpt-5.6", opts)
	var authErr *Error
	if !errors.As(errSelection, &authErr) || authErr.Code != "codex_client_restricted" || authErr.HTTPStatus != http.StatusForbidden || authErr.Message != codexClientRestrictionMessage {
		t.Fatalf("pickHomeDispatchSelection() error = %#v, want uniform 403", errSelection)
	}
}

func TestSelectHomeAuthByKindAppliesCodexClientRestriction(t *testing.T) {
	dispatcher := &codexRestrictionHomeDispatcher{auths: map[int]Auth{
		1: homeCodexAuth("team-protected", true),
		2: homeCodexAuth("ordinary", false),
	}}
	manager := newCodexRestrictionHomeManager(dispatcher)
	selection, errSelection := manager.SelectHomeAuthByKind(
		context.Background(),
		"codex",
		"gpt-5.6",
		AuthKindOAuth,
		restrictedHomeOptions(),
	)
	if errSelection != nil {
		t.Fatalf("SelectHomeAuthByKind() error = %v", errSelection)
	}
	defer selection.End("test_complete")
	selected := selection.CloneAuth()
	if selected == nil || selected.ID != "ordinary" || selection.DispatchCount() != 2 {
		t.Fatalf("selection = %#v count=%d, want ordinary at count 2", selected, selection.DispatchCount())
	}
}
