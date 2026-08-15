package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAccountGroupManagementLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("api-keys:\n  - key-a\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}

	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"key-a"}}}
	store := &memoryAuthStore{items: make(map[string]*coreauth.Auth)}
	manager := coreauth.NewManager(store, nil, nil)
	handler := NewHandler(cfg, configPath, manager)
	handler.SetConfigReloadHook(func(_ context.Context, next *config.Config) {
		manager.SetConfig(next)
	})
	manager.SetConfig(cfg)

	engine := gin.New()
	engine.GET("/account-groups", handler.ListAccountGroups)
	engine.POST("/account-groups", handler.CreateAccountGroup)
	engine.DELETE("/account-groups/:id", handler.DeleteAccountGroup)
	engine.PUT("/account-groups/memberships", handler.PutAccountGroupMemberships)
	engine.PUT("/api-key-group-policies", handler.PutAPIKeyGroupPolicies)

	create := performAccountGroupRequest(t, engine, http.MethodPost, "/account-groups", `{
		"name":"Production",
		"description":"Primary accounts",
		"color":"#0ea5e9",
		"sort_order":10
	}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", create.Code, create.Body.String())
	}
	var createBody struct {
		Group config.AccountGroup `json:"group"`
	}
	if errDecode := json.Unmarshal(create.Body.Bytes(), &createBody); errDecode != nil {
		t.Fatal(errDecode)
	}
	groupID := createBody.Group.ID
	if groupID <= 0 {
		t.Fatalf("created group id = %d", groupID)
	}

	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID: "auth-a", Provider: "codex", Status: coreauth.StatusActive, Metadata: map[string]any{"type": "codex"},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}

	membership := performAccountGroupRequest(t, engine, http.MethodPut, "/account-groups/memberships", `{
		"name":"auth-a",
		"group_ids":[`+jsonNumber(groupID)+`]
	}`)
	if membership.Code != http.StatusOK {
		t.Fatalf("membership status = %d, body=%s", membership.Code, membership.Body.String())
	}

	policy := performAccountGroupRequest(t, engine, http.MethodPut, "/api-key-group-policies", `{
		"api_key":"key-a",
		"allowed_group_ids":[`+jsonNumber(groupID)+`]
	}`)
	if policy.Code != http.StatusOK {
		t.Fatalf("policy status = %d, body=%s", policy.Code, policy.Body.String())
	}

	list := performAccountGroupRequest(t, engine, http.MethodGet, "/account-groups", "")
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", list.Code, list.Body.String())
	}
	var listBody struct {
		Groups []struct {
			ID          int64 `json:"id"`
			MemberCount int   `json:"member_count"`
			APIKeyCount int   `json:"api_key_count"`
		} `json:"groups"`
	}
	if errDecode := json.Unmarshal(list.Body.Bytes(), &listBody); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(listBody.Groups) != 1 || listBody.Groups[0].MemberCount != 1 || listBody.Groups[0].APIKeyCount != 1 {
		t.Fatalf("group usage = %#v", listBody.Groups)
	}

	blocked := performAccountGroupRequest(t, engine, http.MethodDelete, "/account-groups/"+jsonNumber(groupID), "")
	if blocked.Code != http.StatusConflict {
		t.Fatalf("non-force delete status = %d, body=%s", blocked.Code, blocked.Body.String())
	}

	deleted := performAccountGroupRequest(t, engine, http.MethodDelete, "/account-groups/"+jsonNumber(groupID)+"?force=true", "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("force delete status = %d, body=%s", deleted.Code, deleted.Body.String())
	}
	auth, found := manager.GetByID("auth-a")
	if !found || len(auth.GroupIDs()) != 0 {
		t.Fatalf("auth groups after delete = %v, found=%v", auth.GroupIDs(), found)
	}
	if len(cfg.APIKeyGroupPolicies) != 1 || len(cfg.APIKeyGroupPolicies[0].AllowedGroupIDs) != 1 || cfg.APIKeyGroupPolicies[0].AllowedGroupIDs[0] != groupID {
		t.Fatalf("policy after force delete = %#v; sole stale id must remain restricted", cfg.APIKeyGroupPolicies)
	}

	replacement := performAccountGroupRequest(t, engine, http.MethodPost, "/account-groups", `{
		"name":"Replacement"
	}`)
	if replacement.Code != http.StatusCreated {
		t.Fatalf("replacement create status = %d, body=%s", replacement.Code, replacement.Body.String())
	}
	var replacementBody struct {
		Group config.AccountGroup `json:"group"`
	}
	if errDecode := json.Unmarshal(replacement.Body.Bytes(), &replacementBody); errDecode != nil {
		t.Fatal(errDecode)
	}
	if replacementBody.Group.ID == groupID {
		t.Fatalf("replacement group reused reserved stale policy id %d", groupID)
	}
}

func TestAccountGroupMembershipPersistsConfigAuth(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte(`account-groups:
  - id: 7
    name: Production
codex-api-key:
  - api-key: upstream-key
    base-url: https://example.test
`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}

	cfg := &config.Config{
		SDKConfig: config.SDKConfig{AccountGroups: []config.AccountGroup{{ID: 7, Name: "Production"}}},
		CodexKey:  []config.CodexKey{{APIKey: "upstream-key", BaseURL: "https://example.test"}},
	}
	idGen := synthesizer.NewStableIDGenerator()
	authID, _ := idGen.Next("codex:apikey", "upstream-key", "https://example.test")
	manager := coreauth.NewManager(&memoryAuthStore{items: make(map[string]*coreauth.Auth)}, nil, nil)
	manager.SetConfig(cfg)
	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{
		ID:       authID,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeSource:   "config:codex[test]",
			coreauth.AttributeAPIKey:   "upstream-key",
			coreauth.AttributeAuthKind: coreauth.AuthKindAPIKey,
		},
		Metadata: map[string]any{},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}

	handler := NewHandler(cfg, configPath, manager)
	engine := gin.New()
	engine.GET("/auth-files", handler.ListAuthFiles)
	engine.PUT("/account-groups/memberships", handler.PutAccountGroupMemberships)
	engine.DELETE("/account-groups/:id", handler.DeleteAccountGroup)

	defaultList := performAccountGroupRequest(t, engine, http.MethodGet, "/auth-files", "")
	if defaultList.Code != http.StatusOK {
		t.Fatalf("default auth list status = %d, body=%s", defaultList.Code, defaultList.Body.String())
	}
	var defaultListBody struct {
		Files []map[string]any `json:"files"`
	}
	if errDecode := json.Unmarshal(defaultList.Body.Bytes(), &defaultListBody); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(defaultListBody.Files) != 0 {
		t.Fatalf("default auth list exposed config auths = %#v", defaultListBody.Files)
	}

	groupingList := performAccountGroupRequest(t, engine, http.MethodGet, "/auth-files?include_config=true", "")
	if groupingList.Code != http.StatusOK {
		t.Fatalf("grouping auth list status = %d, body=%s", groupingList.Code, groupingList.Body.String())
	}
	var groupingListBody struct {
		Files []struct {
			ID           string `json:"id"`
			Source       string `json:"source"`
			ConfigBacked bool   `json:"config_backed"`
		} `json:"files"`
	}
	if errDecode := json.Unmarshal(groupingList.Body.Bytes(), &groupingListBody); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(groupingListBody.Files) != 1 || groupingListBody.Files[0].ID != authID || groupingListBody.Files[0].Source != "config" || !groupingListBody.Files[0].ConfigBacked {
		t.Fatalf("grouping auth list = %#v", groupingListBody.Files)
	}

	response := performAccountGroupRequest(t, engine, http.MethodPut, "/account-groups/memberships", `{
		"name":"`+authID+`",
		"group_ids":[7]
	}`)
	if response.Code != http.StatusOK {
		t.Fatalf("membership status = %d, body=%s", response.Code, response.Body.String())
	}
	if got := cfg.CodexKey[0].GroupIDs; len(got) != 1 || got[0] != 7 {
		t.Fatalf("runtime config group ids = %v, want [7]", got)
	}
	updated, found := manager.GetByID(authID)
	if !found || len(updated.GroupIDs()) != 1 || updated.GroupIDs()[0] != 7 {
		t.Fatalf("runtime auth groups = %v, found=%v", updated.GroupIDs(), found)
	}
	reloaded, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	if got := reloaded.CodexKey[0].GroupIDs; len(got) != 1 || got[0] != 7 {
		t.Fatalf("reloaded config group ids = %v, want [7]", got)
	}
	auths, errSynthesize := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config: reloaded, IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil || len(auths) != 1 {
		t.Fatalf("synthesize reloaded config: auths=%d error=%v", len(auths), errSynthesize)
	}
	synthesizedGroups, okGroups := auths[0].Metadata["group_ids"].([]int64)
	if !okGroups || len(synthesizedGroups) != 1 || synthesizedGroups[0] != 7 {
		t.Fatalf("synthesized auth group ids = %#v, want [7]", auths[0].Metadata["group_ids"])
	}

	deleted := performAccountGroupRequest(t, engine, http.MethodDelete, "/account-groups/7?force=true", "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("force delete status = %d, body=%s", deleted.Code, deleted.Body.String())
	}
	if got := cfg.CodexKey[0].GroupIDs; len(got) != 0 {
		t.Fatalf("runtime config group ids after delete = %v, want empty", got)
	}
	reloadedAfterDelete, errReloadDelete := config.LoadConfig(configPath)
	if errReloadDelete != nil {
		t.Fatal(errReloadDelete)
	}
	if got := reloadedAfterDelete.CodexKey[0].GroupIDs; len(got) != 0 {
		t.Fatalf("reloaded config group ids after delete = %v, want empty", got)
	}
}

func performAccountGroupRequest(t *testing.T, engine *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	engine.ServeHTTP(recorder, request)
	return recorder
}

func jsonNumber(value int64) string {
	return strconv.FormatInt(value, 10)
}
