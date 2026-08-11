package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type managementTestAgentRegistrationRuntime struct {
	status   codexauth.AgentIdentityRegistrationStatus
	retries  int
	rebuilds int
}

func (r *managementTestAgentRegistrationRuntime) SetRegistrationClient(*http.Client) {}

func (r *managementTestAgentRegistrationRuntime) RegistrationStatus() codexauth.AgentIdentityRegistrationStatus {
	return r.status
}

func (r *managementTestAgentRegistrationRuntime) RetryTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool) {
	r.retries++
	r.status = codexauth.AgentIdentityRegistrationStatus{
		State:  codexauth.AgentIdentityRegistrationQueued,
		Active: true,
	}
	return r.status, true
}

func (r *managementTestAgentRegistrationRuntime) RebuildTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool) {
	r.rebuilds++
	r.status = codexauth.AgentIdentityRegistrationStatus{
		State:   codexauth.AgentIdentityRegistrationQueued,
		Active:  true,
		Trigger: "manual_rebuild",
	}
	return r.status, true
}

func managementTestAgentIdentityKey(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestWriteAuthFileExpandsAgentIdentityBundle(t *testing.T) {
	authDir := t.TempDir()
	key := managementTestAgentIdentityKey(t)
	payload, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{
			{"name": "one", "credentials": map[string]any{
				"auth_mode": "agentIdentity", "account_id": "shared-account", "agent_runtime_id": "runtime-one", "agent_private_key": key, "task_id": "task-one",
			}},
			{"name": "two", "credentials": map[string]any{
				"auth_mode": "agentIdentity", "account_id": "shared-account", "agent_runtime_id": "runtime-two", "agent_private_key": key, "task_id": "task-two",
			}},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	handler := &Handler{cfg: &config.Config{AuthDir: authDir}}
	if err := handler.writeAuthFile(context.Background(), "accounts-agentIdentity.json", payload); err != nil {
		t.Fatalf("writeAuthFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "accounts-agentIdentity.json")); !os.IsNotExist(err) {
		t.Fatalf("source bundle should not remain as an unknown auth file")
	}
	entries, err := os.ReadDir(authDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("auth files = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "codex-agent-") {
			t.Fatalf("unexpected generated filename %q", entry.Name())
		}
		data, errRead := os.ReadFile(filepath.Join(authDir, entry.Name()))
		if errRead != nil {
			t.Fatalf("ReadFile: %v", errRead)
		}
		auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{
			Config:  handler.cfg,
			AuthDir: authDir,
		}, filepath.Join(authDir, entry.Name()), data)
		if errSynthesize != nil {
			t.Fatalf("SynthesizeAuthFile(%q): %v", entry.Name(), errSynthesize)
		}
		if len(auths) != 1 || auths[0].Runtime == nil {
			t.Fatalf("generated file %q is not a runnable auth", entry.Name())
		}
	}
}

func TestWriteAuthFileAcceptsPendingAgentIdentityRecovery(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	handler := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
	}
	payload := []byte(`{"type":"codex","auth_mode":"agentIdentity","account_id":"account-placeholder","email":"pending@example.com"}`)
	if err := handler.writeAuthFile(context.Background(), "pending.json", payload); err != nil {
		t.Fatalf("writeAuthFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "pending.json")); err != nil {
		t.Fatalf("pending auth file was not persisted: %v", err)
	}
	auth, ok := manager.GetByID("pending.json")
	if !ok || auth == nil {
		t.Fatal("pending auth was not registered")
	}
	runtime, ok := auth.Runtime.(*codexauth.PendingAgentIdentity)
	if !ok || runtime == nil {
		t.Fatalf("runtime type = %T, want pending agent identity", auth.Runtime)
	}
	if runtime.RegistrationStatus().State != codexauth.AgentIdentityRegistrationCredentialsPending || !auth.Unavailable {
		t.Fatalf("pending auth status=%+v unavailable=%v", runtime.RegistrationStatus(), auth.Unavailable)
	}

	key := managementTestAgentIdentityKey(t)
	recoveredPayload, err := json.Marshal(map[string]any{
		"type":              "codex",
		"auth_mode":         "agentIdentity",
		"account_id":        "account-placeholder",
		"email":             "pending@example.com",
		"agent_runtime_id":  "runtime-recovered",
		"agent_private_key": key,
		"task_id":           "task-recovered",
	})
	if err != nil {
		t.Fatalf("Marshal recovered payload: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "pending.json", recoveredPayload); err != nil {
		t.Fatalf("write recovered auth file: %v", err)
	}
	recovered, ok := manager.GetByID("pending.json")
	if !ok || recovered == nil {
		t.Fatal("recovered auth was not registered")
	}
	if _, pending := recovered.Runtime.(*codexauth.PendingAgentIdentity); pending || recovered.Unavailable {
		t.Fatalf("recovered auth runtime=%T unavailable=%v", recovered.Runtime, recovered.Unavailable)
	}
	registration, ok := recovered.Runtime.(interface {
		RegistrationStatus() codexauth.AgentIdentityRegistrationStatus
	})
	if !ok {
		t.Fatalf("recovered runtime %T does not expose registration status", recovered.Runtime)
	}
	if status := registration.RegistrationStatus(); status.State != codexauth.AgentIdentityRegistrationReady {
		t.Fatalf("recovered registration status=%+v", status)
	}
}

func TestWriteAuthFileDoesNotDowngradeRecoveredAgentIdentity(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	handler := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
	}
	key := managementTestAgentIdentityKey(t)
	healthyPayload, err := json.Marshal(map[string]any{
		"type":              "codex",
		"auth_mode":         "agentIdentity",
		"account_id":        "account-stable",
		"email":             "stable@example.com",
		"agent_runtime_id":  "runtime-stable",
		"agent_private_key": key,
		"task_id":           "task-stable",
	})
	if err != nil {
		t.Fatalf("Marshal healthy payload: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "stable.json", healthyPayload); err != nil {
		t.Fatalf("write healthy auth file: %v", err)
	}

	legacyPayload := []byte(`{"type":"codex","auth_mode":"agentIdentity","account_id":"account-stable","email":"stable@example.com"}`)
	if err := handler.writeAuthFile(context.Background(), "stable.json", legacyPayload); err != nil {
		t.Fatalf("re-import legacy auth file: %v", err)
	}
	auth, ok := manager.GetByID("stable.json")
	if !ok || auth == nil || auth.Unavailable {
		t.Fatalf("auth was downgraded after legacy import: %+v", auth)
	}
	if _, pending := auth.Runtime.(*codexauth.PendingAgentIdentity); pending {
		t.Fatal("healthy auth was replaced by a pending runtime")
	}
	persisted, err := os.ReadFile(filepath.Join(authDir, "stable.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(persisted, []byte("runtime-stable")) || !bytes.Contains(persisted, []byte("task-stable")) {
		t.Fatal("legacy import removed recovered signing credentials")
	}
}

func TestWriteAuthFileBundleReusesPendingRecoveryFile(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	handler := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
	}
	pendingBundle := []byte(`{"accounts":[{"name":"bundle@example.com","credentials":{"auth_mode":"agentIdentity","account_id":"account-bundle","email":"bundle@example.com"}}]}`)
	if err := handler.writeAuthFile(context.Background(), "pending-bundle.json", pendingBundle); err != nil {
		t.Fatalf("write pending bundle: %v", err)
	}
	entries, err := os.ReadDir(authDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("pending bundle files=%d err=%v", len(entries), err)
	}
	pendingName := entries[0].Name()

	key := managementTestAgentIdentityKey(t)
	recoveredBundle, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{{
			"name": "bundle@example.com",
			"credentials": map[string]any{
				"auth_mode":         "agentIdentity",
				"account_id":        "account-bundle",
				"email":             "bundle@example.com",
				"agent_runtime_id":  "runtime-bundle",
				"agent_private_key": key,
				"task_id":           "task-bundle",
			},
		}},
	})
	if err != nil {
		t.Fatalf("Marshal recovered bundle: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "recovered-bundle.json", recoveredBundle); err != nil {
		t.Fatalf("write recovered bundle: %v", err)
	}
	entries, err = os.ReadDir(authDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != pendingName {
		t.Fatalf("recovered bundle files=%v err=%v", entries, err)
	}
	auth, ok := manager.GetByID(pendingName)
	if !ok || auth == nil || auth.Unavailable {
		t.Fatalf("bundle auth did not recover in place: %+v", auth)
	}
	if _, pending := auth.Runtime.(*codexauth.PendingAgentIdentity); pending {
		t.Fatal("bundle auth remained pending after complete re-import")
	}
}

func TestWriteAuthFileBundleReplacesChangedRuntimeByUserIdentity(t *testing.T) {
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	handler := &Handler{
		cfg:         &config.Config{AuthDir: authDir},
		authManager: manager,
	}
	oldKey := managementTestAgentIdentityKey(t)
	oldBundle, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{{
			"name": "member@example.com",
			"credentials": map[string]any{
				"auth_mode":          "agentIdentity",
				"account_id":         "shared-team",
				"chatgpt_account_id": "shared-team",
				"chatgpt_user_id":    "member-user",
				"email":              "member@example.com",
				"agent_runtime_id":   "runtime-old",
				"agent_private_key":  oldKey,
				"task_id":            "task-old",
			},
		}},
	})
	if err != nil {
		t.Fatalf("Marshal old bundle: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "old.json", oldBundle); err != nil {
		t.Fatalf("write old bundle: %v", err)
	}
	entries, err := os.ReadDir(authDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("old bundle files=%d err=%v", len(entries), err)
	}
	originalName := entries[0].Name()

	newKey := managementTestAgentIdentityKey(t)
	newBundle, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{{
			"name": "member@example.com",
			"credentials": map[string]any{
				"auth_mode":          "agentIdentity",
				"account_id":         "shared-team",
				"chatgpt_account_id": "shared-team",
				"chatgpt_user_id":    "member-user",
				"email":              "member@example.com",
				"agent_runtime_id":   "runtime-new",
				"agent_private_key":  newKey,
				"task_id":            "task-new",
			},
		}},
	})
	if err != nil {
		t.Fatalf("Marshal new bundle: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "new.json", newBundle); err != nil {
		t.Fatalf("write new bundle: %v", err)
	}
	entries, err = os.ReadDir(authDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != originalName {
		t.Fatalf("updated bundle files=%v err=%v", entries, err)
	}
	persisted, err := os.ReadFile(filepath.Join(authDir, originalName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(persisted, []byte("runtime-new")) ||
		!bytes.Contains(persisted, []byte("task-new")) ||
		bytes.Contains(persisted, []byte("runtime-old")) {
		t.Fatal("changed runtime was not replaced in place")
	}
}

func TestWriteAuthFileBundleDoesNotMergeSharedTeamMembers(t *testing.T) {
	authDir := t.TempDir()
	handler := &Handler{cfg: &config.Config{AuthDir: authDir}}
	key := managementTestAgentIdentityKey(t)
	writeMember := func(name, userID, runtimeID string) {
		t.Helper()
		bundle, err := json.Marshal(map[string]any{
			"accounts": []map[string]any{{
				"name": name,
				"credentials": map[string]any{
					"auth_mode":          "agentIdentity",
					"account_id":         "shared-team",
					"chatgpt_account_id": "shared-team",
					"chatgpt_user_id":    userID,
					"email":              name,
					"agent_runtime_id":   runtimeID,
					"agent_private_key":  key,
					"task_id":            "task-" + runtimeID,
				},
			}},
		})
		if err != nil {
			t.Fatalf("Marshal member: %v", err)
		}
		if err := handler.writeAuthFile(context.Background(), name+".json", bundle); err != nil {
			t.Fatalf("write member: %v", err)
		}
	}

	writeMember("first@example.com", "user-first", "runtime-first")
	writeMember("second@example.com", "user-second", "runtime-second")
	entries, err := os.ReadDir(authDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("shared team files=%d err=%v", len(entries), err)
	}
}

func TestPendingAgentIdentityCannotInheritAnotherTeamMemberCredentials(t *testing.T) {
	authDir := t.TempDir()
	handler := &Handler{cfg: &config.Config{AuthDir: authDir}}
	key := managementTestAgentIdentityKey(t)
	healthyPayload, err := json.Marshal(map[string]any{
		"type":               "codex",
		"auth_mode":          "agentIdentity",
		"account_id":         "shared-team",
		"chatgpt_account_id": "shared-team",
		"chatgpt_user_id":    "user-first",
		"email":              "first@example.com",
		"agent_runtime_id":   "runtime-first",
		"agent_private_key":  key,
		"task_id":            "task-first",
	})
	if err != nil {
		t.Fatalf("Marshal healthy payload: %v", err)
	}
	if err := handler.writeAuthFile(context.Background(), "shared.json", healthyPayload); err != nil {
		t.Fatalf("write healthy payload: %v", err)
	}
	pendingPayload := []byte(`{"type":"codex","auth_mode":"agentIdentity","account_id":"shared-team","chatgpt_account_id":"shared-team","chatgpt_user_id":"user-second","email":"second@example.com"}`)
	if err := handler.writeAuthFile(context.Background(), "shared.json", pendingPayload); err != nil {
		t.Fatalf("write pending payload: %v", err)
	}
	persisted, err := os.ReadFile(filepath.Join(authDir, "shared.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(persisted, []byte("runtime-first")) || bytes.Contains(persisted, []byte("task-first")) {
		t.Fatal("pending account inherited another team member's signing credentials")
	}
}

func TestListAuthFilesIncludesAgentIdentityRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authDir := t.TempDir()
	path := filepath.Join(authDir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:     codexauth.AgentIdentityRegistrationRuntimeDeleted,
		ErrorCode: "runtime_deleted",
		Error:     "Agent runtime has been deleted.",
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": path,
		},
		Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)

	handler.ListAuthFiles(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"state":"runtime_deleted"`) ||
		strings.Contains(recorder.Body.String(), "runtime-secret") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestRegisterAgentIdentityTaskQueuesRetry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:    codexauth.AgentIdentityRegistrationFailed,
		CanRetry: true,
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/v0/management/auth-files/agent-identity/register",
		bytes.NewBufferString(`{"name":"agent.json"}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler.RegisterAgentIdentityTask(ctx)

	if recorder.Code != http.StatusAccepted || runtime.retries != 1 {
		t.Fatalf("status=%d retries=%d body=%s", recorder.Code, runtime.retries, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"state":"queued"`) {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestListAgentIdentityRegistrationsReturnsLightweightProgress(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:  codexauth.AgentIdentityRegistrationRegistering,
		Active: true,
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
		Metadata: map[string]any{"agent_private_key": "must-not-leak"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/agent-identity/registrations", nil)

	handler.ListAgentIdentityRegistrations(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"active":1`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "must-not-leak") {
		t.Fatalf("registration progress leaked auth metadata: %s", recorder.Body.String())
	}
}

func TestListAgentIdentityRecoveryReturnsSummaryAndCoordinator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:    codexauth.AgentIdentityRegistrationFailed,
		CanRetry: true,
		Trigger:  "upstream_invalid_task",
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
		Metadata: map[string]any{"agent_private_key": "must-not-leak"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/agent-identity/recovery", nil)

	handler.ListAgentIdentityRecovery(ctx)

	if recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"failed":1`) ||
		!strings.Contains(recorder.Body.String(), `"concurrency":6`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "must-not-leak") {
		t.Fatalf("recovery response leaked auth metadata: %s", recorder.Body.String())
	}
}

func TestPutAgentIdentityRecoveryConfigPersistsAndApplies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	defer codexauth.ConfigureAgentIdentityRecovery(
		config.DefaultAgentIdentityRecoveryConcurrency,
		config.DefaultAgentIdentityRecoveryHistory,
	)
	handler := NewHandler(&config.Config{}, writeTestConfigFile(t), coreauth.NewManager(nil, nil, nil))
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPut,
		"/v0/management/auth-files/agent-identity/recovery/config",
		bytes.NewBufferString(`{"concurrency":9,"history_limit":123}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler.PutAgentIdentityRecoveryConfig(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if handler.cfg.AgentIdentityRecovery.Concurrency != 9 || handler.cfg.AgentIdentityRecovery.HistoryLimit != 123 {
		t.Fatalf("saved config = %+v", handler.cfg.AgentIdentityRecovery)
	}
	stats := codexauth.AgentIdentityRecoveryStats()
	if stats.Concurrency != 9 || stats.HistoryLimit != 123 {
		t.Fatalf("runtime recovery config = %+v", stats)
	}
}

func TestRebuildAgentIdentityTaskQueuesForcedRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State: codexauth.AgentIdentityRegistrationRuntimeDeleted,
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/v0/management/auth-files/agent-identity/rebuild",
		bytes.NewBufferString(`{"name":"agent.json"}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler.RebuildAgentIdentityTask(ctx)

	if recorder.Code != http.StatusAccepted || runtime.rebuilds != 1 ||
		!strings.Contains(recorder.Body.String(), `"trigger":"manual_rebuild"`) {
		t.Fatalf("status=%d rebuilds=%d body=%s", recorder.Code, runtime.rebuilds, recorder.Body.String())
	}
}
