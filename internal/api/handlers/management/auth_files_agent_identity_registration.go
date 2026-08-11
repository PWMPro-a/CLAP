package management

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const maxAgentIdentityRegistrationBatch = 2000

type agentIdentityRegistrationRuntime interface {
	RegistrationStatus() codexauth.AgentIdentityRegistrationStatus
	SetRegistrationClient(*http.Client)
	RetryTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool)
}

type agentIdentityRebuildRuntime interface {
	RebuildTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool)
}

type agentIdentityRegistrationResult struct {
	Name         string                                    `json:"name"`
	Queued       bool                                      `json:"queued"`
	Registration codexauth.AgentIdentityRegistrationStatus `json:"registration"`
}

// ListAgentIdentityRegistrations returns only registration progress, avoiding
// repeated full auth-file payloads while the management page is polling.
func (h *Handler) ListAgentIdentityRegistrations(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	views := h.authManager.ListRuntimeViews()
	results := make([]agentIdentityRegistrationResult, 0, len(views))
	active := 0
	for _, auth := range views {
		runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
		if !ok || runtime == nil {
			continue
		}
		status := runtime.RegistrationStatus()
		if status.Active {
			active++
		}
		results = append(results, agentIdentityRegistrationResult{
			Name:         runtimeAuthViewDisplayName(auth),
			Registration: status,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"active":        active,
		"coordinator":   codexauth.AgentIdentityRecoveryStats(),
		"registrations": results,
	})
}

// ListAgentIdentityRecovery returns the complete management view used by the
// recovery console: current account states, pool pressure, and bounded history.
func (h *Handler) ListAgentIdentityRecovery(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	historyLimit := 200
	if raw := strings.TrimSpace(c.Query("history_limit")); raw != "" {
		if parsed, errParse := strconv.Atoi(raw); errParse == nil {
			historyLimit = parsed
		}
	}
	if historyLimit < 0 {
		historyLimit = 0
	} else if historyLimit > 2000 {
		historyLimit = 2000
	}

	results, summary := h.agentIdentityRegistrationSnapshot()
	configSnapshot := h.agentIdentityRecoveryConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"summary":       summary,
		"coordinator":   codexauth.AgentIdentityRecoveryStats(),
		"config":        configSnapshot,
		"registrations": results,
		"history":       codexauth.AgentIdentityRecoveryHistory(historyLimit),
	})
}

func (h *Handler) agentIdentityRegistrationSnapshot() ([]agentIdentityRegistrationResult, map[string]int) {
	results := make([]agentIdentityRegistrationResult, 0)
	summary := map[string]int{
		"total":               0,
		"active":              0,
		"ready":               0,
		"credentials_pending": 0,
		"queued":              0,
		"registering":         0,
		"retry_wait":          0,
		"runtime_deleted":     0,
		"failed":              0,
	}
	if h == nil || h.authManager == nil {
		return results, summary
	}
	for _, auth := range h.authManager.ListRuntimeViews() {
		runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
		if !ok || runtime == nil {
			continue
		}
		status := runtime.RegistrationStatus()
		summary["total"]++
		summary[status.State]++
		if status.Active {
			summary["active"]++
		}
		results = append(results, agentIdentityRegistrationResult{
			Name:         runtimeAuthViewDisplayName(auth),
			Registration: status,
		})
	}
	return results, summary
}

func (h *Handler) agentIdentityRecoveryConfigSnapshot() map[string]int {
	concurrency := 6
	historyLimit := 2000
	if h != nil {
		h.mu.Lock()
		if h.cfg != nil {
			settings := h.cfg.AgentIdentityRecovery
			settings.Normalize()
			concurrency = settings.Concurrency
			historyLimit = settings.HistoryLimit
		}
		h.mu.Unlock()
	}
	return map[string]int{
		"concurrency":   concurrency,
		"history_limit": historyLimit,
	}
}

// PutAgentIdentityRecoveryConfig persists and applies recovery pool settings.
func (h *Handler) PutAgentIdentityRecoveryConfig(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config unavailable"})
		return
	}
	var req struct {
		Concurrency  *int `json:"concurrency"`
		HistoryLimit *int `json:"history_limit"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil || (req.Concurrency == nil && req.HistoryLimit == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	h.mu.Lock()
	settings := h.cfg.AgentIdentityRecovery
	if req.Concurrency != nil {
		settings.Concurrency = *req.Concurrency
	}
	if req.HistoryLimit != nil {
		settings.HistoryLimit = *req.HistoryLimit
	}
	settings.Normalize()
	h.cfg.AgentIdentityRecovery = settings
	snapshot, saved := h.saveConfigAndSnapshotLocked(c)
	h.mu.Unlock()
	if !saved {
		return
	}
	stats := codexauth.ConfigureAgentIdentityRecovery(settings.Concurrency, settings.HistoryLimit)
	var requestContext context.Context
	if c.Request != nil {
		requestContext = c.Request.Context()
	}
	h.reloadConfigAfterManagementSaveAsync(requestContext, snapshot)
	c.JSON(http.StatusOK, gin.H{
		"status":      "ok",
		"config":      map[string]int{"concurrency": settings.Concurrency, "history_limit": settings.HistoryLimit},
		"coordinator": stats,
	})
}

func runtimeAuthViewDisplayName(auth coreauth.RuntimeAuthView) string {
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

// RegisterAgentIdentityTask retries one failed Agent Identity task registration.
func (h *Handler) RegisterAgentIdentityTask(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	result, statusCode, errMessage := h.retryAgentIdentityRegistration(name)
	if errMessage != "" {
		c.JSON(statusCode, gin.H{"error": errMessage})
		return
	}
	if result.Queued || result.Registration.Active {
		statusCode = http.StatusAccepted
	} else {
		statusCode = http.StatusOK
	}
	c.JSON(statusCode, result)
}

// RegisterAgentIdentityTasks retries selected Agent Identity registrations.
func (h *Handler) RegisterAgentIdentityTasks(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Names []string `json:"names"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	names := uniqueAgentIdentityRegistrationNames(req.Names)
	if len(names) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "names are required"})
		return
	}
	if len(names) > maxAgentIdentityRegistrationBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many auth files in one request"})
		return
	}

	results := make([]agentIdentityRegistrationResult, 0, len(names))
	failures := make([]gin.H, 0)
	queued := 0
	skipped := 0
	for _, name := range names {
		result, _, errMessage := h.retryAgentIdentityRegistration(name)
		if errMessage != "" {
			failures = append(failures, gin.H{"name": name, "error": errMessage})
			continue
		}
		if result.Queued {
			queued++
		} else if !result.Registration.Active {
			skipped++
		}
		results = append(results, result)
	}

	statusCode := http.StatusOK
	if queued > 0 {
		statusCode = http.StatusAccepted
	}
	c.JSON(statusCode, gin.H{
		"status":  "ok",
		"queued":  queued,
		"skipped": skipped,
		"results": results,
		"failed":  failures,
	})
}

// RebuildAgentIdentityTask invalidates the installed task and registers a new
// one, including a fresh probe for accounts marked runtime_deleted.
func (h *Handler) RebuildAgentIdentityTask(c *gin.Context) {
	h.handleAgentIdentityRecoveryAction(c, true)
}

// RebuildAgentIdentityTasks performs a bounded batch rebuild.
func (h *Handler) RebuildAgentIdentityTasks(c *gin.Context) {
	h.handleAgentIdentityRecoveryBatch(c, true)
}

func (h *Handler) handleAgentIdentityRecoveryAction(c *gin.Context, rebuild bool) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	result, statusCode, errMessage := h.runAgentIdentityRecoveryAction(req.Name, rebuild)
	if errMessage != "" {
		c.JSON(statusCode, gin.H{"error": errMessage})
		return
	}
	if result.Queued || result.Registration.Active {
		statusCode = http.StatusAccepted
	}
	c.JSON(statusCode, result)
}

func (h *Handler) handleAgentIdentityRecoveryBatch(c *gin.Context, rebuild bool) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Names []string `json:"names"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	names := uniqueAgentIdentityRegistrationNames(req.Names)
	if len(names) == 0 || len(names) > maxAgentIdentityRegistrationBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "names are required or batch is too large"})
		return
	}
	results := make([]agentIdentityRegistrationResult, 0, len(names))
	failures := make([]gin.H, 0)
	queued := 0
	skipped := 0
	for _, name := range names {
		result, _, errMessage := h.runAgentIdentityRecoveryAction(name, rebuild)
		if errMessage != "" {
			failures = append(failures, gin.H{"name": name, "error": errMessage})
			continue
		}
		if result.Queued {
			queued++
		} else {
			skipped++
		}
		results = append(results, result)
	}
	statusCode := http.StatusOK
	if queued > 0 {
		statusCode = http.StatusAccepted
	}
	c.JSON(statusCode, gin.H{
		"status":  "ok",
		"queued":  queued,
		"skipped": skipped,
		"results": results,
		"failed":  failures,
	})
}

func (h *Handler) runAgentIdentityRecoveryAction(name string, rebuild bool) (agentIdentityRegistrationResult, int, string) {
	if !rebuild {
		return h.retryAgentIdentityRegistration(name)
	}
	auth := h.findAuthForAgentIdentityRegistration(name)
	if auth == nil {
		return agentIdentityRegistrationResult{}, http.StatusNotFound, "auth file not found"
	}
	runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
	if !ok || runtime == nil {
		return agentIdentityRegistrationResult{}, http.StatusConflict, "auth file is not an agent identity account"
	}
	rebuilder, ok := auth.Runtime.(agentIdentityRebuildRuntime)
	if !ok || rebuilder == nil {
		return agentIdentityRegistrationResult{}, http.StatusConflict, "agent identity runtime does not support rebuild"
	}
	runtime.SetRegistrationClient(h.agentIdentityRegistrationClient(auth))
	status, queued := rebuilder.RebuildTaskRegistration()
	return agentIdentityRegistrationResult{
		Name:         authFileDisplayName(auth),
		Queued:       queued,
		Registration: status,
	}, http.StatusOK, ""
}

func configureAgentIdentityRecoveryFromConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	settings := cfg.AgentIdentityRecovery
	settings.Normalize()
	codexauth.ConfigureAgentIdentityRecovery(settings.Concurrency, settings.HistoryLimit)
}

func (h *Handler) retryAgentIdentityRegistration(name string) (agentIdentityRegistrationResult, int, string) {
	auth := h.findAuthForAgentIdentityRegistration(name)
	if auth == nil {
		return agentIdentityRegistrationResult{}, http.StatusNotFound, "auth file not found"
	}
	runtime, ok := auth.Runtime.(agentIdentityRegistrationRuntime)
	if !ok || runtime == nil {
		return agentIdentityRegistrationResult{}, http.StatusConflict, "auth file is not an agent identity account"
	}
	runtime.SetRegistrationClient(h.agentIdentityRegistrationClient(auth))
	status, queued := runtime.RetryTaskRegistration()
	return agentIdentityRegistrationResult{
		Name:         authFileDisplayName(auth),
		Queued:       queued,
		Registration: status,
	}, http.StatusOK, ""
}

func (h *Handler) agentIdentityRegistrationClient(auth *coreauth.Auth) *http.Client {
	client := &http.Client{}
	proxyURL := strings.TrimSpace(auth.ProxyURL)
	sourceIP := strings.TrimSpace(auth.SourceIP)
	if proxyURL != "" && sourceIP == "" && h != nil && h.cfg != nil {
		sourceIP = strings.TrimSpace(h.cfg.SourceIP)
	}
	if proxyURL == "" && sourceIP == "" && h != nil && h.cfg != nil {
		proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
		sourceIP = strings.TrimSpace(h.cfg.SourceIP)
	}
	if proxyURL != "" || sourceIP != "" {
		if transport := buildProxyTransport(proxyURL, sourceIP); transport != nil {
			client.Transport = transport
		}
	}
	return client
}

func (h *Handler) findAuthForAgentIdentityRegistration(name string) *coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth
	}
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(auth.FileName), name) ||
			strings.EqualFold(strings.TrimSpace(auth.ID), name) {
			return auth
		}
	}
	return nil
}

func authFileDisplayName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return strings.TrimSpace(auth.ID)
}

func uniqueAgentIdentityRegistrationNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, name)
	}
	return result
}
