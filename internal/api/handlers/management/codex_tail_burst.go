package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// PutCodexTailBurstQuota stores an asynchronously collected Codex usage-window
// snapshot. The request path remains fully in memory after this update.
func (h *Handler) PutCodexTailBurstQuota(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		Name       string     `json:"name"`
		AuthIndex  string     `json:"auth_index"`
		Model      string     `json:"model"`
		UsedRatio  *float64   `json:"used_ratio"`
		Window     string     `json:"window"`
		SampledAt  *time.Time `json:"sampled_at"`
		ExpiresAt  *time.Time `json:"expires_at"`
		Generation uint64     `json:"generation"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil || req.UsedRatio == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "used_ratio is required"})
		return
	}
	target, ok := h.lookupAuthFile(strings.TrimSpace(req.Name), strings.TrimSpace(req.AuthIndex))
	if !ok || target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(target.Provider), "codex") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth file is not a Codex credential"})
		return
	}
	snapshot := coreauth.CodexQuotaSnapshot{
		UsedRatio:  *req.UsedRatio,
		Window:     strings.TrimSpace(req.Window),
		Generation: req.Generation,
	}
	if req.SampledAt != nil {
		snapshot.SampledAt = req.SampledAt.UTC()
	}
	if req.ExpiresAt != nil {
		snapshot.ExpiresAt = req.ExpiresAt.UTC()
	}
	updated, accepted, errUpdate := h.authManager.UpdateCodexQuotaSnapshot(target.ID, strings.TrimSpace(req.Model), snapshot)
	if errUpdate != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errUpdate.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"accepted":   accepted,
		"auth_index": lockedAuthIndex(target),
		"model":      strings.TrimSpace(req.Model),
		"snapshot":   updated,
	})
}
