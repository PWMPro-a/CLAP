package management

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/cacheaffinity"
)

// GetCodexCacheAffinityStats returns irreversible coordinator diagnostics.
func (h *Handler) GetCodexCacheAffinityStats(c *gin.Context) {
	h.mu.Lock()
	cfg := h.cfg
	h.mu.Unlock()
	c.JSON(200, gin.H{
		"settings": cacheaffinity.Settings(cfg),
		"stats":    cacheaffinity.Snapshot(),
	})
}
