package management

import (
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func setConfigAuthAccountGroups(cfg *config.Config, auth *coreauth.Auth, groupIDs []int64) (bool, error) {
	if cfg == nil || auth == nil || auth.AuthSourceKind() != coreauth.AuthSourceConfig {
		return false, nil
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return false, fmt.Errorf("auth id is empty")
	}
	groupIDs = config.NormalizeAccountGroupIDs(groupIDs)
	idGen := synthesizer.NewStableIDGenerator()

	for index := range cfg.GeminiKey {
		entry := &cfg.GeminiKey[index]
		id, _ := idGen.Next("gemini:apikey", entry.APIKey, entry.BaseURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}
	for index := range cfg.InteractionsKey {
		entry := &cfg.InteractionsKey[index]
		id, _ := idGen.Next("gemini-interactions:apikey", entry.APIKey, entry.BaseURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}
	for index := range cfg.ClaudeKey {
		entry := &cfg.ClaudeKey[index]
		id, _ := idGen.Next("claude:apikey", entry.APIKey, entry.BaseURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}
	for index := range cfg.CodexKey {
		entry := &cfg.CodexKey[index]
		id, _ := idGen.Next("codex:apikey", entry.APIKey, entry.BaseURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}
	for index := range cfg.XAIKey {
		entry := &cfg.XAIKey[index]
		id, _ := idGen.Next("xai:apikey", entry.APIKey, entry.BaseURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}
	for providerIndex := range cfg.OpenAICompatibility {
		provider := &cfg.OpenAICompatibility[providerIndex]
		providerName := strings.ToLower(strings.TrimSpace(provider.Name))
		if providerName == "" {
			providerName = "openai-compatibility"
		}
		idKind := fmt.Sprintf("openai-compatibility:%s", providerName)
		baseURL := strings.TrimSpace(provider.BaseURL)
		if len(provider.APIKeyEntries) == 0 {
			id, _ := idGen.Next(idKind, baseURL)
			if id == authID {
				provider.GroupIDs = append([]int64(nil), groupIDs...)
				return true, nil
			}
			continue
		}
		for keyIndex := range provider.APIKeyEntries {
			entry := &provider.APIKeyEntries[keyIndex]
			id, _ := idGen.Next(idKind, entry.APIKey, baseURL, entry.ProxyURL)
			if id == authID {
				entry.GroupIDs = append([]int64(nil), groupIDs...)
				return true, nil
			}
		}
	}
	for index := range cfg.VertexCompatAPIKey {
		entry := &cfg.VertexCompatAPIKey[index]
		id, _ := idGen.Next("vertex:apikey", entry.APIKey, entry.BaseURL, entry.ProxyURL)
		if id == authID {
			entry.GroupIDs = append([]int64(nil), groupIDs...)
			return true, nil
		}
	}

	return false, nil
}
