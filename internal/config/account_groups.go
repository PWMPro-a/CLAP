package config

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const (
	MaxAccountGroups         = 64
	DefaultAccountGroupColor = "#14b8a6"
)

// AccountGroup describes an operator-managed credential group.
type AccountGroup struct {
	ID          int64  `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Color       string `yaml:"color,omitempty" json:"color,omitempty"`
	SortOrder   int    `yaml:"sort-order,omitempty" json:"sort_order"`
}

// APIKeyGroupPolicy restricts one downstream API key hash to selected account groups.
// An absent policy means unrestricted access. Empty policies are normalized away.
type APIKeyGroupPolicy struct {
	APIKeyHash      string  `yaml:"api-key-hash" json:"api_key_hash"`
	AllowedGroupIDs []int64 `yaml:"allowed-group-ids" json:"allowed_group_ids"`
}

// HashAPIKeyForGroupPolicy returns the stable hash used by API key group policies.
func HashAPIKeyForGroupPolicy(apiKey string) string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// NormalizeAccountGroups sanitizes groups and API key policies after config parsing.
func (cfg *Config) NormalizeAccountGroups() {
	if cfg == nil {
		return
	}

	seenIDs := make(map[int64]struct{}, len(cfg.AccountGroups))
	seenNames := make(map[string]struct{}, len(cfg.AccountGroups))
	maxID := int64(0)
	for _, group := range cfg.AccountGroups {
		if group.ID > maxID {
			maxID = group.ID
		}
	}
	for _, policy := range cfg.APIKeyGroupPolicies {
		for _, groupID := range policy.AllowedGroupIDs {
			if groupID > maxID {
				maxID = groupID
			}
		}
	}

	capacity := len(cfg.AccountGroups)
	if capacity > MaxAccountGroups {
		capacity = MaxAccountGroups
	}
	groups := make([]AccountGroup, 0, capacity)
	for _, group := range cfg.AccountGroups {
		name := strings.TrimSpace(group.Name)
		if name == "" {
			continue
		}
		nameKey := strings.ToLower(name)
		if _, exists := seenNames[nameKey]; exists {
			continue
		}
		if group.ID <= 0 {
			maxID++
			group.ID = maxID
		} else if _, exists := seenIDs[group.ID]; exists {
			maxID++
			group.ID = maxID
		}
		seenIDs[group.ID] = struct{}{}
		seenNames[nameKey] = struct{}{}
		group.Name = name
		group.Description = strings.TrimSpace(group.Description)
		group.Color = normalizeAccountGroupColor(group.Color)
		groups = append(groups, group)
		if len(groups) >= MaxAccountGroups {
			break
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].SortOrder != groups[j].SortOrder {
			return groups[i].SortOrder < groups[j].SortOrder
		}
		return groups[i].ID < groups[j].ID
	})
	cfg.AccountGroups = groups
	cfg.normalizeCredentialAccountGroups()

	policyIndex := make(map[string]int, len(cfg.APIKeyGroupPolicies))
	policies := make([]APIKeyGroupPolicy, 0, len(cfg.APIKeyGroupPolicies))
	for _, policy := range cfg.APIKeyGroupPolicies {
		hash := strings.ToLower(strings.TrimSpace(policy.APIKeyHash))
		if !isSHA256Hex(hash) {
			continue
		}
		ids := NormalizeAccountGroupIDs(policy.AllowedGroupIDs)
		if len(ids) == 0 {
			continue
		}
		policy.APIKeyHash = hash
		policy.AllowedGroupIDs = ids
		if index, exists := policyIndex[hash]; exists {
			policies[index] = policy
			continue
		}
		policyIndex[hash] = len(policies)
		policies = append(policies, policy)
	}
	cfg.APIKeyGroupPolicies = policies
}

func (cfg *Config) normalizeCredentialAccountGroups() {
	for index := range cfg.GeminiKey {
		cfg.GeminiKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.GeminiKey[index].GroupIDs)
	}
	for index := range cfg.InteractionsKey {
		cfg.InteractionsKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.InteractionsKey[index].GroupIDs)
	}
	for index := range cfg.ClaudeKey {
		cfg.ClaudeKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.ClaudeKey[index].GroupIDs)
	}
	for index := range cfg.CodexKey {
		cfg.CodexKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.CodexKey[index].GroupIDs)
	}
	for index := range cfg.XAIKey {
		cfg.XAIKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.XAIKey[index].GroupIDs)
	}
	for providerIndex := range cfg.OpenAICompatibility {
		provider := &cfg.OpenAICompatibility[providerIndex]
		provider.GroupIDs = NormalizeAccountGroupIDs(provider.GroupIDs)
		for keyIndex := range provider.APIKeyEntries {
			provider.APIKeyEntries[keyIndex].GroupIDs = NormalizeAccountGroupIDs(provider.APIKeyEntries[keyIndex].GroupIDs)
		}
	}
	for index := range cfg.VertexCompatAPIKey {
		cfg.VertexCompatAPIKey[index].GroupIDs = NormalizeAccountGroupIDs(cfg.VertexCompatAPIKey[index].GroupIDs)
	}
}

// NormalizeAccountGroupIDs removes invalid and duplicate IDs and returns sorted output.
func NormalizeAccountGroupIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizeAccountGroupColor(color string) string {
	color = strings.TrimSpace(color)
	if len(color) != 7 || color[0] != '#' {
		return DefaultAccountGroupColor
	}
	for _, char := range color[1:] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return DefaultAccountGroupColor
		}
	}
	return strings.ToLower(color)
}

func isSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
