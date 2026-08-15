package management

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	maxAccountGroupNameRunes        = 80
	maxAccountGroupDescriptionRunes = 240
)

type accountGroupResponse struct {
	config.AccountGroup
	MemberCount int `json:"member_count"`
	APIKeyCount int `json:"api_key_count"`
}

func (h *Handler) ListAccountGroups(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	h.mu.Lock()
	groups := append([]config.AccountGroup(nil), h.cfg.AccountGroups...)
	policies := append([]config.APIKeyGroupPolicy(nil), h.cfg.APIKeyGroupPolicies...)
	apiKeys := append([]string(nil), h.cfg.APIKeys...)
	h.mu.Unlock()

	members := make(map[int64]int, len(groups))
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			for _, groupID := range auth.GroupIDs() {
				members[groupID]++
			}
		}
	}
	activeHashes := make(map[string]struct{}, len(apiKeys))
	for _, apiKey := range apiKeys {
		if hash := config.HashAPIKeyForGroupPolicy(apiKey); hash != "" {
			activeHashes[hash] = struct{}{}
		}
	}
	keyCounts := make(map[int64]int, len(groups))
	for _, policy := range policies {
		if _, active := activeHashes[policy.APIKeyHash]; !active {
			continue
		}
		for _, groupID := range policy.AllowedGroupIDs {
			keyCounts[groupID]++
		}
	}

	out := make([]accountGroupResponse, 0, len(groups))
	for _, group := range groups {
		out = append(out, accountGroupResponse{
			AccountGroup: group,
			MemberCount:  members[group.ID],
			APIKeyCount:  keyCounts[group.ID],
		})
	}
	c.JSON(http.StatusOK, gin.H{"groups": out})
}

type accountGroupCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	SortOrder   *int   `json:"sort_order"`
}

func (h *Handler) CreateAccountGroup(c *gin.Context) {
	var req accountGroupCreateRequest
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	group, errValidate := validateAccountGroupInput(req.Name, req.Description, req.Color)
	if errValidate != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errValidate.Error()})
		return
	}
	if req.SortOrder != nil {
		group.SortOrder = *req.SortOrder
	}

	h.mu.Lock()
	if len(h.cfg.AccountGroups) >= config.MaxAccountGroups {
		h.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": "account group limit reached"})
		return
	}
	if accountGroupNameExists(h.cfg.AccountGroups, group.Name, 0) {
		h.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "account group name already exists"})
		return
	}
	group.ID = nextAccountGroupID(h.cfg.AccountGroups, h.cfg.APIKeyGroupPolicies)
	h.cfg.AccountGroups = append(h.cfg.AccountGroups, group)
	h.cfg.NormalizeAccountGroups()
	snapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
	h.mu.Unlock()
	if !okSnapshot {
		return
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	c.JSON(http.StatusCreated, gin.H{"group": group})
}

type accountGroupUpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Color       *string `json:"color"`
	SortOrder   *int    `json:"sort_order"`
}

func (h *Handler) UpdateAccountGroup(c *gin.Context) {
	id, errID := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if errID != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account group id"})
		return
	}
	var req accountGroupUpdateRequest
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	h.mu.Lock()
	index := accountGroupIndex(h.cfg.AccountGroups, id)
	if index < 0 {
		h.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "account group not found"})
		return
	}
	group := h.cfg.AccountGroups[index]
	name := group.Name
	description := group.Description
	color := group.Color
	if req.Name != nil {
		name = *req.Name
	}
	if req.Description != nil {
		description = *req.Description
	}
	if req.Color != nil {
		color = *req.Color
	}
	validated, errValidate := validateAccountGroupInput(name, description, color)
	if errValidate != nil {
		h.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": errValidate.Error()})
		return
	}
	if accountGroupNameExists(h.cfg.AccountGroups, validated.Name, id) {
		h.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "account group name already exists"})
		return
	}
	validated.ID = id
	validated.SortOrder = group.SortOrder
	if req.SortOrder != nil {
		validated.SortOrder = *req.SortOrder
	}
	h.cfg.AccountGroups[index] = validated
	h.cfg.NormalizeAccountGroups()
	snapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
	h.mu.Unlock()
	if !okSnapshot {
		return
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	c.JSON(http.StatusOK, gin.H{"group": validated})
}

func (h *Handler) DeleteAccountGroup(c *gin.Context) {
	id, errID := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if errID != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account group id"})
		return
	}
	force := strings.EqualFold(strings.TrimSpace(c.Query("force")), "true")

	h.mu.Lock()
	if accountGroupIndex(h.cfg.AccountGroups, id) < 0 {
		h.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "account group not found"})
		return
	}
	h.mu.Unlock()

	members := h.authsInAccountGroup(id)
	if len(members) > 0 && !force {
		c.JSON(http.StatusConflict, gin.H{
			"error":        "account group still has members",
			"member_count": len(members),
		})
		return
	}
	if force {
		if errRemove := h.removeAccountGroupFromAuths(c.Request.Context(), members, id); errRemove != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errRemove.Error()})
			return
		}
	}

	h.mu.Lock()
	index := accountGroupIndex(h.cfg.AccountGroups, id)
	if index < 0 {
		h.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "account group not found"})
		return
	}
	h.cfg.AccountGroups = append(h.cfg.AccountGroups[:index], h.cfg.AccountGroups[index+1:]...)
	for policyIndex := range h.cfg.APIKeyGroupPolicies {
		ids := h.cfg.APIKeyGroupPolicies[policyIndex].AllowedGroupIDs
		if len(ids) <= 1 {
			continue
		}
		h.cfg.APIKeyGroupPolicies[policyIndex].AllowedGroupIDs = removeAccountGroupID(ids, id)
	}
	h.cfg.NormalizeAccountGroups()
	snapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
	h.mu.Unlock()
	if !okSnapshot {
		return
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type accountGroupMembershipUpdate struct {
	Name      string  `json:"name"`
	AuthIndex string  `json:"auth_index"`
	GroupIDs  []int64 `json:"group_ids"`
}

type accountGroupMembershipRequest struct {
	Updates   []accountGroupMembershipUpdate `json:"updates"`
	Name      string                         `json:"name"`
	AuthIndex string                         `json:"auth_index"`
	GroupIDs  []int64                        `json:"group_ids"`
}

func (h *Handler) PutAccountGroupMemberships(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req accountGroupMembershipRequest
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	updates := req.Updates
	if len(updates) == 0 && (strings.TrimSpace(req.Name) != "" || strings.TrimSpace(req.AuthIndex) != "") {
		updates = []accountGroupMembershipUpdate{{Name: req.Name, AuthIndex: req.AuthIndex, GroupIDs: req.GroupIDs}}
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "membership updates are required"})
		return
	}

	h.mu.Lock()
	known := knownAccountGroupIDs(h.cfg.AccountGroups)
	h.mu.Unlock()
	targets := make([]struct {
		auth     *coreauth.Auth
		groupIDs []int64
	}, 0, len(updates))
	seenAuths := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		ids := config.NormalizeAccountGroupIDs(update.GroupIDs)
		if missing := missingAccountGroupIDs(ids, known); len(missing) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown account group ids: %v", missing)})
			return
		}
		auth, found := h.lookupAuthFile(strings.TrimSpace(update.Name), strings.TrimSpace(update.AuthIndex))
		if !found || auth == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
			return
		}
		if coreauth.IsPluginVirtualAuth(auth) {
			c.JSON(http.StatusConflict, gin.H{"error": errPluginVirtualAuth.Error()})
			return
		}
		if _, duplicate := seenAuths[auth.ID]; duplicate {
			continue
		}
		seenAuths[auth.ID] = struct{}{}
		targets = append(targets, struct {
			auth     *coreauth.Auth
			groupIDs []int64
		}{auth: auth, groupIDs: ids})
	}

	configChanged := false
	h.mu.Lock()
	for _, target := range targets {
		if target.auth.AuthSourceKind() != coreauth.AuthSourceConfig {
			continue
		}
		handled, errConfig := setConfigAuthAccountGroups(h.cfg, target.auth, target.groupIDs)
		if errConfig != nil {
			h.mu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update config auth %s: %v", target.auth.ID, errConfig)})
			return
		}
		if !handled {
			h.mu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("config auth %s was not found", target.auth.ID)})
			return
		}
		configChanged = true
	}
	var configSnapshot configReloadSnapshot
	if configChanged {
		var okSnapshot bool
		configSnapshot, okSnapshot = h.saveConfigAndSnapshotLocked(c)
		if !okSnapshot {
			h.mu.Unlock()
			return
		}
	}
	h.mu.Unlock()

	for _, target := range targets {
		if target.auth.Metadata == nil {
			target.auth.Metadata = make(map[string]any)
		}
		if len(target.groupIDs) == 0 {
			delete(target.auth.Metadata, "group_ids")
		} else {
			target.auth.Metadata["group_ids"] = append([]int64(nil), target.groupIDs...)
		}
		if _, errUpdate := h.authManager.Update(c.Request.Context(), target.auth); errUpdate != nil {
			if configChanged {
				h.reloadConfigAfterManagementSave(c.Request.Context(), configSnapshot)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth %s: %v", target.auth.ID, errUpdate)})
			return
		}
	}
	if configChanged {
		h.reloadConfigAfterManagementSave(c.Request.Context(), configSnapshot)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "updated": len(targets)})
}

type apiKeyGroupPolicyRequest struct {
	APIKey          string  `json:"api_key"`
	APIKeyHash      string  `json:"api_key_hash"`
	AllowedGroupIDs []int64 `json:"allowed_group_ids"`
}

type apiKeyGroupPoliciesRequest struct {
	Items []apiKeyGroupPolicyRequest `json:"items"`
}

func (h *Handler) GetAPIKeyGroupPolicies(c *gin.Context) {
	h.mu.Lock()
	policies := append([]config.APIKeyGroupPolicy(nil), h.cfg.APIKeyGroupPolicies...)
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (h *Handler) PutAPIKeyGroupPolicies(c *gin.Context) {
	data, errRead := c.GetRawData()
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	var batch apiKeyGroupPoliciesRequest
	if errBatch := json.Unmarshal(data, &batch); errBatch != nil || len(batch.Items) == 0 {
		var single apiKeyGroupPolicyRequest
		if errSingle := json.Unmarshal(data, &single); errSingle != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		batch.Items = []apiKeyGroupPolicyRequest{single}
	}

	h.mu.Lock()
	known := knownAccountGroupIDs(h.cfg.AccountGroups)
	policies := append([]config.APIKeyGroupPolicy(nil), h.cfg.APIKeyGroupPolicies...)
	for _, item := range batch.Items {
		hash := strings.ToLower(strings.TrimSpace(item.APIKeyHash))
		if hash == "" {
			hash = config.HashAPIKeyForGroupPolicy(item.APIKey)
		}
		if !validAPIKeyGroupPolicyHash(hash) {
			h.mu.Unlock()
			c.JSON(http.StatusBadRequest, gin.H{"error": "api_key or api_key_hash is required"})
			return
		}
		ids := config.NormalizeAccountGroupIDs(item.AllowedGroupIDs)
		if missing := missingAccountGroupIDs(ids, known); len(missing) > 0 {
			h.mu.Unlock()
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown account group ids: %v", missing)})
			return
		}
		policies = upsertAPIKeyGroupPolicy(policies, hash, ids)
	}
	h.cfg.APIKeyGroupPolicies = policies
	h.cfg.NormalizeAccountGroups()
	snapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
	responsePolicies := append([]config.APIKeyGroupPolicy(nil), h.cfg.APIKeyGroupPolicies...)
	h.mu.Unlock()
	if !okSnapshot {
		return
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "policies": responsePolicies})
}

func (h *Handler) DeleteAPIKeyGroupPolicy(c *gin.Context) {
	hash := strings.ToLower(strings.TrimSpace(c.Query("api_key_hash")))
	if hash == "" {
		hash = config.HashAPIKeyForGroupPolicy(c.Query("api_key"))
	}
	if !validAPIKeyGroupPolicyHash(hash) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "api_key or api_key_hash is required"})
		return
	}
	h.mu.Lock()
	h.cfg.APIKeyGroupPolicies = upsertAPIKeyGroupPolicy(h.cfg.APIKeyGroupPolicies, hash, nil)
	snapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
	h.mu.Unlock()
	if !okSnapshot {
		return
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func validateAccountGroupInput(name, description, color string) (config.AccountGroup, error) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	color = strings.TrimSpace(color)
	if name == "" {
		return config.AccountGroup{}, fmt.Errorf("account group name is required")
	}
	if utf8.RuneCountInString(name) > maxAccountGroupNameRunes {
		return config.AccountGroup{}, fmt.Errorf("account group name exceeds %d characters", maxAccountGroupNameRunes)
	}
	if utf8.RuneCountInString(description) > maxAccountGroupDescriptionRunes {
		return config.AccountGroup{}, fmt.Errorf("account group description exceeds %d characters", maxAccountGroupDescriptionRunes)
	}
	if color == "" {
		color = config.DefaultAccountGroupColor
	}
	if !validAccountGroupColor(color) {
		return config.AccountGroup{}, fmt.Errorf("account group color must use #RRGGBB format")
	}
	return config.AccountGroup{Name: name, Description: description, Color: strings.ToLower(color)}, nil
}

func validAccountGroupColor(color string) bool {
	if len(color) != 7 || color[0] != '#' {
		return false
	}
	for _, char := range color[1:] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}

func nextAccountGroupID(groups []config.AccountGroup, policies []config.APIKeyGroupPolicy) int64 {
	maxID := int64(0)
	for _, group := range groups {
		if group.ID > maxID {
			maxID = group.ID
		}
	}
	for _, policy := range policies {
		for _, groupID := range policy.AllowedGroupIDs {
			if groupID > maxID {
				maxID = groupID
			}
		}
	}
	return maxID + 1
}

func accountGroupIndex(groups []config.AccountGroup, id int64) int {
	for index, group := range groups {
		if group.ID == id {
			return index
		}
	}
	return -1
}

func accountGroupNameExists(groups []config.AccountGroup, name string, excludedID int64) bool {
	name = strings.TrimSpace(name)
	for _, group := range groups {
		if group.ID != excludedID && strings.EqualFold(strings.TrimSpace(group.Name), name) {
			return true
		}
	}
	return false
}

func knownAccountGroupIDs(groups []config.AccountGroup) map[int64]struct{} {
	known := make(map[int64]struct{}, len(groups))
	for _, group := range groups {
		known[group.ID] = struct{}{}
	}
	return known
}

func missingAccountGroupIDs(ids []int64, known map[int64]struct{}) []int64 {
	missing := make([]int64, 0)
	for _, id := range ids {
		if _, exists := known[id]; !exists {
			missing = append(missing, id)
		}
	}
	return missing
}

func normalizeAccountGroupIDsValue(value any) ([]int64, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("group_ids must be an array of integers")
	}
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		parsed, okParse := authFileIntValue(item)
		if !okParse || parsed <= 0 {
			return nil, fmt.Errorf("group_ids must contain positive integers")
		}
		ids = append(ids, int64(parsed))
	}
	return config.NormalizeAccountGroupIDs(ids), nil
}

func removeAccountGroupID(ids []int64, target int64) []int64 {
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id != target {
			out = append(out, id)
		}
	}
	return out
}

func (h *Handler) authsInAccountGroup(groupID int64) []*coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	out := make([]*coreauth.Auth, 0)
	for _, auth := range h.authManager.List() {
		ids := auth.GroupIDs()
		index := sort.Search(len(ids), func(index int) bool { return ids[index] >= groupID })
		if index < len(ids) && ids[index] == groupID {
			out = append(out, auth)
		}
	}
	return out
}

func (h *Handler) removeAccountGroupFromAuths(ctx context.Context, auths []*coreauth.Auth, groupID int64) error {
	h.mu.Lock()
	for _, auth := range auths {
		if auth == nil || auth.AuthSourceKind() != coreauth.AuthSourceConfig {
			continue
		}
		ids := removeAccountGroupID(auth.GroupIDs(), groupID)
		handled, errConfig := setConfigAuthAccountGroups(h.cfg, auth, ids)
		if errConfig != nil {
			h.mu.Unlock()
			return fmt.Errorf("failed to update config auth %s: %w", auth.ID, errConfig)
		}
		if !handled {
			h.mu.Unlock()
			return fmt.Errorf("config auth %s was not found", auth.ID)
		}
	}
	h.mu.Unlock()

	for _, auth := range auths {
		if auth == nil || coreauth.IsPluginVirtualAuth(auth) {
			continue
		}
		ids := removeAccountGroupID(auth.GroupIDs(), groupID)
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		if len(ids) == 0 {
			delete(auth.Metadata, "group_ids")
		} else {
			auth.Metadata["group_ids"] = ids
		}
		if _, errUpdate := h.authManager.Update(ctx, auth); errUpdate != nil {
			return fmt.Errorf("failed to update auth %s: %w", auth.ID, errUpdate)
		}
	}
	return nil
}

func upsertAPIKeyGroupPolicy(policies []config.APIKeyGroupPolicy, hash string, ids []int64) []config.APIKeyGroupPolicy {
	hash = strings.ToLower(strings.TrimSpace(hash))
	out := make([]config.APIKeyGroupPolicy, 0, len(policies)+1)
	found := false
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.APIKeyHash), hash) {
			if len(ids) > 0 && !found {
				out = append(out, config.APIKeyGroupPolicy{APIKeyHash: hash, AllowedGroupIDs: append([]int64(nil), ids...)})
			}
			found = true
			continue
		}
		out = append(out, policy)
	}
	if !found && len(ids) > 0 {
		out = append(out, config.APIKeyGroupPolicy{APIKeyHash: hash, AllowedGroupIDs: append([]int64(nil), ids...)})
	}
	return out
}

func validAPIKeyGroupPolicyHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	_, errDecode := hex.DecodeString(hash)
	return errDecode == nil
}
