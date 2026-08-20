package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type authFileImportDefaults struct {
	Websockets *bool
}

func authFileImportDefaultsFromRequest(c *gin.Context) (authFileImportDefaults, error) {
	var defaults authFileImportDefaults
	if c == nil {
		return defaults, nil
	}
	raw, exists := c.GetQuery("default_websockets")
	if c.ContentType() == "multipart/form-data" {
		form, err := c.MultipartForm()
		if err != nil {
			return defaults, fmt.Errorf("invalid multipart form: %w", err)
		}
		if form != nil {
			if values := form.Value["default_websockets"]; len(values) > 0 {
				raw = values[len(values)-1]
				exists = true
			}
		}
	}
	if !exists {
		return defaults, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return defaults, errors.New("default_websockets must be a boolean")
	}
	defaults.Websockets = &parsed
	return defaults, nil
}
func (h *Handler) writeAuthFileWithDefaults(
	ctx context.Context,
	name string,
	data []byte,
	defaults authFileImportDefaults,
) error {
	imports, handled, errBundle := codex.ParseAgentIdentityBundle(data)
	if errBundle != nil {
		return errBundle
	}
	if handled {
		existingNames := h.existingAgentIdentityImportNames()
		for _, item := range imports {
			applyAuthFileImportDefaults(item.Metadata, defaults)
			canonical, errMarshal := json.MarshalIndent(item.Metadata, "", "  ")
			if errMarshal != nil {
				return fmt.Errorf("serialize agent identity auth file: %w", errMarshal)
			}
			canonical = append(canonical, '\n')
			name := item.FileName
			if existingName := existingNames.claim(item.Metadata); existingName != "" {
				name = existingName
			}
			if errWrite := h.writeSingleAuthFile(ctx, name, canonical); errWrite != nil {
				return errWrite
			}
		}
		log.Infof("imported %d agent identity auth files", len(imports))
		return nil
	}
	sub2Imports, handled, errBundle := codex.ParseSub2Bundle(data)
	if errBundle != nil {
		return errBundle
	}
	if handled {
		for _, item := range sub2Imports {
			applyAuthFileImportDefaults(item.Metadata, defaults)
			canonical, errMarshal := json.MarshalIndent(item.Metadata, "", "  ")
			if errMarshal != nil {
				return fmt.Errorf("serialize Sub2 auth file: %w", errMarshal)
			}
			canonical = append(canonical, '\n')
			if errWrite := h.writeSingleAuthFile(ctx, item.FileName, canonical); errWrite != nil {
				return errWrite
			}
		}
		log.Infof("imported %d Sub2 auth files", len(sub2Imports))
		return nil
	}
	dataWithDefaults, errDefaults := applyAuthFileImportDefaultsToData(data, defaults)
	if errDefaults != nil {
		return errDefaults
	}
	return h.writeSingleAuthFile(ctx, name, dataWithDefaults)
}

type agentIdentityImportNameIndex struct {
	names     map[string]string
	ambiguous map[string]struct{}
	claimed   map[string]struct{}
}

func newAgentIdentityImportNameIndex() *agentIdentityImportNameIndex {
	return &agentIdentityImportNameIndex{
		names:     make(map[string]string),
		ambiguous: make(map[string]struct{}),
		claimed:   make(map[string]struct{}),
	}
}

func (i *agentIdentityImportNameIndex) add(name string, metadata map[string]any) {
	if i == nil || name == "" {
		return
	}
	for _, identity := range agentIdentityAccountLookupKeys(metadata) {
		if _, ambiguous := i.ambiguous[identity]; ambiguous {
			continue
		}
		if existingName, exists := i.names[identity]; exists && existingName != name {
			delete(i.names, identity)
			i.ambiguous[identity] = struct{}{}
			continue
		}
		i.names[identity] = name
	}
}

// claim returns one unambiguous existing auth file and prevents a second
// account in the same bundle from overwriting that file.
func (i *agentIdentityImportNameIndex) claim(metadata map[string]any) string {
	if i == nil {
		return ""
	}
	for _, identity := range agentIdentityAccountLookupKeys(metadata) {
		if _, ambiguous := i.ambiguous[identity]; ambiguous {
			continue
		}
		name := i.names[identity]
		if name == "" {
			continue
		}
		if _, claimed := i.claimed[name]; claimed {
			continue
		}
		i.claimed[name] = struct{}{}
		return name
	}
	return ""
}

func (h *Handler) existingAgentIdentityImportNames() *agentIdentityImportNameIndex {
	index := newAgentIdentityImportNameIndex()
	if h == nil || h.cfg == nil {
		return index
	}
	entries, errReadDir := os.ReadDir(h.cfg.AuthDir)
	if errReadDir != nil {
		return index
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		data, errRead := os.ReadFile(filepath.Join(h.cfg.AuthDir, entry.Name()))
		if errRead != nil {
			continue
		}
		metadata := make(map[string]any)
		if err := json.Unmarshal(data, &metadata); err != nil {
			continue
		}
		if _, handled, _ := codex.ParseAgentIdentityMetadata(metadata); !handled {
			continue
		}
		index.add(entry.Name(), metadata)
	}
	return index
}

func agentIdentityAccountLookupKeys(metadata map[string]any) []string {
	keys := make([]string, 0, 3)
	credentials, handled, _ := codex.ParseAgentIdentityMetadata(metadata)
	if handled && credentials.RuntimeID != "" {
		keys = append(keys, "runtime:"+credentials.RuntimeID)
	}
	if userID := agentIdentityMetadataString(metadata, "chatgpt_user_id", "chatgptUserId", "user_id", "userId"); userID != "" {
		keys = append(keys, "user:"+userID)
	}
	if email := agentIdentityMetadataString(metadata, "email"); email != "" {
		keys = append(keys, "email:"+strings.ToLower(email))
	}
	// A Team/workspace account id may be shared by many users. It is only a
	// safe fallback when the record has no runtime, user id, or email.
	if len(keys) == 0 {
		if accountID := agentIdentityMetadataString(metadata, "account_id", "accountId", "chatgpt_account_id", "chatgptAccountId", "workspace_id", "workspaceId"); accountID != "" {
			keys = append(keys, "account:"+accountID)
		}
	}
	return keys
}

func applyAuthFileImportDefaults(metadata map[string]any, defaults authFileImportDefaults) bool {
	if len(metadata) == 0 || defaults.Websockets == nil {
		return false
	}
	provider, _ := metadata["type"].(string)
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return false
	}
	if _, exists := metadata["websockets"]; exists {
		return false
	}
	metadata["websockets"] = *defaults.Websockets
	return true
}

func applyAuthFileImportDefaultsToData(
	data []byte,
	defaults authFileImportDefaults,
) ([]byte, error) {
	if defaults.Websockets == nil {
		return data, nil
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("invalid auth file: %w", err)
	}
	if !applyAuthFileImportDefaults(metadata, defaults) {
		return data, nil
	}
	canonical, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serialize auth file defaults: %w", err)
	}
	return append(canonical, '\n'), nil
}

func normalizeImportedCodexAuthFileData(data []byte, now time.Time) ([]byte, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return data, nil
	}
	if !strings.EqualFold(strings.TrimSpace(authMetadataString(metadata, "type")), "codex") {
		return data, nil
	}
	if !normalizeImportedCodexAuthFileMetadata(metadata, now) {
		return data, nil
	}
	canonical, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serialize normalized Codex auth file: %w", err)
	}
	return append(canonical, '\n'), nil
}

func normalizeImportedCodexAuthFileMetadata(metadata map[string]any, now time.Time) bool {
	if len(metadata) == 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	changed := false
	if token := authMetadataString(metadata, "session_access_token", "sessionAccessToken"); token != "" && authMetadataString(metadata, "access_token", "accessToken") == "" {
		metadata["access_token"] = token
		changed = true
	}

	claimMaps := make([]map[string]any, 0, 3)
	if idTokenClaims := codexClaimsObjectFromValue(metadata["id_token"]); len(idTokenClaims) > 0 {
		claimMaps = append(claimMaps, idTokenClaims)
	}
	if idTokenClaims := codexClaimsObjectFromValue(metadata["idToken"]); len(idTokenClaims) > 0 {
		claimMaps = append(claimMaps, idTokenClaims)
	}
	if accessClaims := codexJWTClaimsMap(authMetadataString(metadata, "access_token", "accessToken", "session_access_token", "sessionAccessToken")); len(accessClaims) > 0 {
		claimMaps = append(claimMaps, accessClaims)
		if exp, ok := codexClaimUnix(accessClaims, "exp"); ok {
			expiresAt := time.Unix(exp, 0).UTC()
			if codexAuthFileExpiryNeedsRewrite(metadata["expired"]) {
				metadata["expired"] = expiresAt.Format(time.RFC3339)
				changed = true
			}
			if _, exists := metadata["expires_at"]; !exists {
				metadata["expires_at"] = exp
				changed = true
			}
			if _, exists := metadata["expires_in"]; !exists && expiresAt.After(now) {
				metadata["expires_in"] = int64(expiresAt.Sub(now).Seconds())
				changed = true
			}
		}
		if iat, ok := codexClaimUnix(accessClaims, "iat"); ok && strings.TrimSpace(authMetadataString(metadata, "last_refresh", "lastRefresh")) == "" {
			metadata["last_refresh"] = time.Unix(iat, 0).UTC().Format(time.RFC3339)
			changed = true
		}
	}

	for _, claims := range claimMaps {
		changed = copyCodexClaimsToMetadata(metadata, claims) || changed
	}
	return changed
}

func codexClaimsObjectFromValue(value any) map[string]any {
	switch typed := value.(type) {
	case string:
		if claims := codexJWTClaimsMap(typed); len(claims) > 0 {
			return claims
		}
		var object map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(typed)), &object); err == nil {
			return object
		}
	case map[string]any:
		return typed
	case map[string]string:
		object := make(map[string]any, len(typed))
		for key, item := range typed {
			object[key] = item
		}
		return object
	}
	return nil
}

func codexJWTClaimsMap(token string) map[string]any {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return nil
	}
	claims := make(map[string]any)
	if err = json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

func codexClaimUnix(claims map[string]any, key string) (int64, bool) {
	if claims == nil {
		return 0, false
	}
	switch value := claims[key].(type) {
	case float64:
		return int64(value), value > 0
	case int64:
		return value, value > 0
	case int:
		return int64(value), value > 0
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil && parsed > 0
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return parsed, err == nil && parsed > 0
	default:
		return 0, false
	}
}

func codexAuthFileExpiryNeedsRewrite(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case bool:
		return !typed
	default:
		return false
	}
}

func copyCodexClaimsToMetadata(metadata map[string]any, claims map[string]any) bool {
	if len(metadata) == 0 || len(claims) == 0 {
		return false
	}
	changed := false
	authInfo := codexNestedClaimsMap(claims, "https://api.openai.com/auth", "auth")
	profileInfo := codexNestedClaimsMap(claims, "https://api.openai.com/profile", "profile")

	if accountID := firstNonEmptyAuthMetadataString(
		codexClaimString(authInfo, "chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"),
		codexClaimString(claims, "chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"),
	); accountID != "" {
		changed = setMissingCodexMetadataString(metadata, accountID, "account_id", "chatgpt_account_id") || changed
	}
	if accountUserID := firstNonEmptyAuthMetadataString(
		codexClaimString(authInfo, "chatgpt_account_user_id", "chatgptAccountUserId"),
		codexClaimString(claims, "chatgpt_account_user_id", "chatgptAccountUserId"),
	); accountUserID != "" {
		changed = setMissingCodexMetadataString(metadata, accountUserID, "chatgpt_account_user_id") || changed
	}
	if userID := firstNonEmptyAuthMetadataString(
		codexClaimString(authInfo, "chatgpt_user_id", "chatgptUserId", "user_id", "userId"),
		codexClaimString(claims, "chatgpt_user_id", "chatgptUserId", "user_id", "userId"),
	); userID != "" {
		changed = setMissingCodexMetadataString(metadata, userID, "chatgpt_user_id", "user_id") || changed
	}
	if planType := firstNonEmptyAuthMetadataString(
		codexClaimString(authInfo, "chatgpt_plan_type", "chatgptPlanType", "plan_type", "planType"),
		codexClaimString(claims, "chatgpt_plan_type", "chatgptPlanType", "plan_type", "planType"),
	); planType != "" {
		changed = setMissingCodexMetadataString(metadata, strings.ToLower(planType), "chatgpt_plan_type", "plan_type") || changed
	}
	if email := firstNonEmptyAuthMetadataString(
		codexClaimString(profileInfo, "email"),
		codexClaimString(claims, "email"),
	); email != "" {
		changed = setMissingCodexMetadataString(metadata, strings.ToLower(email), "email") || changed
	}
	if name := firstNonEmptyAuthMetadataString(
		codexClaimString(profileInfo, "name"),
		codexClaimString(claims, "name"),
	); name != "" {
		changed = setMissingCodexMetadataString(metadata, name, "name") || changed
	}
	if poid := codexClaimString(authInfo, "poid", "organization_id", "organizationId"); poid != "" {
		changed = setMissingCodexMetadataString(metadata, poid, "poid") || changed
	}
	return changed
}

func codexNestedClaimsMap(claims map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		value, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			return typed
		case map[string]string:
			object := make(map[string]any, len(typed))
			for nestedKey, nestedValue := range typed {
				object[nestedKey] = nestedValue
			}
			return object
		}
	}
	return nil
}

func codexClaimString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		value := claims[key]
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				return trimmed
			}
		case json.Number:
			if text := strings.TrimSpace(typed.String()); text != "" {
				return text
			}
		}
	}
	return ""
}

func firstNonEmptyAuthMetadataString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func setMissingCodexMetadataString(metadata map[string]any, value string, keys ...string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	changed := false
	for _, key := range keys {
		if strings.TrimSpace(authMetadataString(metadata, key)) == "" {
			metadata[key] = value
			changed = true
		}
	}
	return changed
}

func (h *Handler) writeSingleAuthFile(ctx context.Context, name string, data []byte) error {
	dst := filepath.Join(h.cfg.AuthDir, filepath.Base(name))
	if !filepath.IsAbs(dst) {
		if abs, errAbs := filepath.Abs(dst); errAbs == nil {
			dst = abs
		}
	}
	var err error
	data, err = preserveExistingAgentIdentityCredentials(dst, data)
	if err != nil {
		return err
	}
	data, err = normalizeImportedCodexAuthFileData(data, time.Now())
	if err != nil {
		return err
	}
	data, err = prepareCodexIdentityFingerprintForImport(dst, data)
	if err != nil {
		return err
	}
	data, err = prepareImportedTeamInitialization(data)
	if err != nil {
		return err
	}
	auth, err := h.buildAuthFromFileData(dst, data)
	if err != nil {
		return err
	}
	if errWrite := os.WriteFile(dst, data, 0o600); errWrite != nil {
		return fmt.Errorf("failed to write file: %w", errWrite)
	}
	if err := h.upsertAuthRecord(ctx, auth); err != nil {
		return err
	}
	if starter, ok := auth.Runtime.(interface {
		StartTaskRegistration() (codex.AgentIdentityRegistrationStatus, bool)
	}); ok && starter != nil {
		starter.StartTaskRegistration()
	}
	return nil
}

func prepareCodexIdentityFingerprintForImport(path string, data []byte) ([]byte, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return data, nil
	}
	provider, _ := metadata["type"].(string)
	fallbackIdentity := filepath.Base(path)
	incoming := &coreauth.Auth{
		ID:       fallbackIdentity,
		Provider: provider,
		Metadata: metadata,
	}
	changed := false
	if existingData, errRead := os.ReadFile(path); errRead == nil {
		existingMetadata := make(map[string]any)
		if json.Unmarshal(existingData, &existingMetadata) == nil {
			existingProvider, _ := existingMetadata["type"].(string)
			existing := &coreauth.Auth{
				ID:       fallbackIdentity,
				Provider: existingProvider,
				Metadata: existingMetadata,
			}
			_, changed = coreauth.InheritCodexIdentityFingerprint(incoming, existing, fallbackIdentity)
		}
	}
	if !changed {
		_, changed = coreauth.EnsureCodexIdentityFingerprint(incoming, fallbackIdentity)
	}
	if !changed {
		return data, nil
	}
	canonical, errMarshal := json.MarshalIndent(metadata, "", "  ")
	if errMarshal != nil {
		return nil, fmt.Errorf("serialize Codex identity fingerprint: %w", errMarshal)
	}
	return append(canonical, '\n'), nil
}

func prepareImportedTeamInitialization(data []byte) ([]byte, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("invalid auth file: %w", err)
	}
	if _, prepared := coreauth.PrepareImportedCodexTeamInitialization(metadata); !prepared {
		return data, nil
	}
	canonical, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serialize auth initialization state: %w", err)
	}
	return append(canonical, '\n'), nil
}

// preserveExistingAgentIdentityCredentials prevents an older incomplete export
// from downgrading an account that has already recovered. Supplied signing
// fields must agree with the installed identity before any missing fields are
// filled from disk.
func preserveExistingAgentIdentityCredentials(path string, data []byte) ([]byte, error) {
	incoming := make(map[string]any)
	if err := json.Unmarshal(data, &incoming); err != nil {
		return data, nil
	}
	incomingCredentials, handled, errIncoming := codex.ParseAgentIdentityMetadata(incoming)
	if !handled || !errors.Is(errIncoming, codex.ErrAgentIdentityCredentialsMissing) {
		return data, nil
	}

	existingData, errRead := os.ReadFile(path)
	if errors.Is(errRead, os.ErrNotExist) {
		return data, nil
	}
	if errRead != nil {
		return nil, fmt.Errorf("read existing agent identity auth file: %w", errRead)
	}
	existing := make(map[string]any)
	if err := json.Unmarshal(existingData, &existing); err != nil {
		return data, nil
	}
	existingCredentials, existingHandled, errExisting := codex.ParseAgentIdentityMetadata(existing)
	if !existingHandled || errExisting != nil ||
		!sameAgentIdentityAccount(incoming, existing, incomingCredentials, existingCredentials) ||
		(incomingCredentials.RuntimeID != "" && incomingCredentials.RuntimeID != existingCredentials.RuntimeID) ||
		(incomingCredentials.PrivateKey != "" && incomingCredentials.PrivateKey != existingCredentials.PrivateKey) {
		return data, nil
	}

	incoming["agent_runtime_id"] = existingCredentials.RuntimeID
	incoming["agent_private_key"] = existingCredentials.PrivateKey
	if incomingCredentials.TaskID == "" && existingCredentials.TaskID != "" {
		incoming["task_id"] = existingCredentials.TaskID
	}
	delete(incoming, "agent_identity_registration_state")
	merged, errMarshal := json.MarshalIndent(incoming, "", "  ")
	if errMarshal != nil {
		return nil, fmt.Errorf("serialize recovered agent identity auth file: %w", errMarshal)
	}
	return append(merged, '\n'), nil
}

func sameAgentIdentityAccount(
	incoming map[string]any,
	existing map[string]any,
	incomingCredentials codex.AgentIdentityCredentials,
	existingCredentials codex.AgentIdentityCredentials,
) bool {
	if incomingCredentials.RuntimeID != "" && existingCredentials.RuntimeID != "" {
		return incomingCredentials.RuntimeID == existingCredentials.RuntimeID
	}
	incomingUserID := agentIdentityMetadataString(incoming, "chatgpt_user_id", "chatgptUserId", "user_id", "userId")
	existingUserID := agentIdentityMetadataString(existing, "chatgpt_user_id", "chatgptUserId", "user_id", "userId")
	if incomingUserID != "" && existingUserID != "" {
		return incomingUserID == existingUserID
	}
	incomingEmail := agentIdentityMetadataString(incoming, "email")
	existingEmail := agentIdentityMetadataString(existing, "email")
	if incomingEmail != "" && existingEmail != "" {
		return strings.EqualFold(incomingEmail, existingEmail)
	}
	if incomingUserID != "" || existingUserID != "" || incomingEmail != "" || existingEmail != "" {
		return false
	}
	incomingAccountID := agentIdentityMetadataString(incoming, "account_id", "accountId", "chatgpt_account_id", "chatgptAccountId", "workspace_id", "workspaceId")
	existingAccountID := agentIdentityMetadataString(existing, "account_id", "accountId", "chatgpt_account_id", "chatgptAccountId", "workspace_id", "workspaceId")
	return incomingAccountID != "" && existingAccountID != "" && incomingAccountID == existingAccountID
}

func agentIdentityMetadataString(metadata map[string]any, keys ...string) string {
	if value := authMetadataString(metadata, keys...); value != "" {
		return value
	}
	for _, container := range []string{"agent_identity", "agentIdentity"} {
		nested, _ := metadata[container].(map[string]any)
		if value := authMetadataString(nested, keys...); value != "" {
			return value
		}
	}
	return ""
}

func authMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := metadata[key].(string); ok {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}
