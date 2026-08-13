package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const Sub2ImportFormat = "sub2api"

// Sub2ImportFile is one canonical CPA auth file expanded from a Sub2 export.
type Sub2ImportFile struct {
	FileName string
	Metadata map[string]any
}

type sub2Bundle struct {
	Type     string              `json:"type"`
	Accounts []sub2BundleAccount `json:"accounts"`
}

type sub2BundleAccount struct {
	Name        string         `json:"name"`
	Platform    string         `json:"platform"`
	Type        string         `json:"type"`
	Priority    any            `json:"priority"`
	Concurrency any            `json:"concurrency"`
	ExpiresAt   any            `json:"expires_at"`
	Disabled    any            `json:"disabled"`
	Credentials map[string]any `json:"credentials"`
	Extra       map[string]any `json:"extra"`
}

// ParseSub2Bundle recognizes OpenAI OAuth account bundles exported by Sub2 and
// expands them into stable, single-account CPA Codex auth documents.
func ParseSub2Bundle(data []byte) ([]Sub2ImportFile, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false, err
	}
	if _, exists := envelope["accounts"]; !exists {
		return nil, false, nil
	}

	var bundle sub2Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		if isSub2RootType(rawJSONString(envelope["type"])) {
			return nil, true, errors.New("invalid Sub2 accounts bundle")
		}
		return nil, false, nil
	}
	if len(bundle.Accounts) == 0 {
		if isSub2RootType(bundle.Type) {
			return nil, true, errors.New("Sub2 accounts bundle is empty")
		}
		return nil, false, nil
	}

	supported := 0
	for _, account := range bundle.Accounts {
		if isSub2OAuthAccount(account) {
			supported++
		}
	}
	if supported == 0 {
		if isSub2RootType(bundle.Type) {
			return nil, true, errors.New("Sub2 bundle contains no supported OpenAI OAuth accounts")
		}
		return nil, false, nil
	}
	if supported != len(bundle.Accounts) {
		return nil, true, errors.New("Sub2 bundle mixes supported OpenAI OAuth accounts with unsupported account types")
	}

	files := make([]Sub2ImportFile, 0, len(bundle.Accounts))
	seenIdentities := make(map[string]struct{}, len(bundle.Accounts))
	for index, account := range bundle.Accounts {
		metadata, identity, err := normalizeSub2Account(account)
		if err != nil {
			return nil, true, fmt.Errorf("Sub2 account %d is invalid: %w", index+1, err)
		}
		digest := sha256.Sum256([]byte(identity))
		stableID := hex.EncodeToString(digest[:10])
		if _, duplicate := seenIdentities[stableID]; duplicate {
			return nil, true, fmt.Errorf("Sub2 account %d duplicates another account identity", index+1)
		}
		seenIdentities[stableID] = struct{}{}
		files = append(files, Sub2ImportFile{
			FileName: "codex-sub2-" + stableID + ".json",
			Metadata: metadata,
		})
	}
	return files, true, nil
}

func isSub2OAuthAccount(account sub2BundleAccount) bool {
	platform := strings.ToLower(strings.TrimSpace(account.Platform))
	provider := strings.ToLower(firstString(account.Credentials, "type"))
	accountType := strings.ToLower(strings.TrimSpace(account.Type))
	providerMatches := platform == "openai" || platform == "codex" || provider == "codex"
	typeMatches := accountType == "" || accountType == "oauth"
	return providerMatches && typeMatches && hasSub2OAuthToken(account.Credentials)
}

func hasSub2OAuthToken(credentials map[string]any) bool {
	return firstString(
		credentials,
		"access_token",
		"refresh_token",
		"id_token",
		"session_access_token",
	) != ""
}

func normalizeSub2Account(account sub2BundleAccount) (map[string]any, string, error) {
	if len(account.Credentials) == 0 || !hasSub2OAuthToken(account.Credentials) {
		return nil, "", errors.New("OAuth token data is missing")
	}

	metadata := cloneMetadata(account.Credentials)
	metadata["type"] = "codex"
	metadata["import_format"] = Sub2ImportFormat
	metadata["sub2_platform"] = strings.ToLower(strings.TrimSpace(account.Platform))

	if firstString(metadata, "access_token") == "" {
		if accessToken := firstString(metadata, "session_access_token"); accessToken != "" {
			metadata["access_token"] = accessToken
		}
	}

	accountID := firstString(metadata, "account_id", "chatgpt_account_id")
	email := firstNonEmpty(
		firstString(metadata, "email"),
		firstString(account.Extra, "email"),
	)
	planType := resolveSub2PlanType(metadata, account.Extra)
	if idToken := firstString(metadata, "id_token"); idToken != "" {
		if claims, err := ParseJWTToken(idToken); err == nil && claims != nil {
			if accountID == "" {
				accountID = strings.TrimSpace(claims.GetAccountID())
			}
			if email == "" {
				email = strings.TrimSpace(claims.GetUserEmail())
			}
			if planType == "" {
				planType = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
			}
		}
	}
	if accountID != "" {
		metadata["account_id"] = accountID
	}
	if email != "" {
		metadata["email"] = email
	}
	if planType != "" {
		metadata["plan_type"] = planType
		metadata["chatgpt_plan_type"] = planType
		if planType != "free" {
			metadata["codex_plan_type_pinned"] = true
		}
	}
	if name := strings.TrimSpace(account.Name); name != "" {
		metadata["name"] = name
	}
	if account.Priority != nil {
		metadata["priority"] = account.Priority
	}
	if account.Concurrency != nil {
		metadata["max_concurrency"] = account.Concurrency
	}
	if _, exists := metadata["expires_at"]; !exists && account.ExpiresAt != nil {
		metadata["expires_at"] = account.ExpiresAt
	}
	if disabled, ok := firstBool(metadata, "disabled"); ok {
		metadata["disabled"] = disabled
	} else if disabled, ok = boolValue(account.Disabled); ok {
		metadata["disabled"] = disabled
	}
	if proxyURL := firstNonEmpty(
		firstString(metadata, "proxy_url", "proxyUrl"),
		firstString(account.Extra, "proxy_url", "proxyUrl"),
	); proxyURL != "" {
		metadata["proxy_url"] = proxyURL
	}
	if _, exists := metadata["last_refresh"]; !exists {
		if lastRefresh, ok := firstValue(account.Extra, "last_refresh", "lastRefresh"); ok {
			metadata["last_refresh"] = lastRefresh
		}
	}
	if websockets, ok := firstBool(account.Extra,
		"openai_oauth_responses_websockets_v2_enabled",
		"websockets",
	); ok {
		metadata["websockets"] = websockets
	}

	identity := accountID
	identityLabel := firstNonEmpty(email, strings.TrimSpace(account.Name))
	if identity != "" && identityLabel != "" {
		// A Sub2 export can contain multiple users in the same ChatGPT workspace,
		// so account_id alone is not a unique credential identity.
		identity += "|" + identityLabel
	}
	if identity == "" {
		identity = firstString(metadata, "chatgpt_account_id", "chatgpt_user_id")
	}
	if identity == "" && email != "" {
		identity = email + "|" + planType
	}
	if identity == "" {
		identity = firstString(metadata, "refresh_token", "access_token", "id_token")
	}
	if identity == "" {
		return nil, "", errors.New("stable account identity is missing")
	}
	return metadata, identity, nil
}

func resolveSub2PlanType(values ...map[string]any) string {
	candidates := make([]string, 0, len(values)*4)
	for _, value := range values {
		for _, key := range []string{"chatgpt_plan_type", "chatgptPlanType", "plan_type", "planType"} {
			if candidate := strings.ToLower(strings.TrimSpace(firstString(value, key))); candidate != "" {
				candidates = append(candidates, candidate)
			}
		}
	}
	for _, candidate := range candidates {
		if candidate != "free" {
			return candidate
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func firstBool(values map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, exists := values[key]; exists {
			if parsed, ok := boolValue(value); ok {
				return parsed, true
			}
		}
	}
	return false, false
}

func firstValue(values map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, exists := values[key]; exists && value != nil {
			return value, true
		}
	}
	return nil, false
}

func boolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	case float64:
		if typed == 0 || typed == 1 {
			return typed == 1, true
		}
	}
	return false, false
}

func isSub2RootType(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "sub2api" || value == "sub2api-data" || value == "sub2"
}

func rawJSONString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
