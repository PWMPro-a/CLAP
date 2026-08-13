package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// codexCanonicalIdentityKey returns a stable member identity used only for
// local scheduling. It deliberately combines a Team workspace with its member
// identity because every member shares the workspace ID.
func codexCanonicalIdentityKey(auth *Auth) string {
	if auth == nil || !strings.EqualFold(executorKeyFromAuth(auth), "codex") {
		return ""
	}
	workspace := codexWorkspaceIdentityValue(auth)
	member := firstAuthIdentityString(auth, "chatgpt_user_id", "user_id", "email", "outlook_email")
	member = strings.ToLower(strings.TrimSpace(member))
	if member != "" {
		return hashedIdentityKey("codex-member", workspace, member)
	}
	if token := firstAuthIdentityString(auth, "refresh_token", "refreshToken", "access_token", "accessToken"); token != "" {
		return hashedIdentityKey("codex-token", token)
	}
	return ""
}

func codexWorkspaceIdentityKey(auth *Auth) string {
	workspace := codexWorkspaceIdentityValue(auth)
	if workspace == "" {
		return ""
	}
	return hashedIdentityKey("codex-workspace", workspace)
}

func codexWorkspaceIdentityValue(auth *Auth) string {
	return strings.ToLower(firstAuthIdentityString(auth,
		"chatgpt_account_id",
		"account_id",
		"workspace_id",
		"organization_id",
	))
}

func firstAuthIdentityString(auth *Auth, keys ...string) string {
	if auth == nil {
		return ""
	}
	for _, key := range keys {
		if value := authMetadataString(auth, key); value != "" {
			return strings.TrimSpace(value)
		}
		if value := authAttribute(auth, key); value != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func hashedIdentityKey(kind string, values ...string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(kind))
	for _, value := range values {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(strings.TrimSpace(value)))
	}
	return kind + ":" + hex.EncodeToString(digest.Sum(nil))
}

func preferredCanonicalAuth(left, right *Auth) *Auth {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	leftScore := canonicalAuthPreferenceScore(left)
	rightScore := canonicalAuthPreferenceScore(right)
	if leftScore != rightScore {
		if leftScore > rightScore {
			return left
		}
		return right
	}
	if left.ID <= right.ID {
		return left
	}
	return right
}

func preferScheduledCanonicalEntry(left, right *scheduledAuth) *scheduledAuth {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	if left.state != right.state {
		if scheduledStatePreference(left.state) > scheduledStatePreference(right.state) {
			return left
		}
		return right
	}
	if preferredCanonicalAuth(left.auth, right.auth) == left.auth {
		return left
	}
	return right
}

func scheduledStatePreference(state scheduledState) int {
	switch state {
	case scheduledStateReady:
		return 4
	case scheduledStateCooldown:
		return 3
	case scheduledStateBlocked:
		return 2
	case scheduledStateDisabled:
		return 1
	default:
		return 0
	}
}

func canonicalAuthPreferenceScore(auth *Auth) int {
	if auth == nil {
		return -1
	}
	score := 0
	if !auth.Disabled && auth.Status != StatusDisabled {
		score += 100
	}
	if firstAuthIdentityString(auth,
		"codex_identity_fingerprint",
		"codex-identity-fingerprint",
		"codexIdentityFingerprint",
	) != "" {
		score += 20
	}
	if authIdentityBool(auth, "codex_cli_only") {
		score += 10
	}
	if strings.EqualFold(firstAuthIdentityString(auth, "import_format"), "sub2api") {
		score += 5
	}
	return score
}

func authIdentityBool(auth *Auth, key string) bool {
	if auth == nil {
		return false
	}
	if auth.Attributes != nil {
		if parsed, errParse := strconv.ParseBool(strings.TrimSpace(auth.Attributes[key])); errParse == nil {
			return parsed
		}
	}
	if auth.Metadata == nil {
		return false
	}
	switch value := auth.Metadata[key].(type) {
	case bool:
		return value
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(value))
		return errParse == nil && parsed
	default:
		return false
	}
}
