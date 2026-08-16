package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const MetadataCodexIdentityFingerprint = "codex_identity_fingerprint"

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
	// Supplier-managed credentials carry a stable per-member fingerprint. Use it
	// before token material when display/member claims are absent so token
	// rotation cannot make one member look like a new scheduling identity.
	if fingerprint := codexIdentityFingerprintValue(auth); fingerprint != "" {
		return hashedIdentityKey("codex-fingerprint", fingerprint)
	}
	if token := firstAuthIdentityString(auth, "refresh_token", "refreshToken", "access_token", "accessToken"); token != "" {
		return hashedIdentityKey("codex-token", token)
	}
	return ""
}

func codexIdentityFingerprintValue(auth *Auth) string {
	return strings.ToLower(firstAuthIdentityString(auth,
		MetadataCodexIdentityFingerprint,
		"codex-identity-fingerprint",
		"codexIdentityFingerprint",
	))
}

// CodexIdentityFingerprint returns the persisted account identity used to keep
// scheduling and upstream cache namespaces stable across credential rotation.
func CodexIdentityFingerprint(auth *Auth) string {
	return codexIdentityFingerprintValue(auth)
}

// EnsureCodexIdentityFingerprint adds a deterministic persisted fingerprint to
// a Codex credential. Team workspaces are always combined with a member claim;
// when member claims are unavailable, fallbackIdentity should be the stable
// backing file ID.
func EnsureCodexIdentityFingerprint(auth *Auth, fallbackIdentity string) (string, bool) {
	if !isCodexIdentityAuth(auth) {
		return "", false
	}
	if fingerprint := codexIdentityFingerprintValue(auth); fingerprint != "" {
		return fingerprint, setCodexIdentityFingerprint(auth, fingerprint)
	}

	workspace := codexWorkspaceIdentityValue(auth)
	member := strings.ToLower(firstAuthIdentityString(auth,
		"chatgpt_user_id",
		"user_id",
		"chatgpt_account_user_id",
		"email",
		"outlook_email",
	))
	var fingerprint string
	switch {
	case member != "":
		fingerprint = hashedIdentityKey("codex-persisted-fingerprint", workspace, member)
	case firstAuthIdentityString(auth, "agent_runtime_id", "agentRuntimeId") != "":
		fingerprint = hashedIdentityKey("codex-persisted-runtime", firstAuthIdentityString(auth, "agent_runtime_id", "agentRuntimeId"))
	case strings.TrimSpace(fallbackIdentity) != "":
		fingerprint = hashedIdentityKey("codex-persisted-file", fallbackIdentity)
	default:
		return "", false
	}
	return fingerprint, setCodexIdentityFingerprint(auth, fingerprint)
}

// InheritCodexIdentityFingerprint keeps the existing file's cache namespace
// authoritative when its credential payload is replaced.
func InheritCodexIdentityFingerprint(auth *Auth, existing *Auth, fallbackIdentity string) (string, bool) {
	if !isCodexIdentityAuth(auth) {
		return "", false
	}
	if existing != nil && isCodexIdentityAuth(existing) {
		if fingerprint, _ := EnsureCodexIdentityFingerprint(existing, fallbackIdentity); fingerprint != "" {
			return fingerprint, setCodexIdentityFingerprint(auth, fingerprint)
		}
	}
	return EnsureCodexIdentityFingerprint(auth, fallbackIdentity)
}

func isCodexIdentityAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	provider := executorKeyFromAuth(auth)
	if provider == "" && auth.Metadata != nil {
		provider, _ = auth.Metadata["type"].(string)
		provider = strings.ToLower(strings.TrimSpace(provider))
	}
	return provider == "codex" || provider == "openai-codex"
}

func setCodexIdentityFingerprint(auth *Auth, fingerprint string) bool {
	if auth == nil || strings.TrimSpace(fingerprint) == "" {
		return false
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if current, _ := auth.Metadata[MetadataCodexIdentityFingerprint].(string); strings.TrimSpace(current) == fingerprint {
		return false
	}
	auth.Metadata[MetadataCodexIdentityFingerprint] = fingerprint
	return true
}

// codexSameMemberIdentity deliberately never treats a Team workspace ID as a
// credential identity. Multiple independent members share that workspace, and
// a terminal response for one member must not disable every other member.
// When both records carry stable fingerprints they are authoritative; the
// legacy workspace+member key keeps older duplicate files grouped.
func codexSameMemberIdentity(left, right *Auth) bool {
	if left == nil || right == nil ||
		!strings.EqualFold(executorKeyFromAuth(left), "codex") ||
		!strings.EqualFold(executorKeyFromAuth(right), "codex") {
		return false
	}
	leftFingerprint := codexIdentityFingerprintValue(left)
	rightFingerprint := codexIdentityFingerprintValue(right)
	if leftFingerprint != "" && rightFingerprint != "" {
		return leftFingerprint == rightFingerprint
	}
	leftIdentity := codexCanonicalIdentityKey(left)
	return leftIdentity != "" && leftIdentity == codexCanonicalIdentityKey(right)
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
		MetadataCodexIdentityFingerprint,
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
