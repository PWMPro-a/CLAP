package codexclientpolicy

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	ReasonForceAllowed       = "force_codex_cli_enabled"
	ReasonBlacklisted        = "blacklist_matched"
	ReasonOfficialUserAgent  = "official_client_user_agent_matched"
	ReasonOfficialOriginator = "official_client_originator_matched"
	ReasonWhitelisted        = "whitelist_client_matched"
	ReasonAppServer          = "app_server_client_matched"
	ReasonIdentityMissing    = "official_client_identity_not_matched"
	ReasonVersionMissing     = "codex_version_undetectable"
	ReasonVersionTooLow      = "codex_version_too_low"
	ReasonVersionTooHigh     = "codex_version_too_high"
	ReasonFingerprintMissing = "missing_engine_fingerprint"
)

const (
	SignalHeaderExact  = "header_exact"
	SignalHeaderPrefix = "header_prefix"
	SignalBodyPath     = "body_path"
)

type ClientEntry struct {
	Originator            string   `yaml:"originator" json:"originator"`
	UAContains            []string `yaml:"ua-contains" json:"ua-contains"`
	SkipEngineFingerprint bool     `yaml:"skip-engine-fingerprint" json:"skip-engine-fingerprint"`
}

type EngineFingerprintSignal struct {
	Type     string   `yaml:"type" json:"type"`
	Match    []string `yaml:"match" json:"match"`
	Required bool     `yaml:"required" json:"required"`
}

type Policy struct {
	ForceAllow               bool
	MinCodexVersion          string
	MaxCodexVersion          string
	AllowAppServerClients    bool
	Whitelist                []ClientEntry
	Blacklist                []ClientEntry
	EngineFingerprintSignals []EngineFingerprintSignal
}

type Request struct {
	Headers http.Header
	Body    []byte
}

type Result struct {
	Allowed         bool
	Reason          string
	DetectedVersion string
	RequiredVersion string
}

var DefaultEngineFingerprintSignals = []EngineFingerprintSignal{
	{Type: SignalHeaderPrefix, Match: []string{"x-codex-"}, Required: true},
	{Type: SignalHeaderExact, Match: []string{"session-id", "session_id"}},
	{Type: SignalHeaderExact, Match: []string{"thread-id", "thread_id"}},
	{Type: SignalBodyPath, Match: []string{"client_metadata.x-codex-window-id", "client_metadata.x-codex-installation-id"}},
}

var officialUserAgentPrefixes = []string{
	"codex_cli_rs/",
	"codex-tui/",
	"codex_vscode/",
	"codex_vscode_copilot/",
	"codex_app/",
	"codex_chatgpt_desktop/",
	"codex_atlas/",
	"codex_exec/",
	"codex_sdk_ts/",
}

var officialOriginators = map[string]struct{}{
	"codex_cli_rs":          {},
	"codex-tui":             {},
	"codex_vscode":          {},
	"codex_vscode_copilot":  {},
	"codex_app":             {},
	"codex_chatgpt_desktop": {},
	"codex_atlas":           {},
	"codex_exec":            {},
	"codex_sdk_ts":          {},
}

var engineVersionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
var configuredVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func ValidatePolicy(policy Policy) error {
	minimum := strings.TrimSpace(policy.MinCodexVersion)
	maximum := strings.TrimSpace(policy.MaxCodexVersion)
	if minimum != "" && !configuredVersionPattern.MatchString(minimum) {
		return fmt.Errorf("min-codex-version must be empty or X.Y.Z")
	}
	if maximum != "" && !configuredVersionPattern.MatchString(maximum) {
		return fmt.Errorf("max-codex-version must be empty or X.Y.Z")
	}
	if minimum != "" && maximum != "" && CompareVersions(maximum, minimum) < 0 {
		return fmt.Errorf("max-codex-version must be greater than or equal to min-codex-version")
	}
	for index, entry := range policy.Whitelist {
		if normalize(entry.Originator) == "" || !hasNonEmptyValue(entry.UAContains) {
			return fmt.Errorf("whitelist entry %d must include originator and ua-contains", index)
		}
	}
	for index, entry := range policy.Blacklist {
		if normalize(entry.Originator) == "" && !hasNonEmptyValue(entry.UAContains) {
			return fmt.Errorf("blacklist entry %d must include originator or ua-contains", index)
		}
	}
	for index, signal := range policy.EngineFingerprintSignals {
		switch signal.Type {
		case SignalHeaderExact, SignalHeaderPrefix, SignalBodyPath:
		default:
			return fmt.Errorf("engine-fingerprint-signals entry %d has invalid type", index)
		}
		if !hasNonEmptyValue(signal.Match) {
			return fmt.Errorf("engine-fingerprint-signals entry %d must include match values", index)
		}
	}
	return nil
}

func Evaluate(req Request, policy Policy) Result {
	if policy.ForceAllow {
		return Result{Allowed: true, Reason: ReasonForceAllowed}
	}

	userAgent := headerValue(req.Headers, "User-Agent")
	originator := headerValue(req.Headers, "Originator")
	if matchDenyEntries(userAgent, originator, policy.Blacklist) {
		return Result{Reason: ReasonBlacklisted}
	}

	reason := ""
	skipFingerprint := false
	switch {
	case IsOfficialUserAgent(userAgent):
		reason = ReasonOfficialUserAgent
	case IsOfficialOriginator(originator):
		reason = ReasonOfficialOriginator
	default:
		if entry, ok := matchWhitelistEntry(userAgent, originator, policy.Whitelist); ok {
			reason = ReasonWhitelisted
			skipFingerprint = entry.SkipEngineFingerprint
		} else if policy.AllowAppServerClients {
			reason = ReasonAppServer
		}
	}
	if reason == "" {
		return Result{Reason: ReasonIdentityMissing}
	}

	if reason == ReasonOfficialUserAgent || reason == ReasonOfficialOriginator {
		version, ok := ParseEngineVersion(userAgent)
		if !ok {
			return Result{Reason: ReasonVersionMissing}
		}
		if minimum := strings.TrimSpace(policy.MinCodexVersion); minimum != "" && CompareVersions(version, minimum) < 0 {
			return Result{Reason: ReasonVersionTooLow, DetectedVersion: version, RequiredVersion: minimum}
		}
		if maximum := strings.TrimSpace(policy.MaxCodexVersion); maximum != "" && CompareVersions(version, maximum) > 0 {
			return Result{Reason: ReasonVersionTooHigh, DetectedVersion: version, RequiredVersion: maximum}
		}
	}

	if !skipFingerprint && !EvaluateEngineFingerprint(req.Headers, req.Body, policy.EngineFingerprintSignals) {
		return Result{Reason: ReasonFingerprintMissing}
	}
	return Result{Allowed: true, Reason: reason}
}

func IsOfficialUserAgent(value string) bool {
	userAgent := normalize(value)
	if userAgent == "" {
		return false
	}
	for _, prefix := range officialUserAgentPrefixes {
		if strings.HasPrefix(userAgent, prefix) {
			return true
		}
	}
	if strings.HasPrefix(userAgent, "codex ") {
		return true
	}
	return IsOfficialOriginator(userAgentTrailerName(userAgent))
}

func IsOfficialOriginator(value string) bool {
	originator := normalize(value)
	if originator == "" {
		return false
	}
	if _, ok := officialOriginators[originator]; ok {
		return true
	}
	return strings.HasPrefix(originator, "codex ")
}

func ParseEngineVersion(userAgent string) (string, bool) {
	userAgent = strings.TrimSpace(userAgent)
	slash := strings.IndexByte(userAgent, '/')
	if slash < 0 {
		return "", false
	}
	rest := userAgent[slash+1:]
	end := len(rest)
	for index := 0; index < len(rest); index++ {
		if rest[index] == ' ' || rest[index] == '(' {
			end = index
			break
		}
	}
	match := engineVersionPattern.FindString(strings.TrimSpace(rest[:end]))
	return match, match != ""
}

func CompareVersions(left, right string) int {
	leftParts := parseVersion(left)
	rightParts := parseVersion(right)
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1
		}
		if leftParts[index] > rightParts[index] {
			return 1
		}
	}
	return 0
}

func EvaluateEngineFingerprint(headers http.Header, body []byte, signals []EngineFingerprintSignal) bool {
	for _, signal := range signals {
		if !signal.Required {
			continue
		}
		if !fingerprintSignalMatches(headers, body, signal) {
			return false
		}
	}
	return true
}

func fingerprintSignalMatches(headers http.Header, body []byte, signal EngineFingerprintSignal) bool {
	switch signal.Type {
	case SignalHeaderExact:
		for _, name := range signal.Match {
			if strings.TrimSpace(headerValue(headers, name)) != "" {
				return true
			}
		}
	case SignalHeaderPrefix:
		for name := range headers {
			lowerName := strings.ToLower(name)
			for _, prefix := range signal.Match {
				if normalizedPrefix := normalize(prefix); normalizedPrefix != "" && strings.HasPrefix(lowerName, normalizedPrefix) {
					return true
				}
			}
		}
	case SignalBodyPath:
		for _, path := range signal.Match {
			if path = strings.TrimSpace(path); path != "" && len(body) > 0 && gjson.GetBytes(body, path).Exists() {
				return true
			}
		}
	}
	return false
}

func matchWhitelistEntry(userAgent, originator string, entries []ClientEntry) (ClientEntry, bool) {
	for _, entry := range entries {
		if normalize(entry.Originator) == "" || normalize(originator) != normalize(entry.Originator) || len(entry.UAContains) == 0 {
			continue
		}
		matched := true
		for _, marker := range entry.UAContains {
			marker = normalize(marker)
			if marker == "" || !strings.Contains(normalize(userAgent), marker) {
				matched = false
				break
			}
		}
		if matched {
			return entry, true
		}
	}
	return ClientEntry{}, false
}

func matchDenyEntries(userAgent, originator string, entries []ClientEntry) bool {
	for _, entry := range entries {
		if expected := normalize(entry.Originator); expected != "" && normalize(originator) == expected {
			return true
		}
		for _, marker := range entry.UAContains {
			if marker = normalize(marker); marker != "" && strings.Contains(normalize(userAgent), marker) {
				return true
			}
		}
	}
	return false
}

func userAgentTrailerName(userAgent string) string {
	start := strings.LastIndex(userAgent, "(")
	if start < 0 {
		return ""
	}
	rest := userAgent[start+1:]
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	inner := strings.TrimSpace(rest[:end])
	if separator := strings.Index(inner, ";"); separator >= 0 {
		inner = strings.TrimSpace(inner[:separator])
	}
	return inner
}

func parseVersion(value string) [3]int {
	match := engineVersionPattern.FindStringSubmatch(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	parts := [3]int{}
	if len(match) != 4 {
		return parts
	}
	for index := range parts {
		parts[index], _ = strconv.Atoi(match[index+1])
	}
	return parts
}

func hasNonEmptyValue(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func headerValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	return headers.Get(strings.TrimSpace(name))
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
