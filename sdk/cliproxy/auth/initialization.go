package auth

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type InitializationState string

const (
	InitializationStateInitializing    InitializationState = "initializing"
	InitializationStateRefreshingToken InitializationState = "refreshing_token"
	InitializationStateRefreshingQuota InitializationState = "refreshing_quota"
	InitializationStateReady           InitializationState = "ready"
	InitializationStateFailed          InitializationState = "initialization_failed"
)

type RecoveryState string

const (
	RecoveryStateRefreshingToken RecoveryState = "recovering_token"
	RecoveryStateRefreshingQuota RecoveryState = "recovering_quota"
	RecoveryStateReady           RecoveryState = "ready"
	RecoveryStateFailed          RecoveryState = "recovery_failed"
)

const (
	MetadataRecoveryState       = "recovery_state"
	MetadataRecoveryGeneration  = "recovery_generation"
	MetadataRecoveryAttempts    = "recovery_attempts"
	MetadataRecoveryError       = "recovery_error"
	MetadataRecoveryReason      = "recovery_reason"
	MetadataRecoveryUpdatedAt   = "recovery_updated_at"
	MetadataRecoveryNextRetryAt = "recovery_next_retry_at"
	MetadataRecoveryReadyAt     = "recovery_ready_at"
	MetadataRecoveryQuotaAt     = "recovery_quota_refreshed_at"
)

const (
	MetadataInitializationState       = "initialization_state"
	MetadataInitializationGeneration  = "initialization_generation"
	MetadataInitializationAttempts    = "initialization_attempts"
	MetadataInitializationError       = "initialization_error"
	MetadataInitializationUpdatedAt   = "initialization_updated_at"
	MetadataInitializationNextRetryAt = "initialization_next_retry_at"
	MetadataInitializationReadyAt     = "initialization_ready_at"
	MetadataInitializationQuotaAt     = "initialization_quota_refreshed_at"
)

func AuthInitializationState(auth *Auth) InitializationState {
	if auth == nil {
		return ""
	}
	return InitializationStateFromMetadata(auth.Metadata)
}

func InitializationStateFromMetadata(metadata map[string]any) InitializationState {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[MetadataInitializationState].(string)
	switch InitializationState(strings.ToLower(strings.TrimSpace(value))) {
	case InitializationStateInitializing:
		return InitializationStateInitializing
	case InitializationStateRefreshingToken:
		return InitializationStateRefreshingToken
	case InitializationStateRefreshingQuota:
		return InitializationStateRefreshingQuota
	case InitializationStateReady:
		return InitializationStateReady
	case InitializationStateFailed:
		return InitializationStateFailed
	default:
		return ""
	}
}

func AuthInitializationGeneration(auth *Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[MetadataInitializationGeneration].(string)
	return strings.TrimSpace(value)
}

func AuthInitializationAttempts(auth *Auth) int {
	if auth == nil || auth.Metadata == nil {
		return 0
	}
	switch value := auth.Metadata[MetadataInitializationAttempts].(type) {
	case int:
		return max(value, 0)
	case int64:
		return max(int(value), 0)
	case float64:
		return max(int(value), 0)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return max(parsed, 0)
		}
	}
	return 0
}

func IsAuthInitializationBlocking(auth *Auth) bool {
	if auth == nil {
		return false
	}
	switch auth.Status {
	case StatusInitializing, StatusRefreshingToken, StatusRefreshingQuota, StatusInitializationFailed:
		return true
	}
	switch AuthInitializationState(auth) {
	case InitializationStateInitializing, InitializationStateRefreshingToken, InitializationStateRefreshingQuota, InitializationStateFailed:
		return true
	default:
		return false
	}
}

func AuthRecoveryState(auth *Auth) RecoveryState {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[MetadataRecoveryState].(string)
	switch RecoveryState(strings.ToLower(strings.TrimSpace(value))) {
	case RecoveryStateRefreshingToken:
		return RecoveryStateRefreshingToken
	case RecoveryStateRefreshingQuota:
		return RecoveryStateRefreshingQuota
	case RecoveryStateReady:
		return RecoveryStateReady
	case RecoveryStateFailed:
		return RecoveryStateFailed
	default:
		return ""
	}
}

func AuthRecoveryGeneration(auth *Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, _ := auth.Metadata[MetadataRecoveryGeneration].(string)
	return strings.TrimSpace(value)
}

func AuthRecoveryAttempts(auth *Auth) int {
	if auth == nil || auth.Metadata == nil {
		return 0
	}
	return initializationMetadataInt(auth.Metadata, MetadataRecoveryAttempts)
}

func IsAuthRecoveryBlocking(auth *Auth) bool {
	if auth == nil {
		return false
	}
	switch auth.Status {
	case StatusRecoveringToken, StatusRecoveringQuota, StatusRecoveryFailed:
		return true
	}
	switch AuthRecoveryState(auth) {
	case RecoveryStateRefreshingToken, RecoveryStateRefreshingQuota, RecoveryStateFailed:
		return true
	default:
		return false
	}
}

func IsAuthLifecycleBlocking(auth *Auth) bool {
	return IsAuthInitializationBlocking(auth) || IsAuthRecoveryBlocking(auth)
}

// ApplyInitializationStateFromMetadata restores the persisted post-import
// lifecycle after a file, object-store or database-backed auth is loaded.
func ApplyInitializationStateFromMetadata(auth *Auth) {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return
	}
	state := AuthInitializationState(auth)
	switch state {
	case InitializationStateInitializing:
		auth.Status = StatusInitializing
		auth.StatusMessage = "initialization queued"
	case InitializationStateRefreshingToken:
		auth.Status = StatusRefreshingToken
		auth.StatusMessage = "refreshing token"
	case InitializationStateRefreshingQuota:
		auth.Status = StatusRefreshingQuota
		auth.StatusMessage = "refreshing quota"
	case InitializationStateFailed:
		auth.Status = StatusInitializationFailed
		if detail := initializationMetadataString(auth.Metadata, MetadataInitializationError); detail != "" {
			auth.StatusMessage = "initialization failed; retrying: " + detail
		} else {
			auth.StatusMessage = "initialization failed"
		}
	default:
		applyRecoveryStateFromMetadata(auth)
		return
	}
	auth.Unavailable = true
	if nextRetry := initializationMetadataTime(auth.Metadata, MetadataInitializationNextRetryAt); !nextRetry.IsZero() {
		auth.NextRetryAfter = nextRetry
	}
}

func applyRecoveryStateFromMetadata(auth *Auth) {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return
	}
	switch AuthRecoveryState(auth) {
	case RecoveryStateRefreshingToken:
		auth.Status = StatusRecoveringToken
		auth.StatusMessage = "recovering token"
	case RecoveryStateRefreshingQuota:
		auth.Status = StatusRecoveringQuota
		auth.StatusMessage = "recovering quota"
	case RecoveryStateFailed:
		auth.Status = StatusRecoveryFailed
		if detail := initializationMetadataString(auth.Metadata, MetadataRecoveryError); detail != "" {
			auth.StatusMessage = "recovery failed; retrying: " + detail
		} else {
			auth.StatusMessage = "recovery failed"
		}
	default:
		return
	}
	auth.Unavailable = true
	if nextRetry := initializationMetadataTime(auth.Metadata, MetadataRecoveryNextRetryAt); !nextRetry.IsZero() {
		auth.NextRetryAfter = nextRetry
	}
}

// PrepareImportedCodexTeamInitialization marks an uploaded Team credential as
// unavailable before the backing file becomes visible to the watcher.
func PrepareImportedCodexTeamInitialization(metadata map[string]any) (string, bool) {
	if !isImportedCodexTeam(metadata) {
		return "", false
	}
	generation := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	metadata[MetadataInitializationState] = string(InitializationStateInitializing)
	metadata[MetadataInitializationGeneration] = generation
	metadata[MetadataInitializationAttempts] = int64(0)
	metadata[MetadataInitializationUpdatedAt] = now
	delete(metadata, MetadataInitializationError)
	delete(metadata, MetadataInitializationNextRetryAt)
	delete(metadata, MetadataInitializationReadyAt)
	delete(metadata, MetadataInitializationQuotaAt)
	delete(metadata, MetadataRecoveryState)
	delete(metadata, MetadataRecoveryGeneration)
	delete(metadata, MetadataRecoveryError)
	delete(metadata, MetadataRecoveryNextRetryAt)
	return generation, true
}

func isImportedCodexTeam(metadata map[string]any) bool {
	if len(metadata) == 0 || !strings.EqualFold(initializationMetadataString(metadata, "type"), "codex") {
		return false
	}
	for _, key := range []string{"chatgpt_plan_type", "chatgptPlanType", "plan_type", "planType"} {
		if strings.EqualFold(initializationMetadataString(metadata, key), "team") {
			return true
		}
	}
	return false
}

func initializationMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func initializationMetadataTime(metadata map[string]any, key string) time.Time {
	value := initializationMetadataString(metadata, key)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func initializationMetadataInt(metadata map[string]any, key string) int {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case int:
		return max(value, 0)
	case int64:
		return max(int(value), 0)
	case float64:
		return max(int(value), 0)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return max(parsed, 0)
		}
	}
	return 0
}
