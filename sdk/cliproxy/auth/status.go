package auth

// Status represents the lifecycle state of an Auth entry.
type Status string

const (
	// StatusUnknown means the auth state could not be determined.
	StatusUnknown Status = "unknown"
	// StatusActive indicates the auth is valid and ready for execution.
	StatusActive Status = "active"
	// StatusPending indicates the auth is waiting for an external action, such as MFA.
	StatusPending Status = "pending"
	// StatusRefreshing indicates the auth is undergoing a refresh flow.
	StatusRefreshing Status = "refreshing"
	// StatusInitializing indicates the auth is registered but has not completed
	// its mandatory post-import initialization flow.
	StatusInitializing Status = "initializing"
	// StatusRefreshingToken indicates the post-import flow is rotating the
	// credential token. The auth must not participate in request scheduling.
	StatusRefreshingToken Status = "refreshing_token"
	// StatusRefreshingQuota indicates token rotation completed and the imported
	// auth is being verified against the provider quota endpoint.
	StatusRefreshingQuota Status = "refreshing_quota"
	// StatusInitializationFailed indicates the post-import initialization flow
	// failed and is waiting for a background retry.
	StatusInitializationFailed Status = "initialization_failed"
	// StatusRecoveringToken indicates a runtime rate-limit recovery is rotating
	// the credential token. The auth must not participate in scheduling.
	StatusRecoveringToken Status = "recovering_token"
	// StatusRecoveringQuota indicates token rotation completed and the runtime
	// recovery is verifying the credential against the quota endpoint.
	StatusRecoveringQuota Status = "recovering_quota"
	// StatusRecoveryFailed indicates a runtime recovery attempt failed and is
	// waiting for a background retry.
	StatusRecoveryFailed Status = "recovery_failed"
	// StatusError indicates the auth is temporarily unavailable due to errors.
	StatusError Status = "error"
	// StatusDisabled marks the auth as intentionally disabled.
	StatusDisabled Status = "disabled"
)
