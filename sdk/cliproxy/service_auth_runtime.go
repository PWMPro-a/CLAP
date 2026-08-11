package cliproxy

type authRuntimeUpdateReuser interface {
	CanReuseForAuthUpdate(next any) bool
}

type authRuntimeRecoveryStarter interface {
	StartBackgroundRecovery()
}

func reusableAuthRuntime(existing, next any) any {
	if existing == nil || next == nil {
		return next
	}
	if reuser, ok := existing.(authRuntimeUpdateReuser); ok && reuser.CanReuseForAuthUpdate(next) {
		return existing
	}
	return next
}

func startAuthRuntimeRecovery(runtime any) {
	if starter, ok := runtime.(authRuntimeRecoveryStarter); ok && starter != nil {
		starter.StartBackgroundRecovery()
	}
}
