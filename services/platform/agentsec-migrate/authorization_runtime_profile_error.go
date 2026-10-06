package main

import "fmt"

// Retain the original refusal for errors.Is without allowing its contents into
// CLI diagnostics, including verbose formatting of the wrapper.
type authorizationRuntimeProfileStepError struct {
	step  string
	stage string
	cause error
}

func (e *authorizationRuntimeProfileStepError) Error() string {
	return "authorization runtime profile refused: step=" + e.step + " stage=" + e.stage
}

func (e *authorizationRuntimeProfileStepError) Unwrap() error { return e.cause }

func (e *authorizationRuntimeProfileStepError) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, e.Error())
}

func authorizationRuntimeProfileStepRefusal(step, stage string, cause error) error {
	if stage != "install" && stage != "forward-readiness" {
		return cause
	}
	switch step {
	case "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile":
		return &authorizationRuntimeProfileStepError{step: step, stage: stage, cause: cause}
	default:
		// The earlier release installer is outside this fourteen-step diagnostic
		// roster. Preserve its existing error and refusal behavior.
		return cause
	}
}
