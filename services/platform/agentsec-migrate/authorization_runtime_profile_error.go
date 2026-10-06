package main

import (
	"errors"
	"fmt"
)

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

func authorizationRuntimeProfileFailureMarker(err error) string {
	var stepError *authorizationRuntimeProfileStepError
	if !errors.As(err, &stepError) || stepError == nil || stepError.cause == nil {
		return ""
	}
	if stepError.stage != "install" && stepError.stage != "forward-readiness" {
		return ""
	}
	// Validate the same closed producer roster again at the output boundary.
	switch stepError.step {
	case "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile":
		return "ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=" + stepError.step + ";STAGE=" + stepError.stage + "\n"
	default:
		return ""
	}
}

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
