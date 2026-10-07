package main

import "errors"

type runtimeDependencyFailure struct {
	phase string
	cause error
}

func (e *runtimeDependencyFailure) Error() string { return e.cause.Error() }
func (e *runtimeDependencyFailure) Unwrap() error { return e.cause }
func markRuntimeDependencyFailure(phase string, cause error) error {
	if cause == nil {
		return nil
	}
	var existing *runtimeDependencyFailure
	if errors.As(cause, &existing) {
		return cause
	}
	return &runtimeDependencyFailure{phase: phase, cause: cause}
}
func runtimeDependencyFailurePhase(cause error) string {
	var failure *runtimeDependencyFailure
	if !errors.As(cause, &failure) || failure == nil {
		return "unavailable"
	}
	switch failure.phase {
	case "audit-export", "authorization-components", "authorization-readiness", "compliance-export", "composition", "composition-authorization", "composition-inputs", "connector-lifecycle", "connector-oauth", "connector-providers", "connector-secrets", "construction-context", "core-postgres", "core-repositories", "current-authorization", "edge-middleware", "handler-composition", "identity-authenticator", "identity-repository", "identity-webhook", "native-identity-provider", "native-services", "operational-middleware", "policy-history", "policy-surface", "product-middleware", "production-handlers", "public-surface", "reference-providers", "runtime-inputs", "security-agent-postgres", "security-agent-repositories", "temporal-observer", "ticket-services":
		return failure.phase
	default:
		return "unavailable"
	}
}
func complianceBrowserDependencyFailureMarker(cause error) string {
	return "ZASP_COMPLIANCE_API_FAILED_DEPENDENCY=" + runtimeDependencyFailurePhase(cause)
}

// Public constructor callers receive the exact preexisting returned error.
// Only the private diagnostic path retains the phase wrapper.
func runtimeDependencyPublicError(err error) error {
	if failure, ok := err.(*runtimeDependencyFailure); ok && failure != nil {
		return failure.cause
	}
	return err
}
