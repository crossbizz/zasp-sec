package main

import (
	"errors"
	"fmt"
	"testing"
)

type dependencyTestCause struct{ value string }

func (e *dependencyTestCause) Error() string { return e.value }
func TestRuntimeDependencyDiagnosticPreservesCause(t *testing.T) {
	cause := &dependencyTestCause{value: "CANARY_SECRET raw SDK cause"}
	wrapped := markRuntimeDependencyFailure("core-postgres", cause)
	if wrapped.Error() != cause.Error() || !errors.Is(wrapped, cause) {
		t.Fatal("cause identity/message changed")
	}
	var actual *dependencyTestCause
	if !errors.As(wrapped, &actual) || actual != cause {
		t.Fatal("typed cause changed")
	}
	if errors.Unwrap(wrapped) != cause {
		t.Fatal("unwrap changed")
	}
	if markRuntimeDependencyFailure("composition", wrapped) != wrapped {
		t.Fatal("inner phase overridden")
	}
}
func TestRuntimeDependencyDiagnosticFiniteProjection(t *testing.T) {
	for _, phase := range []string{"audit-export", "authorization-components", "authorization-readiness", "compliance-export", "composition", "composition-authorization", "composition-inputs", "connector-lifecycle", "connector-oauth", "connector-providers", "connector-secrets", "construction-context", "core-postgres", "core-repositories", "current-authorization", "edge-middleware", "handler-composition", "identity-authenticator", "identity-repository", "identity-webhook", "native-identity-provider", "native-services", "operational-middleware", "policy-history", "policy-surface", "product-middleware", "production-handlers", "public-surface", "reference-providers", "runtime-inputs", "security-agent-postgres", "security-agent-repositories", "temporal-observer", "ticket-services"} {
		if runtimeDependencyFailurePhase(fmt.Errorf("outer: %w", markRuntimeDependencyFailure(phase, errors.New("CANARY")))) != phase {
			t.Fatal("finite phase missing")
		}
	}
	for _, err := range []error{nil, errors.New("core-postgres"), markRuntimeDependencyFailure("CANARY_SECRET", errors.New("CANARY"))} {
		if runtimeDependencyFailurePhase(err) != "unavailable" {
			t.Fatal("unknown phase exposed")
		}
	}
	if markRuntimeDependencyFailure("core-postgres", nil) != nil {
		t.Fatal("nil success changed")
	}
}

func TestRuntimeDependencyDiagnosticPublicBoundaryIdentity(t *testing.T) {
	cause := errors.New("masked public sentinel")
	wrapped := markRuntimeDependencyFailure("core-postgres", cause)
	if runtimeDependencyPublicError(wrapped) != cause {
		t.Fatal("public direct sentinel identity changed")
	}
	if runtimeDependencyPublicError(cause) != cause || runtimeDependencyPublicError(nil) != nil {
		t.Fatal("public passthrough changed")
	}
	external := fmt.Errorf("existing public wrapper: %w", cause)
	if runtimeDependencyPublicError(external) != external {
		t.Fatal("existing public wrapper removed")
	}
	var invalid *runtimeDependencyFailure
	if runtimeDependencyFailurePhase(invalid) != "unavailable" {
		t.Fatal("typed nil diagnostic exposed")
	}
}
