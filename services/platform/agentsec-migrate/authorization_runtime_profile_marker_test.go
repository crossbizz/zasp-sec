package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAuthorizationRuntimeProfileFailureMarker(t *testing.T) {
	steps := []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile"}
	private := errors.New("PRIVATE_CAUSE_WITH_ENDPOINT_AND_TOKEN")
	for _, step := range steps {
		for _, stage := range []string{"install", "forward-readiness"} {
			t.Run(step+"/"+stage, func(t *testing.T) {
				refusal := authorizationRuntimeProfileStepRefusal(step, stage, private)
				for _, err := range []error{refusal, fmt.Errorf("PRIVATE_WRAPPER: %w", refusal), errors.Join(errors.New("PRIVATE_JOIN"), refusal)} {
					marker := authorizationRuntimeProfileFailureMarker(err)
					want := "ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=" + step + ";STAGE=" + stage + "\n"
					if marker != want {
						t.Fatalf("closed marker=%q; want %q", marker, want)
					}
					if strings.Contains(marker, "PRIVATE") {
						t.Fatal("marker disclosed private cause")
					}
					if !errors.Is(err, private) {
						t.Fatal("original refusal identity changed")
					}
				}
			})
		}
	}
}

func TestAuthorizationRuntimeProfileFailureMarkerRejectsUnclassifiedErrors(t *testing.T) {
	var nilStep *authorizationRuntimeProfileStepError
	for _, err := range []error{nil, errors.New("PRIVATE_CAUSE"), errors.New("ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=up-temporal-domain;STAGE=install\n"), authorizationRuntimeProfileStepRefusal("up-to-60", "install", errors.New("PRIVATE_CAUSE")), &authorizationRuntimeProfileStepError{step: "PRIVATE_STEP", stage: "install", cause: errors.New("PRIVATE_CAUSE")}, &authorizationRuntimeProfileStepError{step: "up-temporal-domain", stage: "PRIVATE_STAGE", cause: errors.New("PRIVATE_CAUSE")}, &authorizationRuntimeProfileStepError{step: "up-temporal-domain", stage: "install"}, nilStep} {
		if marker := authorizationRuntimeProfileFailureMarker(err); marker != "" {
			t.Fatalf("unclassified marker=%q", marker)
		}
	}
}

type profileMarkerPoisonCause struct{}

func (profileMarkerPoisonCause) Error() string { panic("cause formatting is forbidden") }
func TestAuthorizationRuntimeProfileFailureMarkerDoesNotFormatCause(t *testing.T) {
	err := authorizationRuntimeProfileStepRefusal("up-temporal-domain", "install", profileMarkerPoisonCause{})
	if got := authorizationRuntimeProfileFailureMarker(err); got != "ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=up-temporal-domain;STAGE=install\n" {
		t.Fatalf("closed marker=%q", got)
	}
}
