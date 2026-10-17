package apiserver

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestConnectorPreparationFailureStagesAreClosed(t *testing.T) {
	for _, stage := range []string{"release", "begin", "result", "local-state", "quarantine"} {
		t.Run(stage, func(t *testing.T) {
			for _, cause := range []error{ErrRepositoryUnavailable, ErrAuthorizationDenied, ErrRepositoryOperation} {
				err := connectorPreparationFailure(stage, cause)
				if !errors.Is(err, cause) || err.Error() != cause.Error() || connectorPreparationFailureStage(fmt.Errorf("private outer detail: %w", err)) != stage {
					t.Fatal("fixed stage changed sentinel behavior")
				}
			}
		})
	}
	for _, cause := range []error{nil, ErrRepositoryUnavailable, errors.New("begin private SQL/payload detail")} {
		if connectorPreparationFailureStage(cause) != "unknown" {
			t.Fatal("untyped error became diagnostic authority")
		}
	}
	if connectorPreparationFailure("begin", nil) != nil {
		t.Fatal("successful release changed into failure")
	}
	secret := errors.New("sensitive dependency text")
	err := connectorPreparationFailure("begin", secret)
	if strings.Contains(err.Error(), secret.Error()) || err.Error() != ErrRepositoryUnavailable.Error() || !errors.Is(err, secret) {
		t.Fatal("wrapper exposed private dependency detail or lost unwrap")
	}
	if connectorPreparationFailureStage(connectorPreparationFailure("private-stage-value", ErrRepositoryUnavailable)) != "unknown" {
		t.Fatal("unknown stage became public")
	}
	var missing *connectorPreparationStageError
	if connectorPreparationFailureStage(missing) != "unknown" {
		t.Fatal("nil typed error became diagnostic authority")
	}
}
