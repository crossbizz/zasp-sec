package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

var temporalConfirmationTestCommands = []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response"}

func temporalConfirmationFixtureStep(step string) bool {
	for _, command := range temporalConfirmationTestCommands {
		if step == command {
			return true
		}
	}
	return false
}
func (q *authorizationConfirmationLoopQueryer) recordConfirmationEvent(kind, step string) {
	if temporalConfirmationFixtureStep(step) {
		q.temporalEvents = append(q.temporalEvents, kind+":"+step)
	} else {
		q.events = append(q.events, kind+":"+step)
	}
}

func TestTemporalConfirmationUsesActualBoundedAuthorityPath(t *testing.T) {
	if !reflect.DeepEqual(temporalProfileCommands, temporalConfirmationTestCommands) {
		t.Fatal("fixed twelve-step confirmation roster drifted from actual composite plan")
	}
	for _, command := range temporalConfirmationTestCommands {
		t.Run(command, func(t *testing.T) {
			registration := discoveryPrincipalRegistration{migration: "registered_source_login"}
			expected := &releaseReadinessQueryer{}
			if err := registerForwardRelease(context.Background(), expected, registration, []string{command}); err != nil || len(expected.statements) != 1 || len(expected.arguments[0]) != 3 {
				t.Fatal("original exact checksum-only Temporal confirmation unavailable")
			}
			for _, mode := range []string{"accepted", "catalog-refused", "uncertain-commit", "canceled", "missing-closed-begin"} {
				t.Run(mode, func(t *testing.T) {
					tx := &maintenanceConfirmationTransaction{deny: mode == "catalog-refused", uncertain: mode == "uncertain-commit"}
					plain := &maintenanceConfirmationTransaction{}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "canceled" {
						cancel()
					}
					begins := 0
					var begin func(context.Context) (retentionOperatorTransaction, error)
					if mode != "missing-closed-begin" {
						begin = func(context.Context) (retentionOperatorTransaction, error) { begins++; return tx, nil }
					}
					err := confirmForwardRelease(ctx, plain, begin, registration, []string{command})
					if plain.reads != 0 {
						t.Fatal("Temporal confirmation queried protected readiness outside authority transaction")
					}
					if mode == "canceled" || mode == "missing-closed-begin" {
						if err == nil || begins != 0 || tx.reads != 0 || tx.committed {
							t.Fatal("missing or canceled closed transaction fell back to readiness query")
						}
						return
					}
					if begins != 1 || !tx.authority || !tx.rolled || tx.reads != 1 || tx.statement != expected.statements[0] || !reflect.DeepEqual(tx.arguments, expected.arguments[0]) {
						t.Fatal("Temporal transaction changed configured-session SQL, checksum, fingerprint, or cleanup")
					}
					if mode == "accepted" {
						if err != nil || !tx.committed {
							t.Fatal("legitimate exact Temporal confirmation did not commit")
						}
					} else if err == nil || mode == "catalog-refused" && tx.committed {
						t.Fatal("refused or uncertain Temporal confirmation succeeded")
					}
				})
			}
		})
	}
}
func TestTemporalConfirmationRetainsExcludedLegacyFallbacks(t *testing.T) {
	for _, command := range []string{"up-temporal-outbox", "up-temporal-ownership"} {
		t.Run(command, func(t *testing.T) {
			registration := discoveryPrincipalRegistration{migration: "fixture_operator"}
			expected := &releaseReadinessQueryer{}
			actual := &releaseReadinessQueryer{}
			if err := registerForwardRelease(context.Background(), expected, registration, []string{command}); err != nil {
				t.Fatal(err)
			}
			begins := 0
			err := confirmForwardRelease(context.Background(), actual, func(context.Context) (retentionOperatorTransaction, error) {
				begins++
				return nil, errors.New("excluded legacy transaction")
			}, registration, []string{command})
			if err != nil || begins != 0 || !reflect.DeepEqual(actual.statements, expected.statements) || !reflect.DeepEqual(actual.arguments, expected.arguments) {
				t.Fatal("exact switch broadened into excluded legacy confirmation")
			}
		})
	}
}
func TestTemporalConfirmationActualInnerLoopCommitAndFailureOrder(t *testing.T) {
	for _, mode := range []string{"accepted", "domain-catalog", "test-executor-commit", "finding-response-catalog"} {
		t.Run(mode, func(t *testing.T) {
			original := &innerDiagnosticRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}, cause: errors.New("fixture-private-cause")}
			q := &authorizationConfirmationLoopQueryer{delegate: &innerDiagnosticQueryer{runner: original}}
			failIndex := -1
			switch mode {
			case "domain-catalog":
				failIndex = 0
				q.failureMode = "catalog"
			case "test-executor-commit":
				failIndex = 7
				q.failureMode = "commit"
			case "finding-response-catalog":
				failIndex = 11
				q.failureMode = "catalog"
			}
			if failIndex >= 0 {
				q.failureStep = temporalConfirmationTestCommands[failIndex]
			}
			checked := &authorizationConfirmationLoopRunner{innerDiagnosticRunner: original, observer: q}
			r := &registeredReleaseMigrationRunner{releaseMigrationRunner: checked, queryer: q, registration: discoveryPrincipalRegistration{migration: "fixture_operator"}}
			err := runReleaseMigration(context.Background(), r, []string{"up-authorization-runtime-profile"})
			limit := len(temporalConfirmationTestCommands)
			if failIndex >= 0 {
				limit = failIndex + 1
			}
			wantTemporal := []string{}
			for i, step := range temporalConfirmationTestCommands[:limit] {
				wantTemporal = append(wantTemporal, "read:"+step)
				if i == failIndex {
					if q.failureMode == "commit" {
						wantTemporal = append(wantTemporal, "commit-refused:"+step)
					}
				} else {
					wantTemporal = append(wantTemporal, "commit:"+step)
				}
			}
			if !reflect.DeepEqual(q.temporalEvents, wantTemporal) || q.violations != 0 || q.active || q.authority {
				t.Fatal("actual Temporal loop bypassed bounded authority or crossed confirmation fence")
			}
			for i, position := range q.commitPositions {
				if position != 2*(i+1) {
					t.Fatal("a later installer entered before an earlier confirmation committed")
				}
			}
			if failIndex >= 0 {
				if err == nil || !errors.Is(err, errReleasePrincipalRegistration) || err.Error() != "authorization runtime profile refused: step="+q.failureStep+" stage=forward-readiness" || q.workerInstalls != 0 || len(original.events) != 2*limit || len(q.commitPositions) != failIndex {
					t.Fatal("Temporal refusal lost command/stage identity or advanced later installers")
				}
			} else if err != nil || q.workerInstalls != 1 || len(q.commitPositions) != 14 {
				t.Fatal("all fourteen actual confirmations did not commit before subsequent installs")
			}
			wantOriginal := []string{}
			steps := innerDiagnosticSteps
			if failIndex >= 0 {
				steps = steps[:limit]
			}
			for _, step := range steps {
				wantOriginal = append(wantOriginal, "install:"+step, "forward-readiness:"+step)
			}
			if !reflect.DeepEqual(original.events, wantOriginal) {
				t.Fatal("original actual composite command/diagnostic order changed")
			}
		})
	}
}
