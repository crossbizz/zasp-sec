package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type complianceRegistrar interface {
	RegisterComplianceWorkers(context.Context, string, string) error
}

func complianceRegistrationRunner(t *testing.T, runner *Runner) complianceRegistrar {
	t.Helper()
	registrar, ok := any(runner).(complianceRegistrar)
	if !ok {
		t.Fatal("runner has no explicit compliance worker registration path")
	}
	return registrar
}

// Removing either readiness check, accepting false, interpolating identities or
// using caller-supplied pins must break this transaction-boundary contract.
func TestComplianceRegistrationTransaction(t *testing.T) {
	for _, mode := range []string{"healthy", "healthy57", "healthy58", "lower-release", "future-release", "wrong-checksum", "initial-drift", "family-drift", "registration-false", "registration-error", "final-drift", "final-error", "commit-error", "rollback-error", "cancel-registration", "cancel-final"} {
		t.Run(mode, func(t *testing.T) {
			metadata := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance())
			if mode == "healthy57" || mode == "healthy58" {
				metadata = append(metadata, ProductionSecurityAgentAttackLab())
			}
			if mode == "healthy58" {
				metadata = append(metadata, ProductionSecurityAgentExports())
			}
			if mode == "wrong-checksum" {
				metadata[55].checksum = "wrong"
			}
			if mode == "lower-release" {
				metadata = metadata[:55]
			}
			// Current-release dispatch reads a count before its exact reader does.
			rows := append([]Row{fakeRow{values: []any{int64(len(metadata))}}}, exactReleaseRows(metadata...)...)
			if mode == "future-release" {
				rows[0] = fakeRow{values: []any{int64(59)}}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var registration Row = fakeRow{values: []any{mode != "registration-false"}}
			var final Row = fakeRow{values: []any{mode != "final-drift"}}
			if mode == "registration-error" {
				registration = fakeRow{err: errors.New("private SQL detail")}
			}
			if mode == "final-error" {
				final = fakeRow{err: errors.New("private SQL detail")}
			}
			if mode == "cancel-registration" {
				registration = complianceCancelRow{cancel: cancel}
			}
			if mode == "cancel-final" {
				final = complianceCancelRow{cancel: cancel}
			}
			registrationIndex := len(rows) + 2
			rows = append(rows, fakeRow{values: []any{mode != "initial-drift"}}, fakeRow{values: []any{mode != "family-drift"}}, registration, final)
			tx := &fakeTransaction{rows: rows}
			if mode == "commit-error" {
				tx.commitError = errors.New("private SQL detail")
			}
			if mode == "rollback-error" {
				tx.rollbackError = errors.New("private SQL detail")
				tx.rows[registrationIndex] = fakeRow{values: []any{false}}
			}
			db := &fakeDatabase{transaction: tx}
			runner, _ := NewRunner(db)
			err := complianceRegistrationRunner(t, runner).RegisterComplianceWorkers(ctx, "compliance_executor", "compliance_cleanup")
			events := strings.Join(db.events, "\n")
			if strings.HasPrefix(mode, "healthy") {
				if err != nil || !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
					t.Fatalf("healthy registration: %v %s", err, events)
				}
			} else {
				want := ErrInvalidState
				if strings.HasSuffix(mode, "error") {
					want = ErrDatabase
				}
				if strings.HasPrefix(mode, "cancel-") {
					want = context.Canceled
				}
				if !errors.Is(err, want) || !strings.Contains(events, "rollback") || (mode != "commit-error" && strings.Contains(events, "commit")) || tx.rollbackContextError != nil {
					t.Fatalf("refusal/rollback: %v %s", err, events)
				}
			}
			called := strings.Contains(events, "query:SELECT public.zasp_compliance_register_workers($1,$2,$3,$4)")
			preflightRefused := mode == "lower-release" || mode == "future-release" || mode == "wrong-checksum" || mode == "initial-drift" || mode == "family-drift"
			if called == preflightRefused {
				t.Fatalf("registration crossed preflight boundary: %s", events)
			}
			if called {
				pins := ProductionCompliance().Checksum() + "," + ComplianceFingerprint()
				if !strings.Contains(events, "args:compliance_executor,compliance_cleanup,"+pins) {
					t.Fatalf("registration did not bind names and compiled pins: %s", events)
				}
				checks := 3
				if strings.HasPrefix(mode, "registration-") || mode == "rollback-error" {
					checks = 2
				}
				if mode == "healthy57" || mode == "healthy58" {
					checks = 1
				}
				if strings.Count(events, "query:SELECT public.zasp_compliance_readiness($1,$2)\nargs:"+pins) != checks {
					t.Fatalf("readiness protocol changed: %s", events)
				}
			}
		})
	}
}

type complianceCancelRow struct{ cancel context.CancelFunc }

func (row complianceCancelRow) Scan(values ...any) error {
	row.cancel()
	*values[0].(*bool) = true
	return nil
}

func TestComplianceRegistrationInvalidRunnerAndContext(t *testing.T) {
	for _, runner := range []*Runner{nil, {}} {
		if err := complianceRegistrationRunner(t, runner).RegisterComplianceWorkers(context.Background(), "worker", "cleanup"); !errors.Is(err, ErrInvalidRunner) {
			t.Fatal(err)
		}
	}
	db := &fakeDatabase{}
	runner, _ := NewRunner(db)
	registrar := complianceRegistrationRunner(t, runner)
	if err := registrar.RegisterComplianceWorkers(nil, "worker", "cleanup"); !errors.Is(err, ErrInvalidContext) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registrar.RegisterComplianceWorkers(ctx, "worker", "cleanup"); !errors.Is(err, context.Canceled) || len(db.events) != 0 {
		t.Fatal("invalid context reached database", err)
	}
}
