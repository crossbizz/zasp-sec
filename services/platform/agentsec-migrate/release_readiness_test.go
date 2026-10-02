package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type releaseReadinessQueryer struct {
	statements []string
	arguments  [][]any
	contexts   []context.Context
	failAt     int
	queryError bool
}

func (q *releaseReadinessQueryer) QueryRow(ctx context.Context, statement string, args ...any) pgx.Row {
	q.statements = append(q.statements, statement)
	q.arguments = append(q.arguments, append([]any(nil), args...))
	q.contexts = append(q.contexts, ctx)
	failed := len(q.statements) == q.failAt
	if failed && q.queryError {
		return releaseReadinessErrorRow{}
	}
	return scriptedPrincipalRow{value: !failed}
}

type releaseReadinessErrorRow struct{}

func (releaseReadinessErrorRow) Scan(...any) error { return errors.New("private-database-detail") }

func TestRegisterForwardReleaseChecksExactSchemaAfterPrincipals(t *testing.T) {
	for _, tc := range []struct{ command, statement, checksum, fingerprint string }{
		{"up-to-51", "SELECT zasp_production_runtime_precision_readiness($1,$2)", migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()},
		{"up-to-52", "SELECT zasp_production_audit_exports_readiness($1,$2)", migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()},
		{"up-to-53", "SELECT zasp_production_security_agent_budgets_readiness($1,$2)", migrations.ProductionSecurityAgentBudgets().Checksum(), migrations.SecurityAgentBudgetCandidateFingerprint()},
		{"up-to-54", "SELECT zasp_production_security_agent_run_context_readiness($1,$2)", migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()},
		{"up-to-55", "SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()},
		{"up-to-56", "SELECT zasp_compliance_readiness($1,$2)", migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()},
		{"up-to-57", "SELECT zasp_sa_attack_lab_readiness($1,$2)", migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint()},
	} {
		t.Run(tc.command, func(t *testing.T) {
			q := &releaseReadinessQueryer{}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{tc.command}); err != nil {
				t.Fatal(err)
			}
			if len(q.statements) != 17 || q.statements[0] != "SELECT session_user=$1" || q.statements[16] != tc.statement || !reflect.DeepEqual(q.arguments[16], []any{tc.checksum, tc.fingerprint}) {
				t.Fatalf("wrong release readiness sequence/pins: %v %v", q.statements, q.arguments)
			}
		})
	}
	for _, command := range []string{"up", "up-to-48", "up-to-49", "up-to-50"} {
		q := &releaseReadinessQueryer{}
		if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{command}); err != nil || len(q.statements) != 16 {
			t.Fatalf("historical principal path changed for %s: %v %v", command, err, q.statements)
		}
	}
}

func TestRegisterForwardReleaseStopsOnFailedAuthorityOrReadiness(t *testing.T) {
	for index := 1; index <= 17; index++ {
		for _, queryError := range []bool{false, true} {
			q := &releaseReadinessQueryer{failAt: index, queryError: queryError}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-55"}); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != index {
				t.Fatalf("failure %d queryError=%v did not stop/sanitize: err=%v calls=%d", index, queryError, err, len(q.statements))
			}
		}
	}
	for _, args := range [][]string{nil, {"up-to-55", "extra"}, {"up-to-61"}, {"down-to-54"}} {
		q := &releaseReadinessQueryer{}
		if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, args); err == nil || len(q.statements) != 0 {
			t.Fatalf("invalid arguments reached database: %v", args)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		q := &releaseReadinessQueryer{}
		if err := registerForwardRelease(ctx, q, discoveryPrincipalRegistration{}, []string{"up-to-55"}); err == nil || len(q.statements) != 0 {
			t.Fatal("invalid context reached database")
		}
	}
}

func TestProductionDiscoveryScheduleReplayForwardReadiness(t *testing.T) {
	q := &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-60"}); err != nil {
		t.Fatal(err)
	}
	if len(q.statements) != 17 || q.statements[16] != "SELECT zasp_discovery_schedule_replay_readiness($1,$2)" || !reflect.DeepEqual(q.arguments[16], []any{migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()}) {
		t.Fatalf("unbound release60 readiness: %v %v", q.statements, q.arguments)
	}
	for i := 1; i <= 17; i++ {
		for _, queryError := range []bool{false, true} {
			q := &releaseReadinessQueryer{failAt: i, queryError: queryError}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-60"}); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != i {
				t.Fatalf("failed registration/readiness not stopped: %d %v %v", i, err, q.statements)
			}
		}
	}
}
