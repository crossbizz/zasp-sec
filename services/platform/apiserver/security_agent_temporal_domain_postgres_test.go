package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestTemporalDomainRetainedGuardsPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalOutbox(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalDomain(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentPublic(ctx); err == nil {
			t.Fatal("retained67 public authority was dropped")
		}
	})
}

// Retained approvals must still traverse the public API, scoped private
// decision, audit, receipt and65 capture after their readiness handoff.
func TestTemporalDomainDecisionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalOutbox(t, ctx, owner)
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		approved := public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		if approved.StepID != steps[0] || approved.StepState != "authorized" || approved.RunVersion != 4 {
			t.Fatal("retained approval", approved)
		}
		repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
		cancelled, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: run, RunVersion: 4, IdempotencyKey: "domain67-cancel-0001"})
		if err != nil || cancelled.RunState != "cancelled" || cancelled.CleanupRequired {
			t.Fatal("retained cancellation", cancelled, err)
		}
		var bound bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=3 AND count(*) FILTER(WHERE kind='start')=1 AND count(*) FILTER(WHERE kind='approval' AND decision_id=$2)=1 AND count(*) FILTER(WHERE kind='cancel' AND decision_id=$3)=1 AND bool_and(execution_owner='legacy') FROM zasp_temporal65.commands WHERE run_id=$1`, run, approved.ReceiptID, cancelled.ReceiptID).Scan(&bound); err != nil || !bound {
			t.Fatal("retained decision commands", bound, err)
		}
	})
}

// Use a real non-fixture migration owner for the full API admission path.
// Stop at exact60; the callback invokes the shipped67 command itself.
func runTemporalDomainFreshFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string)) {
	t.Helper()
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(ctx)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'ordered-progression-org','ordered-progression-approver','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Ordered progression','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, orderedProgressionApprover); err != nil {
			t.Fatal(err)
		}
		exercise(ctx, owner, worker, api, o, w, e, testID, actor)
	}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_test") })
}
