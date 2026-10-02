package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentWorker63CancelRetainsRecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-cancel-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		q := worker63ClaimRequest("worker63-cancel-claim-token")
		result, err := worker63Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := result["item"].(map[string]any)
		cancel := public62Request(o, w, e, actor, "cancel")
		cancel["run_id"] = created.RunID
		cancel["run_version"] = 2
		cancel["idempotency_key"] = "worker63-cancel-public-operation"
		cancelled, err := public62Call(ctx, api, cancel)
		if err != nil || cancelled["run_state"] != "needs_human" {
			t.Fatal("authentic planning cancellation", cancelled, err)
		}
		mutation := map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 3, "dispatch_version": 1}
		if _, err = worker63Call(ctx, worker, mutation); err == nil {
			t.Fatal("finish orphaned cancelled unreconciled planning job")
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1 AND state='active') AND EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1 AND state='claimed') AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='needs_human' AND last_error_code='public_cancel_requested')`, created.RunID).Scan(&retained); err != nil || !retained {
			t.Fatal("cancel/recovery authority changed", err)
		}
		if err = runner.DownProductionSecurityAgentWorker(ctx); err == nil {
			t.Fatal("unresolved cancellation allowed demotion")
		}
	})
}
