package apiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func worker63ClaimRequest(token string) map[string]any {
	return map[string]any{"operation": "claim", "worker_id": "worker63-recovery", "lease_token": token, "lease_seconds": 30, "limit": 1, "planner": map[string]any{"provider": "openrouter", "model": "openai/gpt-5-mini", "request_policy_version": "security-agent-planner-v1", "request_token_limit": 256, "credential_digest": "sha256:" + strings.Repeat("ab", 32)}}
}

// Real time, public trigger, real claim, real durable send intent. No owner
// mutation manufactures an expired lease or a successful recovery row.
func TestSecurityAgentWorker63RecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		// The shared fixture bounds ordinary cases at two minutes. This case
		// deliberately observes the immutable five-minute lease in real time.
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
		defer cancel()
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
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		runs := []string{}
		for index, mode := range []string{"claimed", "started", "expired", "cancelled-started"} {
			finding := []string{public62Finding, "pid_8d300001-0000-4000-8000-000000000004", "pid_8d300001-0000-4000-8000-000000000005", "pid_8d300001-0000-4000-8000-000000000006"}[index]
			if index > 0 {
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Recovery input','high','open')`, o, w, e, finding); err != nil {
					t.Fatal(err)
				}
			}
			run, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: finding, TriggerVersion: 1, IdempotencyKey: "worker63-recovery-" + mode})
			if err != nil {
				t.Fatal(err)
			}
			runs = append(runs, run.RunID)
			q := worker63ClaimRequest("worker63-recovery-token-" + mode)
			result, err := worker63Call(ctx, worker, q)
			if err != nil || result["outcome"] != "claimed" {
				t.Fatal(mode, result, err)
			}
			item := result["item"].(map[string]any)
			if item["run_id"] != run.RunID {
				t.Fatal("wrong global candidate", item)
			}
			if mode == "started" || mode == "cancelled-started" {
				selection := item["pricing"].(map[string]any)
				selection["organization_id"] = o
				selection["workspace_id"] = w
				selection["environment_id"] = e
				planning := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run.RunID, "worker_id": q["worker_id"], "lease_token": q["lease_token"], "operation": "prepare", "payload": map[string]any{"pricing": selection, "input_version": "worker63-controlled-input-version-1"}}
				if _, err = orderedPlanningCall(ctx, worker, planning); err != nil {
					t.Fatal("prepare durable intent", err)
				}
				planning["operation"] = "start"
				planning["payload"] = map[string]any{}
				sent, err := orderedPlanningCall(ctx, worker, planning)
				if err != nil || sent["send_permit"] != true {
					t.Fatal("durable send intent", sent, err)
				}
			}
			version := 2
			if mode == "cancelled-started" {
				cancel := public62Request(o, w, e, actor, "cancel")
				cancel["run_id"] = run.RunID
				cancel["run_version"] = 2
				cancel["idempotency_key"] = "worker63-cancel-after-durable-send"
				if got, err := public62Call(ctx, api, cancel); err != nil || got["run_state"] != "needs_human" {
					t.Fatal("cancel after send", got, err)
				}
				version = 3
				if _, err = worker63Call(ctx, worker, map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": version, "dispatch_version": 1}); err == nil {
					t.Fatal("durable send cancellation orphaned recovery")
				}
				var retained bool
				if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1 AND state='started') AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND last_error_code='public_cancel_requested') AND EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1 AND state='active')`, run.RunID).Scan(&retained); err != nil || !retained {
					t.Fatal("cancelled send evidence lost", err)
				}
			}
			if mode != "expired" {
				result, err = worker63Call(ctx, worker, map[string]any{"operation": "abandon", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": version, "dispatch_version": 1})
				if err != nil || result["outcome"] != "recovery_deferred" {
					t.Fatal(mode, result, err)
				}
			}
		}
		var expires time.Time
		if err := owner.QueryRow(ctx, `SELECT max(lease_expires_at) FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=ANY($1)`, runs).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		t.Log("waiting for immutable release61 leases", expires.UTC().Format(time.RFC3339Nano))
		timer := time.NewTimer(time.Until(expires) + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		restarted, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close(ctx)
		var got map[string]any
		for n, run := range runs {
			got, err = worker63Call(ctx, restarted, worker63ClaimRequest("worker63-recovery-after-restart-"+run))
			if err != nil || got["outcome"] != "empty" {
				t.Fatal("expired recovery resent/adopted work", got, err)
			}
			var count int
			if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases WHERE state='reconciled'`).Scan(&count); err != nil || count != n+1 {
				t.Fatal("reconciliation must advance one oldest item", count, err)
			}
		}
		var states, errors []string
		if err = owner.QueryRow(ctx, `SELECT array_agg(state ORDER BY run_id),array_agg(last_error_code ORDER BY run_id) FROM zasp_security_agent_runs WHERE run_id=ANY($1)`, runs).Scan(&states, &errors); err != nil {
			t.Fatal(err)
		}
		unknown := 0
		notSent := 0
		for i, state := range states {
			if state != "needs_human" {
				t.Fatal("unsafe terminal state", states)
			}
			switch errors[i] {
			case "budget_usage_unknown":
				unknown++
			case "planner_not_sent":
				notSent++
			default:
				t.Fatal("wrong retained reason", errors)
			}
		}
		if unknown != 2 || notSent != 2 {
			t.Fatal("lost send intent", errors)
		}
		var count int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases WHERE state='reconciled'`).Scan(&count); err != nil || count != 4 {
			t.Fatal("recovery evidence missing", count, err)
		}
		if err = runner.DownProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("resolved down", err)
		}
		if err = runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("resolved reinstall", err)
		}
		if got, err = worker63Call(ctx, restarted, worker63ClaimRequest("worker63-after-reinstall-token")); err != nil || got["outcome"] != "empty" {
			t.Fatal("reinstall resurrected work", got, err)
		}
	})
}
