package apiserver

import (
	"context"
	"crypto/ed25519"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"testing"
)

// Break: finish discards runnable/dirty work, or cannot release a genuine
// approval pause or a public-cancelled run that never created an effect.
func TestSecurityAgentScheduler64FinishPostgres(t *testing.T) {
	for _, mode := range []string{"approval", "terminal", "stop"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				scheduler64Setup(t, ctx, owner)
				var r, s string
				version := 4
				if mode == "approval" {
					var steps []string
					r, steps, _ = scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
					s = steps[1]
					version = 6
				} else {
					worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
					worker63Pricing(t, ctx, owner, o, w, e, actor)
					r, s = scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6440)
					public62TypedDecision(t, ctx, api, o, w, e, r, 3)
				}
				q := scheduler64Request("scheduler64-finish-" + mode)
				v, err := scheduler64Call(ctx, worker, q)
				if err != nil || v["outcome"] != "claimed" {
					t.Fatal("finish setup claim", v, err)
				}
				item := v["item"].(map[string]any)
				if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "finish", version, 1)); err == nil {
					t.Fatal("unfinished work released")
				}
				for _, state := range []string{"contained", "remediated", "needs_human", "cancelled", "failed", "inconclusive"} {
					t.Run("fabricated_"+state, func(t *testing.T) {
						scheduler64Fault(t, ctx, owner, worker, `UPDATE zasp_security_agent_runs SET state=$2,completed_at=clock_timestamp() WHERE run_id=$1`, []any{r, state}, scheduler64Mutation(q, item, "finish", version, 1))
					})
				}
				if mode == "terminal" {
					t.Run("approval_response_is_not_terminal_proof", func(t *testing.T) {
						scheduler64Fault(t, ctx, owner, worker, `WITH changed AS (UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{response,run_state}','"cancelled"'::jsonb) WHERE run_id=$1 AND event_kind='ordered_approval_decided' RETURNING 1) UPDATE zasp_security_agent_runs SET state='cancelled',completed_at=clock_timestamp() WHERE run_id=$1`, []any{r}, scheduler64Mutation(q, item, "finish", version, 1))
					})
				}
				if mode == "approval" {
					if _, err = orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, s, "progress", q["action_worker_id"].(string), 6)); err != nil {
						t.Fatal(err)
					}
				} else if mode == "stop" {
					if _, err = api.Exec(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,'scheduler64-terminal-stop','environment','*',false,1,clock_timestamp()+interval '4 minutes',$5,$5,$5)`, o, w, e, actor, "pid_64000000-0000-4000-8000-000000000003"); err != nil {
						t.Fatal(err)
					}
					var successor string
					if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1`, r).Scan(&successor); err != nil {
						t.Fatal(err)
					}
					if _, err = orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, successor, "stop", q["action_worker_id"].(string), 4)); err != nil {
						t.Fatal(err)
					}
				} else {
					repo, id := public62GoRepository(t, api, o, w, e, actor)
					if _, err = repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 4, IdempotencyKey: "scheduler64-finish-cancel"}); err != nil {
						t.Fatal(err)
					}
				}
				v, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "finish", version+1, 1))
				if err != nil || v["outcome"] != "finished" {
					t.Fatal("authentic "+mode+" finish unavailable", v, err)
				}
				var count int
				if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_scheduler64.schedule_leases WHERE state='reconciled'`).Scan(&count); err != nil || count != 1 {
					t.Fatal("finish erased original schedule evidence", count, err)
				}
				if mode != "approval" {
					runner := precisionMigrationRunner(t, owner)
					if err = runner.DownProductionSecurityAgentScheduler(ctx); err != nil {
						t.Fatal("clean reconciled demotion unavailable", err)
					}
					if err = runner.UpProductionSecurityAgentScheduler(ctx); err != nil {
						t.Fatal(err)
					}
				}
			})
		})
	}
}

func TestSecurityAgentScheduler64CleanedFinishPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		r, steps, key := scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 6, IdempotencyKey: "scheduler64-clean-terminal"}); err != nil {
			t.Fatal(err)
		}
		q := scheduler64Request("scheduler64-cleaned-finish")
		q["action_worker_id"], q["deployment_worker_id"], q["deployment_lease_token"] = "ordered-cleanup-worker", "ordered-deployment", "ordered-deployment-lease"
		got, err := scheduler64Call(ctx, worker, q)
		if err != nil || got["outcome"] != "claimed" {
			t.Fatal(got, err)
		}
		item := got["item"].(map[string]any)
		config := owner.Config().Copy()
		config.User = "ordered_legacy_action_login"
		action, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer action.Close(ctx)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		cq := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 7, 3, 0)
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		claimed, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil {
			t.Fatal(err)
		}
		cq = orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claimed, key)
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		stored, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "finish", 7, 1)); err == nil {
			t.Fatal("partial cleanup finished")
		}
		// This helper's optional argument carrier is local request construction;
		// scheduler and release61 response bytes never contain the raw token.
		deploymentInput := cloneOrderedApplicationRequest(t, stored)
		deploymentInput["cleanup_lease_token"] = q["action_lease_token"]
		deployOrderedCleanup(t, ctx, owner, key, deploymentInput)
		cq = orderedCleanupRequest(o, w, e, r, steps[0], "complete", 7, int(stored["effect_version"].(float64)), int(stored["version"].(float64)))
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		completed, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil || completed["state"] != "cleaned" || completed["run_state"] != "cancelled" {
			t.Fatal(completed, err)
		}
		if got, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "finish", int(completed["run_version"].(float64)), 1)); err != nil || got["outcome"] != "finished" {
			t.Fatal("genuine cleaned finish", got, err)
		}
	})
}
