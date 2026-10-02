package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Only provider bytes and artifact acknowledgements are controlled fixtures;
// real claim, pricing, intent, start and accounting authority produce each state.
func TestSecurityAgentMultistepPlanningExpiryPostgres(t *testing.T) {
	for _, stage := range []string{"claimed", "prepared", "started", "completed", "settled", "artifacts"} {
		t.Run(stage, func(t *testing.T) {
			runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, rawResult string) {
				job, err := orderedPlanningCall(ctx, worker, q)
				if err != nil {
					t.Fatal(err)
				}
				for _, next := range []string{"prepare", "start", "result", "settle", "artifacts"} {
					if job["state"] == stage {
						break
					}
					q["operation"] = next
					q["payload"] = map[string]any{}
					switch next {
					case "prepare":
						q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
					case "result":
						q["payload"] = map[string]any{"raw": rawResult}
					case "artifacts":
						q["payload"] = map[string]any{"input_version": "controlled-input-version", "output_version": "controlled-output-version", "output_digest": job["output_digest"]}
					}
					job, err = orderedPlanningCall(ctx, worker, q)
					if err != nil {
						t.Fatal(next, err)
					}
				}
				// Clock fault advances exact expiry, not provider or result authority.
				_, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.planning_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_runs SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, q["run_id"])
				if err != nil {
					t.Fatal(err)
				}
				q["operation"] = "reconcile"
				q["payload"] = map[string]any{}
				job, err = orderedPlanningCall(ctx, worker, q)
				if err != nil || job["state"] != "needs_human" {
					t.Fatal("expired planning recovery unavailable", err, job)
				}
				if again, err := orderedPlanningCall(ctx, worker, q); err != nil || !jsonEqualMaps(again, job) {
					t.Fatal("recovery restart mutated authority", err)
				}
				var settled bool
				var plans int
				if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations WHERE run_id=$1 AND settled_at IS NOT NULL),(SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1)`, q["run_id"]).Scan(&settled, &plans); err != nil || plans != 0 || settled != (stage == "completed" || stage == "settled" || stage == "artifacts") {
					t.Fatal("fabricated usage or admission", settled, plans, err)
				}
				q["operation"] = "start"
				if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
					t.Fatal("expired recovery reopened send")
				}
			})
		})
	}
}

func runOrderedPlanningFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, map[string]any, map[string]any, string)) {
	t.Helper()
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
		run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		config := owner.Config().Copy()
		config.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		policy := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), created)
		delete(selection, "body")
		delete(selection, "body_digest")
		candidate := map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": e}, map[string]any{"index": 1, "action": "run_test", "target_id": testID}}}
		content, _ := json.Marshal(candidate)
		raw, _ := json.Marshal(map[string]any{"model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(content)}}}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 50, "total_tokens": 100, "cost": 0.0000005}})
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		exercise(ctx, owner, worker, q, selection, string(raw))
	})
}
