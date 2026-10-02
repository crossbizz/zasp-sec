package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A valid immutable receipt cannot authorize changed mutable execution facts.
func TestSecurityAgentMultistepProgressionBindingPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for i, mode := range []string{"generation", "predecessor_approval", "approval_replay_step", "progress_replay_step", "authorization_floor", "application_unknown", "application_failed", "progress_replay_missing_receipt"} {
			t.Run(mode, func(t *testing.T) {
				req := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 300+i)
				r := req["run_id"].(string)
				admitted, err := orderedProgressionCall(ctx, worker, "admit", req)
				if err != nil {
					t.Fatal(err)
				}
				steps := admitted["step_ids"].([]any)
				s0, s1 := steps[0].(string), steps[1].(string)
				approve := orderedProgressionRequest(o, w, e, r, s0, "approve", orderedProgressionApprover, 3)
				if _, err = orderedProgressionCall(ctx, api, "transition", approve); err != nil {
					t.Fatal(err)
				}
				request := orderedProgressionRequest(o, w, e, r, s1, "progress", "ordered-progress-worker", 4)
				connection := worker
				if mode == "approval_replay_step" {
					request = approve
					connection = api
				} else {
					seedOrderedApplicationAuthority(t, ctx, owner, o, w, e, r, s0)
				}
				if mode == "progress_replay_step" || mode == "progress_replay_missing_receipt" {
					if _, err = orderedProgressionCall(ctx, worker, "transition", request); err != nil {
						t.Fatal(err)
					}
				}
				q := map[string]string{
					"generation":                      `UPDATE zasp_security_agent_temporary_policy_targets SET desired_generation=desired_generation+1 WHERE run_id=$1`,
					"predecessor_approval":            `UPDATE zasp_security_agent_approvals SET state='cancelled' WHERE run_id=$1 AND step_id=$2`,
					"approval_replay_step":            `UPDATE zasp_security_agent_steps SET state='waiting_approval' WHERE run_id=$1 AND step_id=$2`,
					"progress_replay_step":            `UPDATE zasp_security_agent_steps SET state='queued' WHERE run_id=$1 AND step_index=1 AND $2<>''`,
					"authorization_floor":             `UPDATE zasp_security_agent_steps SET authorization_result='allow' WHERE run_id=$1 AND step_index=1 AND $2<>''`,
					"application_unknown":             `UPDATE zasp_security_agent_effects SET state='unknown_outcome' WHERE run_id=$1 AND step_id=$2`,
					"application_failed":              `UPDATE zasp_security_agent_effects SET state='known_failure' WHERE run_id=$1 AND step_id=$2`,
					"progress_replay_missing_receipt": `BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2; COMMIT`,
				}[mode]
				if mode == "generation" {
					_, err = owner.Exec(ctx, q, r)
				} else if mode == "progress_replay_missing_receipt" {
					// Deliberate owner-only storage corruption, not an adapter path.
					_, err = owner.Exec(ctx, q, pgx.QueryExecModeSimpleProtocol, r, s0)
				} else {
					_, err = owner.Exec(ctx, q, r, s0)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := orderedAdmissionSnapshot(t, ctx, owner, r)
				got, err := orderedProgressionCall(ctx, connection, "transition", request)
				if mode == "application_unknown" || mode == "application_failed" {
					if err != nil || got["outcome"] != "blocked" {
						t.Fatal("uncertain application not blocked", got, err)
					}
					return
				}
				if err == nil {
					t.Fatal("changed authority accepted", got)
				}
				if orderedAdmissionSnapshot(t, ctx, owner, r) != before {
					t.Fatal("refused authority changed work")
				}
			})
		}
	})
}
