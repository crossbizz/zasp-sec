package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepApplicationBindingPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		for i, mode := range []string{"effect_input", "missing_reservation", "replay_target", "empty_policy", "changed_policy"} {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 750+i, true)
				request := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
				claim, err := orderedProgressionCall(ctx, action, "application", request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = owner.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				// Faults are committed, then the real action principal must refuse.
				query := map[string]string{"effect_input": `UPDATE zasp_security_agent_effects SET input_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1`, "missing_reservation": `DELETE FROM zasp_security_agent_step_reservations WHERE run_id=$1`, "replay_target": `UPDATE zasp_security_agent_temporary_policy_targets SET sequence=sequence+1,policy_version=policy_version+1 WHERE run_id=$1`}[mode]
				if query != "" {
					if _, err = owner.Exec(ctx, query, r); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = owner.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				if mode == "empty_policy" || mode == "changed_policy" {
					_, key, _ := ed25519.GenerateKey(rand.Reader)
					request = cloneOrderedApplicationRequest(t, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key))
					envelope := request["envelope"].(map[string]any)
					if mode == "empty_policy" {
						envelope["policies"] = []any{}
					} else {
						envelope["policies"].([]any)[0].(map[string]any)["rego"] = "package bypass"
					}
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if got, err := orderedProgressionCall(ctx, action, "application", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("changed application binding accepted", got, err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepApplicationCurrentRefusalPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		modes := []string{"lease", "approval_expired", "approval_revoked", "stopped", "cancelled", "failed", "unknown", "requester", "approver", "kill_switch", "readiness", "generation", "source_expiry", "source_policy"}
		for i, mode := range modes {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 830+i, true)
				claim, err := orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0))
				if err != nil {
					t.Fatal(err)
				}
				request := orderedApplicationRequest(o, w, e, r, steps[0], "heartbeat", 5, 1)
				if mode == "generation" || mode == "source_expiry" || mode == "source_policy" {
					_, key, _ := ed25519.GenerateKey(rand.Reader)
					if _, err = orderedProgressionCall(ctx, action, "application", orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key)); err != nil {
						t.Fatal(err)
					}
					request["effect_version"] = 2
				}
				fault := map[string]string{
					"lease":            `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"approval_expired": `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"approval_revoked": `UPDATE zasp_security_agent_approvals SET state='rejected' WHERE run_id=$1`,
					"stopped":          `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
					"cancelled":        `UPDATE zasp_security_agent_runs SET state='cancelled',completed_at=clock_timestamp() WHERE run_id=$1`,
					"failed":           `UPDATE zasp_security_agent_steps SET state='failed' WHERE run_id=$1 AND step_index=0`,
					"unknown":          `UPDATE zasp_security_agent_steps SET state='inconclusive' WHERE run_id=$1 AND step_index=0`,
					"requester":        `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"approver":         `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT approver_id FROM zasp_security_agent_approvals WHERE run_id=$1)`,
					"kill_switch":      `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE action_key='create_temporary_policy' AND $1<>''`,
					"readiness":        `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
					"generation":       `UPDATE zasp_policy_deployment_work SET desired_generation=desired_generation+1 WHERE device_id=(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
					"source_expiry":    `UPDATE zasp_security_agent_temporary_policy_targets SET expires_at=expires_at+interval '1 minute' WHERE run_id=$1`,
					"source_policy":    `UPDATE zasp_security_agent_temporary_policy_targets SET policies='[]' WHERE run_id=$1`,
				}[mode]
				if _, err = owner.Exec(ctx, fault, r); err != nil {
					t.Fatal(err)
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if _, err = orderedProgressionCall(ctx, action, "application", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("invalid current authority accepted", mode, err)
				}
				assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
				// Restore only shared configuration; faulted run evidence stays visible.
				if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id IN($1,$2);UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE action_key='create_temporary_policy';UPDATE zasp_schema_metadata SET value=$3 WHERE key='production_security_agent_multistep_checksum';UPDATE zasp_security_agent_runs SET state='cancelled' WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, actor, orderedProgressionApprover, migrations.ProductionSecurityAgentMultistep().Checksum(), r); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepApplicationCancellationRacePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		for i, mode := range []string{"cancel_first", "claim_first"} {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 850+i, true)
				claim := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
				cancel := orderedProgressionRequest(o, w, e, r, steps[0], "cancel", orderedProgressionApprover, 4)
				first, second := api, action
				firstFunction, secondFunction := "transition", "application"
				firstRequest, secondRequest := cancel, claim
				if mode == "claim_first" {
					first, second = action, api
					firstFunction, secondFunction = "application", "transition"
					firstRequest, secondRequest = claim, cancel
				}
				if _, err := first.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer first.Exec(ctx, `ROLLBACK`)
				if _, err := orderedProgressionCall(ctx, first, firstFunction, firstRequest); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := orderedProgressionCall(ctx, second, secondFunction, secondRequest); done <- err }()
				joined := false
				defer func() {
					if !joined {
						first.Exec(ctx, `ROLLBACK`)
						<-done
					}
				}()
				waitOrderedProgressionBlocked(t, ctx, first, second)
				if _, err := first.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				err := <-done
				joined = true
				if err == nil {
					t.Fatal("stale contender crossed commit boundary")
				}
				if mode == "claim_first" {
					cancel["run_version"] = 5
					if _, err = orderedProgressionCall(ctx, api, "transition", cancel); err != nil {
						t.Fatal(err)
					}
					assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
					if _, err = orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "heartbeat", 6, 1)); err == nil {
						t.Fatal("cancelled claim retained apply authority")
					}
				} else {
					assertOrderedApplicationCounts(t, ctx, owner, r, 0, 0, 0, 1)
				}
			})
		}
	})
}

func orderedApplicationSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, r string) string {
	t.Helper()
	var deployment string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY organization_id,workspace_id,environment_id) FROM zasp_policy_deployment_work w WHERE device_id=$1),'bundles',(SELECT jsonb_agg(to_jsonb(b) ORDER BY organization_id,workspace_id,environment_id,sequence) FROM zasp_runtime_gateway_policy_bundles b WHERE device_id=$1))::text`, orderedApplicationDevice).Scan(&deployment); err != nil {
		t.Fatal(err)
	}
	return orderedActionFenceSnapshot(t, ctx, owner, r) + deployment
}
