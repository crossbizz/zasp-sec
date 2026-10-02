package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepCleanupAuthorityPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claimQ := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
		claim, err := orderedCleanupCall(ctx, action, claimQ, keys)
		if err != nil {
			t.Fatal(err)
		}
		orderedCleanupResponseRefusals(t, ctx, claimQ, claim, keys)
		orderedCleanupRequestBounds(t, ctx, claimQ, claim)
		for _, fault := range []string{`UPDATE zasp_security_agent_temporary_policy_targets SET sequence=1000000000,policy_version=1000000000 WHERE run_id=$1 AND phase='cleanup'`, `UPDATE zasp_security_agent_temporary_policy_targets SET policy_version=sequence+1 WHERE run_id=$1 AND phase='cleanup'`} {
			before := orderedCleanupSnapshot(t, ctx, owner, r)
			if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, fault, r); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{action.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			_, callErr := orderedProgressionCall(ctx, owner, "cleanup", orderedCleanupRequest(o, w, e, r, steps[0], "heartbeat", 10, 4, 1))
			if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
			if callErr == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
				t.Fatal("SQL returned undecodable target authority", callErr)
			}
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
		faults := map[string]string{
			"owner_snapshot":     `UPDATE zasp_sa_multistep_prior.cleanups SET snapshot=jsonb_set(snapshot,'{effect,outcome_id}','"invalid"') WHERE run_id=$1`,
			"owner_version":      `UPDATE zasp_sa_multistep_prior.cleanups SET version=version+1 WHERE run_id=$1`,
			"owner_lease":        `UPDATE zasp_sa_multistep_prior.cleanups SET lease_token='different-cleanup-token' WHERE run_id=$1`,
			"effect_input":       `UPDATE zasp_security_agent_effects SET input_digest=decode(repeat('cd',32),'hex') WHERE run_id=$1 AND action_key='create_temporary_policy'`,
			"application_result": `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('cd',32),'hex') WHERE run_id=$1 AND action_key='create_temporary_policy'`,
			"application_source": `UPDATE zasp_security_agent_temporary_policy_targets SET policies='[]' WHERE run_id=$1 AND phase='apply'`,
			"control_state":      `UPDATE zasp_security_agent_controls SET state='disabled' WHERE run_id=$1`,
			"control_version":    `UPDATE zasp_security_agent_controls SET version=version+1 WHERE run_id=$1`,
			"test_step_state":    `UPDATE zasp_security_agent_steps SET state='failed' WHERE run_id=$1 AND step_index=1`,
			"test_effect_state":  `UPDATE zasp_security_agent_effects SET state='unknown_outcome' WHERE run_id=$1 AND action_key='run_test'`,
			"test_effect_result": `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('cd',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
			"test_link_state":    `UPDATE zasp_security_agent_test_links SET reconcile_version=reconcile_version+1 WHERE run_id=$1`,
			"approval_history":   `UPDATE zasp_security_agent_approvals SET state='rejected',version=version+1 WHERE run_id=$1 AND step_id=(SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0)`,
			"source_expiry":      `UPDATE zasp_security_agent_temporary_policy_targets SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND phase='cleanup'`,
			"generation":         `UPDATE zasp_policy_deployment_work SET desired_generation=desired_generation+1 WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
			"readiness":          `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
			"credential":         `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
			"device":             `UPDATE zasp_gateway_devices SET state='revoked',revoked_at=clock_timestamp() WHERE id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
		}
		for _, mode := range []string{"owner_snapshot", "owner_version", "owner_lease", "effect_input", "application_result", "application_source", "control_state", "control_version", "test_step_state", "test_effect_state", "test_effect_result", "test_link_state", "approval_history", "source_expiry", "generation", "readiness", "credential", "device", "stale_run", "stale_effect", "wrong_step", "cross_tenant"} {
			t.Run(mode, func(t *testing.T) {
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				if fault := faults[mode]; fault != "" {
					if _, err := owner.Exec(ctx, fault, r); err != nil {
						t.Fatal("negative fixture", mode, err)
					}
				}
				q := cloneOrderedApplicationRequest(t, complete)
				switch mode {
				case "stale_run":
					q["run_version"] = 9
				case "stale_effect":
					q["effect_version"] = 4
				case "wrong_step":
					q["step_id"] = steps[1]
				case "cross_tenant":
					q["organization_id"] = "pid_8f000002-0000-4000-8000-000000000001"
				}
				// Negative/fault-only transaction. Execute as the real registered
				// principal; no owner-created row supplies completion evidence.
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{action.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				got, callErr := orderedProgressionCall(ctx, owner, "cleanup", q)
				if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				if callErr == nil {
					t.Fatal("changed cleanup authority accepted", mode, got)
				}
				if orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("negative fixture escaped rollback", mode)
				}
			})
		}
		got, err := orderedCleanupCall(ctx, action, complete, keys)
		if err != nil {
			t.Fatal("exact completion after negative matrix", err)
		}
		orderedCleanupResponseRefusals(t, ctx, complete, got, keys)
		orderedCleanupMaximumResponse(t, ctx, complete, got)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		for _, sql := range []string{`UPDATE zasp_sa_multistep_prior.cleanup_receipts SET body='{}' WHERE run_id=$1`, `DELETE FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1`} {
			if _, err := owner.Exec(ctx, sql, r); err == nil {
				t.Fatal("mutable cleanup evidence", sql)
			}
		}
		if orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("typed evidence mutation committed")
		}
	})
}
