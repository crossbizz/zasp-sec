package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func orderedTestTerminalReplayRefusals(t *testing.T, ctx context.Context, owner *pgx.Conn, r, s string, raw json.RawMessage, settled bool, expiry ...bool) {
	t.Helper()
	var request orderedTestAction
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("replay request")
	}
	var inputManifest, outputManifest json.RawMessage
	var inputBody, outputBody []byte
	if settled {
		if err := owner.QueryRow(ctx, `SELECT i.manifest,i.body,s.output_manifest,s.output_body FROM zasp_sa_multistep_prior.test_inputs i JOIN zasp_sa_multistep_prior.test_settlements s USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE i.run_id=$1`, r).Scan(&inputManifest, &inputBody, &outputManifest, &outputBody); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"effect_missing", "effect_input", "effect_attempt", "effect_outcome", "effect_result", "effect_lease", "child_version", "child_cancel", "child_verdict", "child_artifact", "link_input", "link_reconcile", "link_response"} {
		if !settled && (mode == "child_verdict" || mode == "child_artifact" || mode == "link_response") {
			continue
		}
		t.Run("terminal_"+mode, func(t *testing.T) {
			fault := map[string]string{
				"effect_missing": `DELETE FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='run_test'`,
				"effect_input":   `UPDATE zasp_security_agent_effects SET input_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
				"effect_attempt": `UPDATE zasp_security_agent_effects SET attempt=attempt+1 WHERE run_id=$1 AND action_key='run_test'`,
				"effect_outcome": `UPDATE zasp_security_agent_effects SET outcome_id='foreign' WHERE run_id=$1 AND action_key='run_test'`,
				"effect_result":  `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
				"effect_lease":   `UPDATE zasp_security_agent_effects SET lease_owner='foreign',lease_token=repeat('b',32),lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1 AND action_key='run_test'`,
				"child_version":  `UPDATE zasp_red_team_runs SET version=version+1 WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"child_cancel":   `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"child_verdict":  `UPDATE zasp_red_team_runs SET verdict='fail' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"child_artifact": `UPDATE zasp_red_team_runs SET evidence_version_id='foreign' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"link_input":     `UPDATE zasp_security_agent_test_links SET input_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1`,
				"link_reconcile": `UPDATE zasp_security_agent_test_links SET reconcile_version=reconcile_version+1 WHERE run_id=$1`,
				"link_response":  `UPDATE zasp_security_agent_test_links SET reconcile_settlement=jsonb_set(reconcile_settlement,'{outcome}','"reproduced"') WHERE run_id=$1`,
			}[mode]
			if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
				t.Fatal(err)
			}
			defer owner.Exec(ctx, `ROLLBACK`)
			if _, err := owner.Exec(ctx, fault, r); err != nil {
				if mode == "effect_missing" && strings.Contains(err.Error(), "SQLSTATE 23503") {
					if _, err = owner.Exec(ctx, `ROLLBACK`); err != nil {
						t.Fatal(err)
					}
					return
				}
				t.Fatal(err)
			}
			before := orderedTestSnapshot(t, ctx, owner, r)
			role := "ordered_test_red_worker"
			if len(expiry) > 0 && expiry[0] {
				role = "security_agent_v33_worker_login"
			}
			if _, err := owner.Exec(ctx, `SAVEPOINT attempt;SET SESSION AUTHORIZATION `+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			var response json.RawMessage
			var callErr error
			if settled {
				callErr = owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), request.OrganizationID, request.WorkspaceID, request.EnvironmentID, r, s, request.WorkerID, request.LeaseToken, request.RunVersion, request.EffectVersion, inputManifest, inputBody, outputManifest, outputBody).Scan(&response)
			} else if len(expiry) > 0 && expiry[0] {
				callErr = owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_reconcile_uncertain($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response)
			} else {
				callErr = owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_uncertain($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response)
			}
			if _, err := owner.Exec(ctx, `ROLLBACK TO SAVEPOINT attempt`); err != nil {
				t.Fatal(err)
			}
			if callErr == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("terminal replay accepted drift", mode, callErr)
			}
			if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
		})
	}
}
