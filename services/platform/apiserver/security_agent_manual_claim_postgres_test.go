package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// An invalid manual candidate must not roll back an earlier healthy claim or
// prevent later same-tenant and cross-tenant work. Its accounting is not erased.
func TestSecurityAgentManualClaimIsolationPostgres(t *testing.T) {
	for _, scenario := range []string{"revoked_requester", "disabled_control", "changed_definition", "reclaimed_accounting", "post_write_permission_loss", "expired_test_binding", "missing_attack_lab_proof", "missing_manual_receipt"} {
		t.Run(scenario, func(t *testing.T) {
			action := "create_evidence_export"
			if scenario == "expired_test_binding" {
				action = "run_test"
			}
			if scenario == "missing_attack_lab_proof" {
				action = "start_attack_lab"
			}
			runManualAdmissionFixture(t, action, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID string, actor, definition string, version int64) {
				const invalid = "pid_8e1a0001-0000-4000-8000-000000000001"
				const first = "pid_8e1a0002-0000-4000-8000-000000000002"
				const last = "pid_8e1a0003-0000-4000-8000-000000000003"
				const foreign = "pid_8e1a0004-0000-4000-8000-000000000004"
				const otherOrg = "pid_9a000001-0000-4000-8000-000000000001"
				var raw json.RawMessage
				if scenario == "missing_attack_lab_proof" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET safety=jsonb_set(safety,'{credential_class}','"test_write"') WHERE organization_id=$1;
 UPDATE zasp_attack_lab_credential_bindings SET credential_class='test_write' WHERE organization_id=$1;
 INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) VALUES($1,$2,$3,'pid_8e1a0005-0000-4000-8000-000000000005',$4,1,$5,'complete',1,digest('manual-source','sha256'),'fail','s3://fixture-bucket/manual-source','manual-source','source-version',digest('evidence','sha256'),100,clock_timestamp());
 INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'controlled objective','controlled failure','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM zasp_red_team_runs WHERE run_id='pid_8e1a0005-0000-4000-8000-000000000005'`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID, actor); err != nil {
						t.Fatal(err)
					}
				}
				if err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-claim-isolation-01", version, invalid, invalid, invalid, invalid, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				var retained string
				if scenario == "reclaimed_accounting" {
					if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 120, 1).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					if _, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest) SELECT organization_id,workspace_id,environment_id,run_id,attempt,'retained-manual-accounting',digest('input','sha256'),'retained-model','retained-cost','openrouter_credit',10,10,lease_owner,digest(lease_token,'sha256') FROM zasp_security_agent_runs WHERE run_id=$1; UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, invalid); err != nil {
						t.Fatal(err)
					}
					if err = owner.QueryRow(ctx, `SELECT jsonb_build_object('budget',to_jsonb(b),'reservation',to_jsonb(p))::text FROM zasp_security_agent_run_budgets b JOIN zasp_security_agent_provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE run_id=$1`, invalid).Scan(&retained); err != nil {
						t.Fatal(err)
					}
				}
				// Legacy ProductID candidates intentionally have no manual receipt.
				// Their existing contract must survive the new manual authority check.
				if _, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,available_at)
 SELECT organization_id,workspace_id,environment_id,$2,definition_id,version,$2,'legacy-fixture','queued',clock_timestamp()-interval '3 minutes' FROM zasp_security_agent_definitions WHERE definition_id=$1 AND organization_id=$7;
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,available_at)
 SELECT organization_id,workspace_id,environment_id,$3,definition_id,version,$3,'legacy-fixture','queued',clock_timestamp()-interval '1 minute' FROM zasp_security_agent_definitions WHERE definition_id=$1 AND organization_id=$7;
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,available_at)
 SELECT organization_id,workspace_id,environment_id,$4,definition_id,version,$4,'legacy-fixture','queued',clock_timestamp()-interval '1 minute' FROM zasp_security_agent_definitions WHERE organization_id=$5;
 UPDATE zasp_security_agent_runs SET available_at=clock_timestamp()-interval '2 minutes' WHERE run_id=$6`, pgx.QueryExecModeSimpleProtocol, definition, first, last, foreign, otherOrg, invalid, o); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "revoked_requester", "reclaimed_accounting":
					_, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, actor, o)
				case "disabled_control":
					_, err = owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'create_evidence_export')`, o, w, e)
				case "changed_definition":
					_, err = owner.Exec(ctx, `UPDATE zasp_security_agent_definition_versions SET definition_digest=digest('changed','sha256') WHERE definition_id=$1`, definition)
				case "expired_test_binding":
					_, err = owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings SET valid_until=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, o)
				case "missing_attack_lab_proof":
					_, err = owner.Exec(ctx, `UPDATE zasp_red_team_runs SET verdict='pass' WHERE run_id='pid_8e1a0005-0000-4000-8000-000000000005'`)
				case "missing_manual_receipt":
					_, err = owner.Exec(ctx, `DELETE FROM zasp_security_agent_request_receipts WHERE response->>'id'=$1`, invalid)
				case "post_write_permission_loss":
					// A fixture-only trigger makes revocation happen after provisional
					// lease writes, so only the second check and rollback can catch it.
					_, err = owner.Exec(ctx, `CREATE FUNCTION public.manual_claim_test_revoke() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $trigger$ BEGIN UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=NEW.requested_by AND organization_id=NEW.organization_id; RETURN NEW; END $trigger$;
 CREATE TRIGGER manual_claim_test_revoke AFTER UPDATE ON zasp_security_agent_runs FOR EACH ROW WHEN(NEW.run_id='pid_8e1a0001-0000-4000-8000-000000000001' AND NEW.state='planning') EXECUTE FUNCTION public.manual_claim_test_revoke()`)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, "manual-isolation-next-lease", 120, 25).Scan(&raw); err != nil {
					t.Fatalf("invalid manual candidate aborted healthy claim batch: %v", err)
				}
				var claims struct {
					Items []struct {
						RunID          string `json:"run_id"`
						OrganizationID string `json:"organization_id"`
					} `json:"items"`
				}
				if err = json.Unmarshal(raw, &claims); err != nil {
					t.Fatal(err)
				}
				if len(claims.Items) != 3 || claims.Items[0].RunID != first || claims.Items[1].RunID != last || claims.Items[2].RunID != foreign || claims.Items[2].OrganizationID != otherOrg {
					t.Fatalf("healthy claim order/progress lost: %s", raw)
				}
				var committed int
				if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=ANY($1::text[]) AND r.state='planning' AND r.attempt=1 AND r.lease_token='manual-isolation-next-lease' AND b.stop_reason IS NULL`, []string{first, last, foreign}).Scan(&committed); err != nil || committed != 3 {
					t.Fatalf("healthy claims did not commit: %d %v", committed, err)
				}
				var stopped bool
				attempt := 0
				if scenario == "reclaimed_accounting" {
					attempt = 1
				}
				if err = owner.QueryRow(ctx, `SELECT state='needs_human' AND last_error_code='manual_authority_unavailable' AND attempt=$2 AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, invalid, attempt).Scan(&stopped); err != nil || !stopped {
					t.Fatalf("invalid candidate retained authority: %v %v", stopped, err)
				}
				if retained != "" {
					var after string
					if err = owner.QueryRow(ctx, `SELECT jsonb_build_object('budget',to_jsonb(b),'reservation',to_jsonb(p))::text FROM zasp_security_agent_run_budgets b JOIN zasp_security_agent_provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE run_id=$1`, invalid).Scan(&after); err != nil || after != retained {
						t.Fatalf("retained accounting changed: %s -> %s: %v", retained, after, err)
					}
				} else {
					var count int
					if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_run_budgets WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE run_id=$1)`, invalid).Scan(&count); err != nil || count != 0 {
						t.Fatalf("invalid provisional budget/permit survived: %d %v", count, err)
					}
				}
				if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, "manual-isolation-last-lease", 120, 25).Scan(&raw); err != nil || string(raw) != "{\"items\": []}" {
					t.Fatalf("invalid candidate re-entered claim: %s %v", raw, err)
				}
				if scenario != "changed_definition" && scenario != "missing_manual_receipt" {
					if err = api.QueryRow(ctx, `SELECT zasp_security_agent_run_detail_v24($1,$2,$3,$4)`, o, w, e, invalid).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					var detail map[string]json.RawMessage
					if json.Unmarshal(raw, &detail) != nil || detail["budget_stop_reason"] != nil {
						t.Fatalf("authority stop leaked into closed budget reasons: %s", raw)
					}
				}
				if scenario == "revoked_requester" {
					// Do not swallow unknown readiness or infrastructure errors even
					// when they originate within the marked manual check.
					for _, code := range []string{"55000", "42501", "40001"} {
						if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='queued' WHERE run_id=$1`, invalid); err != nil {
							t.Fatal(err)
						}
						if _, err = owner.Exec(ctx, fmt.Sprintf(`CREATE OR REPLACE FUNCTION public.zasp_sa_manual_recheck(o text,w text,e text,r text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $test$ BEGIN RAISE EXCEPTION USING ERRCODE='%s',MESSAGE='unexpected database failure'; END $test$`, code)); err != nil {
							t.Fatal(err)
						}
						if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, "manual-isolation-error-lease", 120, 25).Scan(&raw); err == nil {
							t.Fatalf("unexpected %s swallowed", code)
						}
						var unchanged bool
						if err = owner.QueryRow(ctx, `SELECT state='queued' AND attempt=0 AND lease_token IS NULL FROM zasp_security_agent_runs WHERE run_id=$1`, invalid).Scan(&unchanged); err != nil || !unchanged {
							t.Fatalf("unexpected error persisted claim state: %v %v", unchanged, err)
						}
					}
				}
				t.Log(fmt.Sprintf("%s: earlier, later and foreign claims retained; invalid candidate stopped without new authority", scenario))
			})
		})
	}
}
