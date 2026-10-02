package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catch source-free admission that fabricates provenance, duplicates a run on
// retry, or borrows a revoked requester's authority. Only definition/control
// prerequisites are owner-seeded; API authority must create every run/receipt.
func runManualAdmissionFixture(t *testing.T, action string, exercise func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string, string, int64)) {
	t.Helper()
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID string, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		if _, err := owner.Exec(ctx, `
 UPDATE zasp_security_agent_definitions SET activation='supervised',body=(body-'existing_test')||jsonb_build_object('enabled',true,'autonomy','supervised','allowed_actions',jsonb_build_array('create_evidence_export'),'verification_kind','export','concurrency_limit',10,'max_ai_cost_nano_credits',1000000) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$4 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'manual-admission-org','manual-admission-actor','security_admin',true) ON CONFLICT(principal_id,organization_id) DO UPDATE SET active=true,role=excluded.role;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Manual admission','["view","manage_workflows","view_audit"]') ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions=excluded.permissions;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',true,$4) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		var definition, scheduledKind string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT definition_id,version,body->>'trigger_kind' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&definition, &version, &scheduledKind); err != nil {
			t.Fatal(err)
		}
		if action != "create_evidence_export" {
			verification := map[string]string{"run_test": "test_run", "rerun_test": "test_run", "start_attack_lab": "attack_lab_run", "update_finding_response": "finding_state", "create_temporary_policy": "policy_state", "isolate_session": "session_state", "revoke_integration_connection": "integration_state"}[action]
			if verification == "" {
				t.Fatalf("unknown manual fixture action %s", action)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$4;
 UPDATE zasp_security_agent_definitions SET body=body||jsonb_build_object('allowed_actions',jsonb_build_array($5::text),'verification_kind',$6::text)||CASE WHEN $5 IN('run_test','rerun_test','start_attack_lab') THEN jsonb_build_object('existing_test',jsonb_build_object('definition_id',$4::text,'definition_version',1)) ELSE '{}'::jsonb END WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 UPDATE zasp_security_agent_definition_versions v SET definition=d.body,definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d WHERE (v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) AND d.organization_id=$1;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,$5,true,$7) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID, action, verification, actor); err != nil {
				t.Fatal(err)
			}
		}
		exercise(ctx, owner, api, o, w, e, testID, actor, definition, version)
	})
}

func TestSecurityAgentManualAdmissionPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor, definition string, version int64) {
		var scheduledKind string
		if err := owner.QueryRow(ctx, `SELECT body->>'trigger_kind' FROM zasp_security_agent_definitions WHERE definition_id=$1`, definition).Scan(&scheduledKind); err != nil {
			t.Fatal(err)
		}
		counts := func() [4]int {
			t.Helper()
			var count [4]int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_request_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_audit WHERE organization_id=$1)`, o).Scan(&count[0], &count[1], &count[2], &count[3]); err != nil {
				t.Fatal(err)
			}
			return count
		}
		if initial := counts(); initial != [4]int{} {
			t.Fatalf("manual admission fixture already has execution authority: %v", initial)
		}
		const run = "pid_8e190001-0000-4000-8000-000000000001"
		const replacement = "pid_8e190002-0000-4000-8000-000000000002"
		const audit = "pid_8e190003-0000-4000-8000-000000000003"
		const correlation = "pid_8e190004-0000-4000-8000-000000000004"
		const receipt = "pid_8e190005-0000-4000-8000-000000000005"
		invoke := func(env, key, runID, auditID, receiptID string, expected int64) (SecurityAgentRunResult, error) {
			var raw json.RawMessage
			err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, env, definition, actor, key, expected, runID, auditID, correlation, receiptID, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
			var value SecurityAgentRunResult
			if err == nil {
				err = json.Unmarshal(raw, &value)
			}
			return value, err
		}
		value, err := invoke(e, "manual-admission-0001", run, audit, receipt, version)
		if err != nil {
			t.Fatalf("registered manual admission: %v", err)
		}
		if !validSecurityAgentRunResult(value, SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: version, TriggerKind: "manual"}) || value.ID != run || value.Replayed || value.AuditID != audit || value.ReceiptID != receipt || value.State != "queued" {
			t.Fatalf("invalid admitted manual result: %#v", value)
		}
		if got := counts(); got != [4]int{1, 1, 1, 1} {
			t.Fatalf("admission not atomic/singular: %v", got)
		}
		var bound bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs r JOIN zasp_security_agent_trigger_receipts t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id,r.trigger_id) JOIN zasp_security_agent_request_receipts q ON (q.organization_id,q.workspace_id,q.environment_id,q.principal_id,q.resource_id,q.operation,q.idempotency_key)=(r.organization_id,r.workspace_id,r.environment_id,r.requested_by,r.definition_id,'runSecurityAgent','manual-admission-0001') WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.requested_by) = ($1,$2,$3,$4,$5) AND t.trigger_kind='manual' AND t.trigger_version=1 AND t.trigger_id=encode(t.trigger_digest,'hex') AND 'sha256:'||t.trigger_id=$6 AND q.response->>'id'=r.run_id AND q.response->'manual_trigger'->>'intent_digest'=$6) AND EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE definition_id=$7 AND body->>'trigger_kind'=$8)`, o, w, e, run, actor, value.ManualTrigger.IntentDigest, definition, scheduledKind).Scan(&bound); err != nil || !bound {
			t.Fatalf("original scoped manual intent not bound: %v %v", bound, err)
		}
		replayed, err := invoke(e, "manual-admission-0001", replacement, replacement, replacement, version)
		if err != nil || !replayed.Replayed || replayed.ID != run || replayed.AuditID != audit || replayed.ReceiptID != receipt || !sameSecurityAgentManualTrigger(replayed.ManualTrigger, value.ManualTrigger) {
			t.Fatalf("lost reply changed authority: %#v %v", replayed, err)
		}
		refuse := func(label, env, key string, v int64) {
			t.Helper()
			before := counts()
			if _, err := invoke(env, key, replacement, replacement, replacement, v); err == nil {
				t.Fatalf("%s admitted", label)
			}
			if after := counts(); after != before {
				t.Fatalf("%s left writes: %v -> %v", label, before, after)
			}
		}
		refuse("changed-version replay", e, "manual-admission-0001", version+1)
		refuse("foreign scope", replacement, "manual-admission-0002", version)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		refuse("revoked requester replay", e, "manual-admission-0001", version)
		refuse("revoked requester new intent", e, "manual-admission-0002", version)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		next, err := invoke(e, "manual-admission-0002", replacement, replacement, replacement, version)
		if err != nil || next.ManualTrigger == nil || next.ManualTrigger.IntentDigest == value.ManualTrigger.IntentDigest || !strings.HasPrefix(next.ManualTrigger.IntentDigest, "sha256:") {
			t.Fatalf("new explicit intent did not get distinct receipt: %#v %v", next, err)
		}
		if got := counts(); got != [4]int{2, 2, 2, 2} {
			t.Fatalf("replay/refusal duplicated admission: %v", got)
		}
		assertManualExportConnected(t, ctx, owner, api, o, w, e, run, value.ManualTrigger)
	})
}

// Catch digest-as-ProductID projection, a claim missing its original receipt,
// or preparation that loses the manual binding after real provider accounting.
func assertManualExportConnected(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, run string, manual *SecurityAgentManualTrigger) {
	t.Helper()
	var raw json.RawMessage
	if err := api.QueryRow(ctx, `SELECT zasp_security_agent_run_page($1,$2,$3,NULL,NULL,NULL,NULL,10)`, o, w, e).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items []SecurityAgentRunResult `json:"items"`
	}
	if json.Unmarshal(raw, &page) != nil || len(page.Items) != 2 {
		t.Fatalf("manual page: %s", raw)
	}
	for _, item := range page.Items {
		if item.ManualTrigger == nil || item.EvidenceIDs == nil || len(item.EvidenceIDs) != 0 {
			t.Fatalf("manual page fabricated evidence: %s", raw)
		}
	}
	cfg := owner.Config().Copy()
	cfg.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 120, 2).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Items []struct {
			RunID     string                      `json:"run_id"`
			TriggerID string                      `json:"trigger_id"`
			Manual    *SecurityAgentManualTrigger `json:"manual_trigger"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &claims) != nil || len(claims.Items) != 2 {
		t.Fatalf("manual claims=%s", raw)
	}
	for _, item := range claims.Items {
		if item.Manual == nil || "sha256:"+item.TriggerID != item.Manual.IntentDigest {
			t.Fatalf("claim lost manual provenance: %s", raw)
		}
	}
	if err = worker.QueryRow(ctx, postgresSecurityAgentExportPlannerContextSQL, o, w, e, run, exportFixtureWorker, exportFixtureLease).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Context struct {
			Run struct {
				Manual *SecurityAgentManualTrigger `json:"manual_trigger"`
			} `json:"run"`
			Selection []SecurityAgentExportSelection `json:"export_selection"`
		} `json:"context"`
		Input string `json:"input_digest"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !sameSecurityAgentManualTrigger(envelope.Context.Run.Manual, manual) || len(envelope.Context.Selection) < 1 || envelope.Context.Selection[0].Kind != "manual" || envelope.Context.Selection[0].ID != strings.TrimPrefix(manual.IntentDigest, "sha256:") {
		t.Fatalf("manual planner context=%s", raw)
	}
	input := strings.TrimPrefix(envelope.Input, "sha256:")
	output := strings.Repeat("bf", 32)
	if err = worker.QueryRow(ctx, `SELECT zasp_sa_export_reserve_planner($1,$2,$3,$4,$5,$6,1,'manual-planner-reservation',decode($7,'hex'),'fixture-model','fixture-cost-policy','openrouter_credit',50,100)`, o, w, e, run, exportFixtureWorker, exportFixtureLease, input).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err = worker.QueryRow(ctx, `SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,1,'manual-planner-reservation',decode($7,'hex'),0,0,0,0)`, o, w, e, run, exportFixtureWorker, exportFixtureLease, output).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Export original manual intent", "steps": []any{map[string]any{"index": 0, "action": "create_evidence_export", "target_id": run, "evidence_ids": envelope.Context.Selection[:1]}}})
	if err = worker.QueryRow(ctx, `SELECT zasp_sa_export_accept_planner($1,$2,$3,$4,$5,$6,decode($7,'hex'),decode($8,'hex'),'fixture-model','planner-v1',$9,$10,$11,'pid_8e190011-0000-4000-8000-000000000011','pid_8e190012-0000-4000-8000-000000000012')`, o, w, e, run, exportFixtureWorker, exportFixtureLease, input, output, candidate, exportApprovalID, time.Now().UTC().Add(5*time.Minute)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"waiting_approval"`) {
		t.Fatalf("manual acceptance=%s", raw)
	}
	if err = api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`, o, w, e, run, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var envelopeDetail struct {
		Detail struct {
			Run       SecurityAgentRunResult `json:"run"`
			Evidence  []string               `json:"evidence_ids"`
			Approvals []struct {
				Manual   *SecurityAgentManualTrigger `json:"manual_trigger"`
				Evidence []string                    `json:"evidence_summary"`
			} `json:"approvals"`
		} `json:"detail"`
	}
	if json.Unmarshal(raw, &envelopeDetail) != nil {
		t.Fatal(string(raw))
	}
	detail := envelopeDetail.Detail
	if !sameSecurityAgentManualTrigger(detail.Run.ManualTrigger, manual) || detail.Evidence == nil || len(detail.Evidence) != 0 || len(detail.Approvals) != 1 || !sameSecurityAgentManualTrigger(detail.Approvals[0].Manual, manual) || detail.Approvals[0].Evidence == nil || len(detail.Approvals[0].Evidence) != 0 {
		t.Fatalf("manual context/detail=%s", raw)
	}
	var planEvidence json.RawMessage
	if err = owner.QueryRow(ctx, `SELECT plan->'evidence_ids' FROM zasp_security_agent_plans WHERE run_id=$1`, run).Scan(&planEvidence); err != nil || string(planEvidence) != "[]" {
		t.Fatalf("manual plan evidence=%s %v", planEvidence, err)
	}
	f := &exportDBFixture{ctx: ctx, owner: owner, api: api, worker: worker, o: o, w: w, e: e}
	if raw, err = readExportApproval(f); err != nil {
		t.Fatal(err)
	}
	if _, err = decodeApprovalContextEnvelope(raw, exportApprovalID); err != nil {
		t.Fatalf("manual independent approval: %s %v", raw, err)
	}
	if _, err = owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'manual-approver-org','manual-approver','security_engineer',true); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Manual approver','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, exportApproverID); err != nil {
		t.Fatal(err)
	}
	if raw, err = decideExportApproval(f, exportApproverID, "manual-export-approval", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var decided struct {
		Manual   *SecurityAgentManualTrigger `json:"manual_trigger"`
		Evidence []string                    `json:"evidence_summary"`
	}
	if json.Unmarshal(raw, &decided) != nil || !sameSecurityAgentManualTrigger(decided.Manual, manual) || decided.Evidence == nil || len(decided.Evidence) != 0 {
		t.Fatalf("manual decision lost provenance=%s", raw)
	}
	if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 120, 2).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw, err = f.dispatch(o, w, e, run, exportFixtureLease); err != nil {
		t.Fatal(err)
	}
	var dispatched struct {
		ExportID string `json:"export_id"`
	}
	if json.Unmarshal(raw, &dispatched) != nil || dispatched.ExportID == "" {
		t.Fatal(string(raw))
	}
	captured := f.capture(t, dispatched.ExportID)
	if !strings.Contains(string(captured), `"manual"`) || !strings.Contains(string(captured), manual.IntentDigest) {
		t.Fatalf("capture lost original manual receipt=%s", captured)
	}
}

func TestSecurityAgentManualActionPrerequisitesPostgres(t *testing.T) {
	for _, action := range []string{"run_test", "rerun_test", "start_attack_lab", "update_finding_response", "create_temporary_policy", "isolate_session", "revoke_integration_connection"} {
		t.Run(action, func(t *testing.T) {
			runManualAdmissionFixture(t, action, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor, definition string, version int64) {
				const run = "pid_8e191001-0000-4000-8000-000000000001"
				const audit = "pid_8e191002-0000-4000-8000-000000000002"
				var raw json.RawMessage
				invoke := func() error {
					return api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-action-bound-0001", version, run, audit, audit, audit, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
				}
				if action == "start_attack_lab" {
					if err := invoke(); err == nil {
						t.Fatal("manual attack lab admitted without retained failed proof")
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET safety=jsonb_set(safety,'{credential_class}','"test_write"') WHERE organization_id=$1;
 UPDATE zasp_attack_lab_credential_bindings SET credential_class='test_write' WHERE organization_id=$1;
 INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) VALUES($1,$2,$3,'pid_8e191003-0000-4000-8000-000000000003',$4,1,$5,'complete',1,digest('manual-source','sha256'),'fail','s3://fixture-bucket/manual-source','manual-source','source-version',digest('evidence','sha256'),100,clock_timestamp());
 INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'controlled objective','controlled failure','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM zasp_red_team_runs WHERE run_id='pid_8e191003-0000-4000-8000-000000000003'`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID, actor); err != nil {
						t.Fatal(err)
					}
				}
				err := invoke()
				if action != "run_test" && action != "rerun_test" && action != "start_attack_lab" {
					if err == nil {
						t.Fatal("manual action fabricated missing source")
					}
					var count int
					if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs)+(SELECT count(*) FROM zasp_security_agent_trigger_receipts)+(SELECT count(*) FROM zasp_security_agent_request_receipts)+(SELECT count(*) FROM zasp_security_agent_audit)`).Scan(&count); err != nil || count != 0 {
						t.Fatalf("refused prerequisite left authority: %d %v", count, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("bound manual %s: %v", action, err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 120, 1).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				prefix := "zasp_production_security_agent_existing_tests_"
				if action == "start_attack_lab" {
					prefix = "zasp_sa_attack_lab_"
				}
				if err = worker.QueryRow(ctx, fmt.Sprintf(`SELECT %splanner_context($1,$2,$3,$4,$5,$6)`, prefix), o, w, e, run, exportFixtureWorker, exportFixtureLease).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var contextValue struct {
					Context struct {
						Run struct {
							Manual *SecurityAgentManualTrigger `json:"manual_trigger"`
						} `json:"run"`
						Targets []string `json:"allowed_targets"`
					} `json:"context"`
				}
				if json.Unmarshal(raw, &contextValue) != nil || contextValue.Context.Run.Manual == nil || len(contextValue.Context.Targets) != 1 || contextValue.Context.Targets[0] != testID {
					t.Fatalf("bound target/manual context=%s", raw)
				}
				// Deterministic prepare remains provider-free. The parent and proof
				// receipts are real, no plan/step/provider state has been seeded.
				if err = worker.QueryRow(ctx, fmt.Sprintf(`SELECT %sprepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, prefix), o, w, e, run, exportFixtureWorker, exportFixtureLease, exportApprovalID, time.Now().UTC().Add(5*time.Minute), "pid_8e191004-0000-4000-8000-000000000004", "pid_8e191005-0000-4000-8000-000000000005").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), `"waiting_approval"`) {
					t.Fatal(string(raw))
				}
				var evidence json.RawMessage
				if err = owner.QueryRow(ctx, `SELECT plan->'evidence_ids' FROM zasp_security_agent_plans WHERE run_id=$1`, run).Scan(&evidence); err != nil || string(evidence) != "[]" {
					t.Fatalf("manual plan=%s %v", evidence, err)
				}
				if err = api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`, o, w, e, run, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil || !strings.Contains(string(raw), `"manual_trigger"`) {
					t.Fatalf("manual bound public context=%s %v", raw, err)
				}
			})
		})
	}
}

func TestSecurityAgentManualIntegrityPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "run_test", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor, definition string, version int64) {
		const run = "pid_8e192001-0000-4000-8000-000000000001"
		var raw json.RawMessage
		if err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-integrity-0001", version, run, run, run, run, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var admitted SecurityAgentRunResult
		if json.Unmarshal(raw, &admitted) != nil {
			t.Fatal(string(raw))
		}
		var intent, response json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT intent,response FROM zasp_security_agent_request_receipts WHERE receipt_id=$1`, run).Scan(&intent, &response); err != nil {
			t.Fatal(err)
		}
		read := func() error {
			return api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`, o, w, e, run, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
		}
		if err := read(); err != nil {
			t.Fatal(err)
		}
		for _, probe := range []struct{ name, change, restore string }{
			{"borrowed_product_id", `UPDATE zasp_security_agent_runs SET trigger_id='pid_8e192002-0000-4000-8000-000000000002' WHERE run_id=$1`, `UPDATE zasp_security_agent_runs SET trigger_id=(SELECT trigger_id FROM zasp_security_agent_trigger_receipts WHERE run_id=$1) WHERE run_id=$1`},
			{"version", `UPDATE zasp_security_agent_trigger_receipts SET trigger_version=2 WHERE run_id=$1`, `UPDATE zasp_security_agent_trigger_receipts SET trigger_version=1 WHERE run_id=$1`},
			{"digest", `UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=decode(repeat('aa',32),'hex') WHERE run_id=$1`, `UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=decode(trigger_id,'hex') WHERE run_id=$1`},
			{"intent", `UPDATE zasp_security_agent_request_receipts SET intent=intent||'{"environment_id":"pid_8e192002-0000-4000-8000-000000000002"}' WHERE receipt_id=$1`, `UPDATE zasp_security_agent_request_receipts SET intent=$2 WHERE receipt_id=$1`},
			{"response", `UPDATE zasp_security_agent_request_receipts SET response=response||'{"evidence_ids":["pid_8e192002-0000-4000-8000-000000000002"]}' WHERE receipt_id=$1`, `UPDATE zasp_security_agent_request_receipts SET response=$2 WHERE receipt_id=$1`},
			{"original_definition", `UPDATE zasp_security_agent_definition_versions SET definition_digest=decode(repeat('aa',32),'hex') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, `UPDATE zasp_security_agent_definition_versions SET definition_digest=digest(convert_to(definition::text,'UTF8'),'sha256') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`},
		} {
			t.Run(probe.name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, probe.change, run); err != nil {
					t.Fatal(err)
				}
				if err := read(); err == nil {
					t.Errorf("%s provenance drift was projected", probe.name)
				}
				args := []any{run}
				if probe.name == "intent" {
					args = append(args, intent)
				}
				if probe.name == "response" {
					args = append(args, response)
				}
				if _, err := owner.Exec(ctx, probe.restore, args...); err != nil {
					t.Fatal(err)
				}
			})
		}
		if err := read(); err != nil {
			t.Fatal(err)
		}
		var catalogOK bool
		if err := owner.QueryRow(ctx, `SELECT p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') AND NOT has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0) FROM pg_proc p WHERE p.oid='public.zasp_sa_manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text)'::regprocedure`).Scan(&catalogOK); err != nil || !catalogOK {
			t.Fatalf("manual registered owner/ACL=%v %v", catalogOK, err)
		}
		if _, err := owner.Exec(ctx, `BEGIN; ALTER FUNCTION public.zasp_sa_manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text) STABLE`); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("manual function drift ignored: %v %v", ready, err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		// No export definition exists here: refusal is specifically retained
		// manual authority, not the already-covered export-history downgrade gate.
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'create_evidence_export')`, o, w, e); err != nil {
			t.Fatal(err)
		}
		var otherHistory bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_sa_export_links) OR EXISTS(SELECT 1 FROM zasp_sa_export_planner_inputs) OR EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE body->'allowed_actions' ? 'create_evidence_export') OR EXISTS(SELECT 1 FROM zasp_security_agent_definition_versions WHERE definition->'allowed_actions' ? 'create_evidence_export') OR EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE action_key='create_evidence_export')`).Scan(&otherHistory); err != nil || otherHistory {
			t.Fatalf("manual downgrade fixture still has export history: %v %v", otherHistory, err)
		}
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentExports(ctx); err == nil {
			t.Fatal("downgrade erased manual provenance support")
		}
		var present bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1) AND to_regprocedure('public.zasp_sa_manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text)') IS NOT NULL`, run).Scan(&present); err != nil || !present {
			t.Fatalf("retained history damaged: %v %v", present, err)
		}
		for _, login := range []string{"security_agent_v33_api_login", "security_agent_v33_worker_login"} {
			cfg := owner.Config().Copy()
			cfg.User = login
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"zasp_sa_manual_provenance", "zasp_sa_manual_fields", "zasp_sa_manual_recheck"} {
				if _, err = conn.Exec(ctx, fmt.Sprintf(`SELECT %s($1,$2,$3,$4)`, name), o, w, e, run); err == nil {
					t.Errorf("%s can call private %s", login, name)
				}
			}
			if login == "security_agent_v33_worker_login" {
				if err = conn.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-integrity-0002", version, run, run, run, run, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err == nil {
					t.Error("worker admitted manual API intent")
				}
			}
			conn.Close(context.Background())
		}
	})
}

func TestSecurityAgentManualConcurrencyPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor, definition string, version int64) {
		cfg := api.Config().Copy()
		second, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close(context.Background())
		blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close(context.Background())
		if _, err = blocker.Exec(ctx, `BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, pgx.QueryExecModeSimpleProtocol, o); err != nil {
			t.Fatal(err)
		}
		type result struct {
			value SecurityAgentRunResult
			err   error
		}
		done := make(chan result, 2)
		for i, conn := range []*pgx.Conn{api, second} {
			go func(i int, conn *pgx.Conn) {
				id := fmt.Sprintf("pid_8e19300%d-0000-4000-8000-000000000001", i+1)
				var raw json.RawMessage
				err := conn.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-concurrent-0001", version, id, id, id, id, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
				var value SecurityAgentRunResult
				if err == nil {
					err = json.Unmarshal(raw, &value)
				}
				done <- result{value, err}
			}(i, conn)
		}
		waitManualLocks(t, ctx, owner, api.PgConn().PID(), second.PgConn().PID())
		if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		first, next := <-done, <-done
		if first.err != nil || next.err != nil || first.value.ID != next.value.ID || first.value.Replayed == next.value.Replayed || !sameSecurityAgentManualTrigger(first.value.ManualTrigger, next.value.ManualTrigger) {
			t.Fatalf("concurrent intent split: %#v %#v", first, next)
		}
		var counts [4]int
		if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs),(SELECT count(*) FROM zasp_security_agent_trigger_receipts),(SELECT count(*) FROM zasp_security_agent_request_receipts),(SELECT count(*) FROM zasp_security_agent_audit)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil || counts != [4]int{1, 1, 1, 1} {
			t.Fatalf("concurrent authority duplicated: %v %v", counts, err)
		}
	})
}

func waitManualLocks(t *testing.T, ctx context.Context, owner *pgx.Conn, pids ...uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, pid := range pids {
			var waiting bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			all = all && waiting
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("manual requests did not reach controlled lock wait")
}

func TestSecurityAgentManualCancelPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor, definition string, version int64) {
		const run = "pid_8e194001-0000-4000-8000-000000000001"
		const audit = "pid_8e194002-0000-4000-8000-000000000002"
		var raw json.RawMessage
		if err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-cancel-admit-0001", version, run, run, run, run, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var original SecurityAgentRunResult
		if json.Unmarshal(raw, &original) != nil {
			t.Fatal(string(raw))
		}
		for i := 0; i < 2; i++ {
			if err := api.QueryRow(ctx, postgresSecurityAgentCancelRunSQL, o, w, e, run, actor, "manual-cancel-bound-0001", 1, audit, audit, audit).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var value SecurityAgentRunResult
			if json.Unmarshal(raw, &value) != nil || value.State != "cancelled" || value.Replayed != (i == 1) || value.EvidenceIDs == nil || len(value.EvidenceIDs) != 0 || !sameSecurityAgentManualTrigger(value.ManualTrigger, original.ManualTrigger) {
				t.Fatalf("manual cancellation/replay lost provenance=%s", raw)
			}
		}
	})
}

func TestSecurityAgentManualPostWaitPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor, definition string, version int64) {
		blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close(context.Background())
		if _, err = blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_security_agent_audit IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var raw json.RawMessage
			done <- api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "manual-postwait-bound-0001", version, "pid_8e195001-0000-4000-8000-000000000001", "pid_8e195002-0000-4000-8000-000000000002", "pid_8e195003-0000-4000-8000-000000000003", "pid_8e195004-0000-4000-8000-000000000004", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
		}()
		waitManualLocks(t, ctx, owner, api.PgConn().PID())
		if _, err = owner.Exec(ctx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		var allowed bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes($4,$1) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND permissions ? 'manage_workflows')`, o, w, e, actor).Scan(&allowed); err != nil || allowed {
			t.Fatalf("effective authority not revoked: %v %v", allowed, err)
		}
		if _, err = blocker.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("manual admission survived permission loss during final write")
		}
		var count int
		if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs)+(SELECT count(*) FROM zasp_security_agent_trigger_receipts)+(SELECT count(*) FROM zasp_security_agent_request_receipts)+(SELECT count(*) FROM zasp_security_agent_audit)`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("post-wait refusal left authority: %d %v", count, err)
		}
	})
}
