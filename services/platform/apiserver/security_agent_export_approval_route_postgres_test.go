package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const exportApprovalID = "pid_8e130009-0000-4000-8000-000000000009"
const exportApproverID = "pid_8e130010-0000-4000-8000-000000000010"

func seedExportPendingApproval(t *testing.T, f *exportDBFixture) {
	t.Helper()
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_definitions SET activation='supervised',body=jsonb_set(body,'{autonomy}','"supervised"') WHERE organization_id=$1;
 UPDATE zasp_security_agent_definition_versions v SET activation=d.activation,definition=d.body,definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d WHERE (v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) AND v.organization_id=$1;
 UPDATE zasp_security_agent_steps SET authorization_result='approval_required',state='waiting_approval' WHERE run_id=$2;
 UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,authorization}','"approval_required"') WHERE run_id=$2`, pgx.QueryExecModeSimpleProtocol, f.o, exportFixtureRun); err != nil {
		t.Fatal(err)
	}
	f.setSelection(t, f.selection)
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state='waiting_approval',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1 WHERE run_id=$4;
 INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) SELECT organization_id,workspace_id,environment_id,$5,run_id,$6,plan_hash,'pending',$7,expires_at FROM zasp_security_agent_plans WHERE run_id=$4;
 INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($8,$1,'export-approval-org','export-approver','security_engineer',true);
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($8,$1,$2,$3,'Export approver','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, exportApprovalID, exportFixtureStep, f.actor, exportApproverID); err != nil {
		t.Fatal(err)
	}
}

func readExportApproval(f *exportDBFixture) (json.RawMessage, error) {
	var raw json.RawMessage
	err := f.api.QueryRow(f.ctx, `SELECT zasp_production_security_agent_existing_tests_approval($1,$2,$3,$4,$5,$6)`, f.o, f.w, f.e, exportApprovalID, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	return raw, err
}

func decideExportApproval(f *exportDBFixture, actor, key string, stamp time.Time) (json.RawMessage, error) {
	var raw json.RawMessage
	err := f.api.QueryRow(f.ctx, `SELECT zasp_production_security_agent_existing_tests_decide_approval($1,$2,$3,$4,$5,$6,1,'approved',$7,'pid_8e130011-0000-4000-8000-000000000011','pid_8e130012-0000-4000-8000-000000000012','pid_8e130013-0000-4000-8000-000000000013',$8,$9)`, f.o, f.w, f.e, exportApprovalID, actor, key, stamp, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	return raw, err
}

func TestSecurityAgentExportApprovalPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		seedExportPendingApproval(t, f)
		raw, err := readExportApproval(f)
		if err != nil {
			t.Fatal(err)
		}
		value, err := decodeApprovalContextEnvelope(raw, exportApprovalID)
		if err != nil || value.ExpectedEffect != "Create run-scoped evidence export" || !value.Reversible || value.TTLSeconds != 0 || value.Context == nil || value.Context.TargetID == nil || *value.Context.TargetID != exportFixtureRun || value.Context.Risk.Class != "low" {
			t.Fatalf("registered export approval projection=%s error=%v", raw, err)
		}
		var selected, want any
		selection, _ := json.Marshal(value.Context.ExportSelection)
		if json.Unmarshal(selection, &selected) != nil || json.Unmarshal(f.selection, &want) != nil || !reflect.DeepEqual(selected, want) || !reflect.DeepEqual(value.EvidenceSummary, []string{exportFixtureFinding}) {
			t.Fatalf("approval replaced original evidence/selection: %s", raw)
		}
		if err = f.api.QueryRow(f.ctx, `SELECT zasp_production_security_agent_existing_tests_approval_page($1,$2,$3,'pending',$4,NULL,NULL,10,$5,$6)`, f.o, f.w, f.e, exportFixtureRun, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		page, err := decodeApprovalContextPage(raw, SecurityAgentApprovalPageRequest{RunID: exportFixtureRun, State: "pending", Limit: 10})
		if err != nil || len(page.Items) != 1 || page.Items[0].ExpectedEffect != value.ExpectedEffect {
			t.Fatalf("export approval page=%s %v", raw, err)
		}
		assertExportProjection(t, f, "")
		before := existingTestAcceptanceSnapshot(t, f.ctx, f.owner, f.o, f.w, f.e, exportFixtureRun)
		if _, err = decideExportApproval(f, f.actor, "export-approval-requester", time.Now().UTC()); err == nil {
			t.Fatal("requester self-approved")
		}
		if _, err = decideExportApproval(f, exportApproverID, "export-approval-stale-auth", time.Now().UTC().Add(-6*time.Minute)); err == nil {
			t.Fatal("stale auth approved")
		}
		if got := existingTestAcceptanceSnapshot(t, f.ctx, f.owner, f.o, f.w, f.e, exportFixtureRun); got != before {
			t.Fatal("refused approval mutated authority")
		}
		raw, err = decideExportApproval(f, exportApproverID, "export-approval-decision", time.Now().UTC())
		var receipt map[string]any
		if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt["expected_effect"] != value.ExpectedEffect || receipt["state"] != "approved" || receipt["reversible"] != true || receipt["ttl_seconds"] != float64(0) || receipt["version"] != float64(2) {
			t.Fatalf("registered approval decision=%s %v", raw, err)
		}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE approval_id=$1`, exportApprovalID); err != nil {
			t.Fatal(err)
		}
		raw, err = decideExportApproval(f, exportApproverID, "export-approval-decision", time.Now().UTC())
		var replay map[string]any
		if err != nil || json.Unmarshal(raw, &replay) != nil {
			t.Fatalf("approval replay=%s %v", raw, err)
		}
		receipt["replayed"] = true
		if !reflect.DeepEqual(receipt, replay) {
			t.Fatalf("approval receipt changed after lost reply: %v", replay)
		}
		if err = f.worker.QueryRow(f.ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 60, 1).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatalf("approved export did not dispatch: %v", err)
		}
	})
}

func exportRunKind(f *exportDBFixture, c *pgx.Conn, o, w, e, r, worker, lease string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.QueryRow(f.ctx, `SELECT zasp_sa_export_run_kind($1,$2,$3,$4,$5,$6)`, o, w, e, r, worker, lease).Scan(&raw)
	return raw, err
}

func TestSecurityAgentExportRunKindPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		kind := func(lease string) {
			t.Helper()
			raw, err := exportRunKind(f, f.worker, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, lease)
			if err != nil || string(raw) != `{"export": true}` {
				t.Fatalf("registered export route=%s %v", raw, err)
			}
		}
		kind(exportFixtureLease)
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		if _, err := exportRunKind(f, f.worker, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, exportFixtureLease); err == nil {
			t.Fatal("expired lease routed")
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{"short", "foreign-export-route-lease"} {
			if raw, err := exportRunKind(f, f.worker, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, token); err == nil {
				t.Fatalf("foreign lease routed: %s", raw)
			}
		}
		if _, err := exportRunKind(f, f.api, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, exportFixtureLease); err == nil {
			t.Fatal("API obtained worker routing")
		}
		for i := 0; i < 4; i++ {
			ids := []string{f.o, f.w, f.e, exportFixtureRun}
			ids[i] = "pid_8e130099-0000-4000-8000-000000000099"
			if raw, err := exportRunKind(f, f.worker, ids[0], ids[1], ids[2], ids[3], exportFixtureWorker, exportFixtureLease); err == nil {
				t.Fatalf("foreign dimension%d routed: %s", i, raw)
			}
		}
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatal(err)
		}
		kind(exportFixtureLease)
		if _, err := exportRunKind(f, f.worker, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, "foreign-export-replay-lease"); err == nil {
			t.Fatal("foreign token replay routing")
		}
		if _, err := f.owner.Exec(f.ctx, `CREATE ROLE export_route_mixed LOGIN INHERIT; GRANT zasp_security_agent_worker,zasp_security_agent_api TO export_route_mixed`); err != nil {
			t.Fatal(err)
		}
		cfg := f.owner.Config().Copy()
		cfg.User = "export_route_mixed"
		mixed, err := pgx.ConnectConfig(f.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer mixed.Close(context.Background())
		if _, err = exportRunKind(f, mixed, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, exportFixtureLease); err == nil {
			t.Fatal("mixed role routed")
		}
	})
}

func TestSecurityAgentExportApprovalRefusalsPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		seedExportPendingApproval(t, f)
		for i, mutation := range []string{
			`UPDATE zasp_security_agent_approvals SET plan_hash=digest('foreign-plan','sha256') WHERE approval_id=$1 AND run_id=$2`,
			`UPDATE zasp_security_agent_steps SET input_digest=digest('foreign-input','sha256') WHERE run_id=$2 AND $1::text IS NOT NULL`,
			`UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,target_id}',to_jsonb($1::text)) WHERE run_id=$2`,
			`UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,evidence_ids}','[]') WHERE run_id=$2 AND $1::text IS NOT NULL`,
		} {
			var err error
			// Owner corruption is restored from exact row snapshots below.
			var before json.RawMessage
			if err = f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('approval',to_jsonb(a),'step',to_jsonb(s),'plan',to_jsonb(p)) FROM zasp_security_agent_approvals a JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE a.approval_id=$1`, exportApprovalID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err = f.owner.Exec(f.ctx, mutation, pgx.QueryExecModeSimpleProtocol, exportApprovalID, exportFixtureRun); err != nil {
				t.Fatal(err)
			}
			// Rehash plan edits to exercise semantic checks rather than only digest drift.
			if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET plan_hash=digest(convert_to(plan::text,'UTF8'),'sha256') WHERE run_id=$1; UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE r.run_id=p.run_id AND r.run_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun); err != nil {
				t.Fatal(err)
			}
			if i >= 2 {
				if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_approvals a SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE a.run_id=p.run_id AND a.run_id=$1; UPDATE zasp_security_agent_steps s SET input_digest=digest(convert_to((p.plan->'steps'->s.step_index)::text,'UTF8'),'sha256') FROM zasp_security_agent_plans p WHERE s.run_id=p.run_id AND s.run_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := existingTestAcceptanceSnapshot(t, f.ctx, f.owner, f.o, f.w, f.e, exportFixtureRun)
			if _, err = readExportApproval(f); err == nil {
				t.Fatalf("malformed approval read: %s", mutation)
			}
			if _, err = decideExportApproval(f, exportApproverID, "export-approval-refusal", time.Now().UTC()); err == nil {
				t.Fatalf("malformed approval accepted: %s", mutation)
			}
			if got := existingTestAcceptanceSnapshot(t, f.ctx, f.owner, f.o, f.w, f.e, exportFixtureRun); got != snapshot {
				t.Fatal("refusal changed authority")
			}
			if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_approvals SET plan_hash=($2::jsonb->'approval'->>'plan_hash')::bytea WHERE approval_id=$1; UPDATE zasp_security_agent_steps SET input_digest=($2::jsonb->'step'->>'input_digest')::bytea WHERE run_id=$3; UPDATE zasp_security_agent_plans SET plan=$2::jsonb->'plan'->'plan',plan_hash=($2::jsonb->'plan'->>'plan_hash')::bytea WHERE run_id=$3; UPDATE zasp_security_agent_runs SET plan_hash=($2::jsonb->'plan'->>'plan_hash')::bytea WHERE run_id=$3`, pgx.QueryExecModeSimpleProtocol, exportApprovalID, before, exportFixtureRun); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestSecurityAgentExportNonExportRoutePostgres(t *testing.T) {
	for _, family := range []string{"existing_test", "attack_lab"} {
		t.Run(family, func(t *testing.T) {
			runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
				runner := precisionMigrationRunner(t, owner)
				if err := runner.UpProductionCompliance(ctx); err != nil {
					t.Fatal(err)
				}
				if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
					t.Fatal(err)
				}
				applyExport58(t, ctx, owner)
				cfg := owner.Config().Copy()
				cfg.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				f := &exportDBFixture{ctx: ctx, owner: owner, api: api, worker: worker, o: o, w: w, e: e, actor: actor}
				if family == "attack_lab" {
					seedExportRouteAttackLabDefinition(t, ctx, owner, api, o, w, e, testID, actor)
					exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, testID, actor, true, false)
					var exact bool
					if err = owner.QueryRow(ctx, `SELECT d.activation='autonomous' AND d.version=5 AND h.activation=d.activation AND h.definition=d.body AND h.actor_id=$4 AND h.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,'pid_6a000004-0000-4000-8000-000000000004')`, o, w, e, actor).Scan(&exact); err != nil || !exact {
						t.Fatalf("Attack Lab fixture changed registered definition history: exact=%t err=%v", exact, err)
					}
					var run string
					if err = owner.QueryRow(ctx, `SELECT run_id FROM zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&run); err != nil {
						t.Fatal(err)
					}
					raw, err := exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "attack-lab-dispatch-lease")
					if err != nil || string(raw) != `{"export": false}` {
						t.Fatalf("durable Attack Lab replay route=%s %v", raw, err)
					}
					if _, err = exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "foreign-attack-lab-lease"); err == nil {
						t.Fatal("foreign Attack Lab replay routed")
					}
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE run_id=$1`, run); err != nil {
						t.Fatal(err)
					}
					if _, err = exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "attack-lab-dispatch-lease"); err == nil {
						t.Fatal("changed Attack Lab approval routed")
					}
					return
				}
				const run = "pid_8e140001-0000-4000-8000-000000000001"
				const finding = "pid_8e140002-0000-4000-8000-000000000002"
				const workerID = "export-route-existing-test"
				const planningLease = "export-route-planning-lease"
				const dispatchLease = "export-route-dispatch-lease"
				seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, run, finding, "run_test", workerID, planningLease)
				if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='autonomous',body=jsonb_set(body,'{autonomy}','"autonomous"') WHERE organization_id=$1;
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$2 FROM zasp_security_agent_definitions WHERE organization_id=$1 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$3,$4,'run_test',true,$2) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
					t.Fatal(err)
				}
				raw, err := exportRunKind(f, worker, o, w, e, run, workerID, planningLease)
				if err != nil || string(raw) != `{"export": false}` {
					t.Fatalf("unplanned existing-test route=%s %v", raw, err)
				}
				if err = worker.QueryRow(ctx, existingTestPrepareSQL, o, w, e, run, workerID, planningLease, "pid_8e140003-0000-4000-8000-000000000003", time.Now().UTC().Add(5*time.Minute), "pid_8e140004-0000-4000-8000-000000000004", "pid_8e140005-0000-4000-8000-000000000005").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, workerID, dispatchLease, 60, 1).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				raw, err = exportRunKind(f, worker, o, w, e, run, workerID, dispatchLease)
				if err != nil || string(raw) != `{"export": false}` {
					t.Fatalf("planned existing-test route=%s %v", raw, err)
				}
				execute := func() error {
					return worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,'pid_8e140006-0000-4000-8000-000000000006','pid_8e140007-0000-4000-8000-000000000007',$7,$8)`, o, w, e, run, workerID, dispatchLease, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
				}
				if err = execute(); err != nil {
					t.Fatal(err)
				}
				before := existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run)
				if err = execute(); err == nil {
					t.Fatal("predecessor unexpectedly permits cleared-lease replay")
				}
				if _, err = exportRunKind(f, worker, o, w, e, run, workerID, dispatchLease); err == nil {
					t.Fatal("route invented existing-test replay authority")
				}
				if got := existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run); got != before {
					t.Fatal("refused replay mutated state")
				}
			})
		})
	}
}

// The inherited Attack Lab helper starts from an owner-seeded live definition.
// Release58 routes every unplanned run through its immutable definition version.
// Publish that version through the registered lifecycle, not a history-table
// fixture insert that could hide a broken product provenance contract.
func seedExportRouteAttackLabDefinition(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
	t.Helper()
	const id = "pid_6a000004-0000-4000-8000-000000000004"
	body := map[string]any{"name": "Export route Attack Lab predecessor", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{e}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{"start_attack_lab"}, "verification_kind": "attack_lab_run", "definition_version": 1, "enabled": false, "existing_test": map[string]any{"definition_id": testID, "definition_version": 1}}
	intent, err := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": body})
	if err != nil {
		t.Fatal(err)
	}
	body["id"] = id
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err = api.QueryRow(ctx, postgresSecurityAgentExistingTestDefinitionMutateSQL, "create", id, o, w, e, actor, "createSecurityAgent", "export-route-attack-lab-create", int64(0), json.RawMessage(intent), json.RawMessage(payload), "pid_8e150001-0000-4000-8000-000000000001", "pid_8e150002-0000-4000-8000-000000000002", "pid_8e150003-0000-4000-8000-000000000003", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
		t.Fatalf("registered Attack Lab route definition: %v", err)
	}
	var created WorkflowMutationResult
	if json.Unmarshal(raw, &created) != nil || created.Version != 2 || created.Replayed || !equalIntegrationJSON(created.Body, payload) {
		t.Fatalf("registered Attack Lab route draft: %s", raw)
	}
	if err = api.QueryRow(ctx, postgresExistingTestSetControlSQL, existingTestReadPins([]any{o, w, e, actor, "export-route-attack-lab-control", "action", "start_attack_lab", true, int64(0), time.Now().UTC().Add(time.Minute), "pid_8e150041-0000-4000-8000-000000000001", "pid_8e150042-0000-4000-8000-000000000002", "pid_8e150043-0000-4000-8000-000000000003"})...).Scan(&raw); err != nil {
		t.Fatalf("registered Attack Lab route execution control: %v", err)
	}
	for i, activation := range []string{"validated", "supervised", "autonomous"} {
		ids := [3][3]string{
			{"pid_8e150011-0000-4000-8000-000000000001", "pid_8e150012-0000-4000-8000-000000000002", "pid_8e150013-0000-4000-8000-000000000003"},
			{"pid_8e150021-0000-4000-8000-000000000001", "pid_8e150022-0000-4000-8000-000000000002", "pid_8e150023-0000-4000-8000-000000000003"},
			{"pid_8e150031-0000-4000-8000-000000000001", "pid_8e150032-0000-4000-8000-000000000002", "pid_8e150033-0000-4000-8000-000000000003"},
		}[i]
		if err = api.QueryRow(ctx, existingTestActivateSQL, o, w, e, id, actor, "export-route-attack-lab-"+activation, int64(i+2), activation, time.Now().UTC().Add(time.Minute), ids[0], ids[1], ids[2], migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatalf("registered Attack Lab route activation %s: %v", activation, err)
		}
	}
	var exact bool
	if err = owner.QueryRow(ctx, `SELECT d.activation='autonomous' AND d.version=5 AND d.body=$5::jsonb||'{"enabled":true,"autonomy":"autonomous"}'::jsonb AND h.activation=d.activation AND h.definition=d.body AND h.actor_id=$4 AND h.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,'pid_6a000004-0000-4000-8000-000000000004')`, o, w, e, actor, json.RawMessage(payload)).Scan(&exact); err != nil || !exact {
		t.Fatalf("registered Attack Lab route immutable version: exact=%t err=%v", exact, err)
	}
}
