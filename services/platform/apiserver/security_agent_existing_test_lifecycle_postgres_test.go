package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const existingTestActivateSQL = `SELECT public.zasp_production_security_agent_existing_tests_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const existingTestSimulateSQL = `SELECT public.zasp_production_security_agent_existing_tests_simulate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16)`

func TestSecurityAgentExistingTestLifecyclePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		const finding = "pid_89e20800-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Pinned simulation evidence','high','open')`, org, ws, env, finding); err != nil {
			t.Fatal(err)
		}
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		identity := fixtureRequestIdentity(t)
		o, _ := domain.ParseProductID(org)
		w, _ := domain.ParseProductID(ws)
		e, _ := domain.ParseProductID(env)
		identity.Scope, _ = domain.NewScope(o, w, e)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		identity.FreshAuthenticated = true
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		inventoryEvidence := seedExistingTestSimulationEvidence(t, ctx, owner, org, ws, env, actor)
		var entityOwner, evidenceOwner string
		var entityUpdate, evidenceUpdate bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT relowner::regrole::text FROM pg_class WHERE oid='zasp_inventory_entities'::regclass),(SELECT relowner::regrole::text FROM pg_class WHERE oid='zasp_inventory_evidence'::regclass),has_table_privilege('zasp_discovery_authority','zasp_inventory_entities','UPDATE'),has_table_privilege('zasp_discovery_authority','zasp_inventory_evidence','UPDATE')`).Scan(&entityOwner, &evidenceOwner, &entityUpdate, &evidenceUpdate); err != nil {
			t.Fatal(err)
		}
		t.Logf("inventory row-lock authority: entity owner=%s discovery UPDATE=%t; evidence owner=%s discovery UPDATE=%t", entityOwner, entityUpdate, evidenceOwner, evidenceUpdate)
		for index, action := range []string{"run_test", "rerun_test"} {
			t.Run(action, func(t *testing.T) {
				id := fmt.Sprintf("pid_89e20100-0000-4000-8000-%012d", index+1)
				createExistingTestLifecycleDraft(t, ctx, api, org, ws, env, id, testID, actor, action)
				activate := append([]any{org, ws, env, id, actor, "pinned-lifecycle-activate-" + action, int64(1), "validated", time.Now().UTC().Add(time.Minute),
					fmt.Sprintf("pid_89e21200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e21300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e21400-0000-4000-8000-%012d", index+1)}, pins...)
				refuse := func(query string, args []any, code string) {
					t.Helper()
					before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
					var raw json.RawMessage
					err := api.QueryRow(ctx, query, args...).Scan(&raw)
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != code {
						t.Fatalf("expected lifecycle refusal %s: result=%s err=%v", code, raw, err)
					}
					if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
						t.Fatal("lifecycle refusal changed snapshotted authority")
					}
				}
				setTestVersion := func(version int64) {
					t.Helper()
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=$5 WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, testID, version); err != nil {
						t.Fatal(err)
					}
				}
				defer setTestVersion(1)
				setTestVersion(2)
				refuse(existingTestActivateSQL, activate, "40001")
				setTestVersion(1)
				lateRefusal := func(query string, args []any, expiryIndex int) {
					t.Helper()
					late := append([]any(nil), args...)
					deadline := time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
					late[expiryIndex] = deadline
					before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
					err := existingTestAcceptanceWait(t, ctx, owner, api, id, "audit_lifecycle", func() error {
						var raw json.RawMessage
						return api.QueryRow(ctx, query, late...).Scan(&raw)
					}, deadline)
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "40001" || !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
						t.Fatalf("post-audit expiry accepted or changed authority: %v", err)
					}
				}
				lateRefusal(existingTestActivateSQL, activate, 8)
				identity.FreshAuthExpiresAt = activate[8].(time.Time)
				activationRequest := SecurityAgentActivation{DefinitionID: id, IdempotencyKey: activate[5].(string), ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: activate[9].(string), CorrelationID: activate[10].(string), ReceiptID: activate[11].(string)}
				activation, err := repository.ActivateSecurityAgent(ctx, identity, activationRequest)
				if err != nil {
					t.Fatalf("validate pinned test: %v", err)
				}
				activated, err := json.Marshal(activation)
				if err != nil || activation.ID != id || activation.Version != 2 || activation.Activation != "validated" || activation.Enabled || activation.Replayed {
					t.Fatalf("invalid validation response: %s", activated)
				}
				var exact bool
				if err := owner.QueryRow(ctx, `SELECT d.version=2 AND d.activation='validated' AND d.body->'enabled'='false'::jsonb AND h.definition=d.body AND h.actor_id=$5 AND h.definition_digest=digest(convert_to(h.definition::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, org, ws, env, id, actor).Scan(&exact); err != nil || !exact {
					t.Fatalf("validation lost scoped version/provenance: %t %v", exact, err)
				}
				replay := func(query string, args []any, original json.RawMessage) {
					t.Helper()
					before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
					var raw json.RawMessage
					if err := api.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
						t.Fatalf("immutable lifecycle replay: %v", err)
					}
					var want map[string]any
					if err := json.Unmarshal(original, &want); err != nil {
						t.Fatal(err)
					}
					want["replayed"] = true
					expected, _ := json.Marshal(want)
					if !equalIntegrationJSON(raw, expected) || !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
						t.Fatalf("replay changed response/authority: %s", raw)
					}
				}
				replay(existingTestActivateSQL, activate, activated)
				execution := append([]any(nil), activate...)
				execution[5], execution[6], execution[7] = "pinned-lifecycle-enable-"+action, int64(2), "supervised"
				// Public enablement is supported at55, but this fixture has never
				// enabled the scoped test-action control. Its absence must still refuse.
				var missingControl bool
				if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,$4) AND execution_enabled)`, org, ws, env, action).Scan(&missingControl); err != nil || !missingControl {
					t.Fatalf("missing-control refusal prerequisite: %v", err)
				}
				refuse(existingTestActivateSQL, execution, "55000")
				run := fmt.Sprintf("pid_89e21900-0000-4000-8000-%012d", index+1)
				expires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond)
				simulate := append([]any{org, ws, env, id, actor, "pinned-lifecycle-simulate-" + action, int64(2), run, "Verify the pinned test", json.RawMessage(`["` + finding + `"]`), expires,
					fmt.Sprintf("pid_89e22200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e22300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e22400-0000-4000-8000-%012d", index+1)}, pins...)
				var simulated json.RawMessage
				foreign := append([]any(nil), simulate...)
				foreign[9] = json.RawMessage(`["pid_89e29900-0000-4000-8000-000000000001"]`)
				refuse(existingTestSimulateSQL, foreign, "42501")
				lateRefusal(existingTestSimulateSQL, simulate, 10)
				simulationRequest := SecurityAgentSimulationRequest{DefinitionID: id, IdempotencyKey: simulate[5].(string), ExpectedVersion: 2, RunID: run, Goal: simulate[8].(string), EvidenceIDs: []string{finding}, ExpiresAt: expires, AuditID: simulate[11].(string), CorrelationID: simulate[12].(string), ReceiptID: simulate[13].(string)}
				result, err := repository.SimulateSecurityAgent(ctx, identity, simulationRequest)
				if err != nil {
					t.Fatalf("simulate pinned test: %v", err)
				}
				if err := owner.QueryRow(ctx, `SELECT response FROM zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=($1,$2,$3,$4,'simulateSecurityAgent',$5)`, org, ws, env, actor, simulationRequest.IdempotencyKey).Scan(&simulated); err != nil {
					t.Fatal(err)
				}
				var persisted SecurityAgentSimulationResult
				if json.Unmarshal(simulated, &persisted) != nil || !reflect.DeepEqual(result, persisted) || !validSecurityAgentSimulation(result, id, 2, []string{finding}, expires) || result.RunID != run || result.Replayed || len(result.Steps) != 1 || result.Steps[0].Action != action || !result.Steps[0].ApprovalRequired {
					t.Fatalf("invalid simulation response: %s", simulated)
				}
				if err := owner.QueryRow(ctx, `SELECT p.plan->'existing_test'=jsonb_build_object('definition_id',$5::text,'definition_version',1,'target_id','pid_89000011-0000-4000-8000-000000000001','target_kind','agent_endpoint') AND p.plan_hash=digest(convert_to(p.plan::text,'UTF8'),'sha256') AND r.plan_hash=p.plan_hash AND 'sha256:'||encode(p.plan_hash,'hex')=$6 AND r.state='simulated' AND r.completed_at IS NOT NULL FROM zasp_security_agent_plans p JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=($1,$2,$3,$4)`, org, ws, env, run, testID, result.PlanHash).Scan(&exact); err != nil || !exact {
					t.Fatalf("simulation did not hash exact test intent: %t %v", exact, err)
				}
				replay(existingTestSimulateSQL, simulate, simulated)
				var originalPlan json.RawMessage
				if err := owner.QueryRow(ctx, `SELECT plan FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&originalPlan); err != nil {
					t.Fatal(err)
				}
				// Recompute every outer hash so these refusals exercise the exact
				// binding/scope/version checks, not merely a stale digest check.
				for _, patch := range []json.RawMessage{
					json.RawMessage(`{"existing_test":{"definition_id":"` + testID + `","definition_version":2,"target_id":"pid_89000011-0000-4000-8000-000000000001","target_kind":"agent_endpoint"}}`),
					json.RawMessage(`{"definition_version":2.5}`),
					json.RawMessage(`{"target_scope":{"organization_id":"` + org + `","workspace_id":"` + ws + `","environment_id":"pid_89e29900-0000-4000-8000-000000000001"}}`),
				} {
					func() {
						defer func() {
							if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=$5::jsonb,plan_hash=digest(convert_to(($5::jsonb)::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_runs SET plan_hash=digest(convert_to(($5::jsonb)::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_request_receipts SET response=$6::jsonb WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=($1,$2,$3,$7,'simulateSecurityAgent',$8)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, run, originalPlan, simulated, actor, simulationRequest.IdempotencyKey); err != nil {
								t.Fatal(err)
							}
						}()
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=plan||$5::jsonb,plan_hash=digest(convert_to((plan||$5::jsonb)::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_runs SET plan_hash=(SELECT plan_hash FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)) WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{plan_hash}',to_jsonb((SELECT 'sha256:'||encode(plan_hash,'hex') FROM zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)))) WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=($1,$2,$3,$6,'simulateSecurityAgent',$7)`, pgx.QueryExecModeSimpleProtocol, org, ws, env, run, patch, actor, simulationRequest.IdempotencyKey); err != nil {
							t.Fatal(err)
						}
						refuse(existingTestSimulateSQL, simulate, "40001")
					}()
				}
				replay(existingTestSimulateSQL, simulate, simulated)
				for evidenceIndex, evidence := range []string{"pid_89000011-0000-4000-8000-000000000001", inventoryEvidence} {
					t.Run(fmt.Sprintf("inventory_%d", evidenceIndex), func(t *testing.T) {
						extra := append([]any(nil), simulate...)
						sequence := index*10 + evidenceIndex + 1
						extra[5] = fmt.Sprintf("pinned-inventory-simulation-%d", sequence)
						extra[7] = fmt.Sprintf("pid_89e24900-0000-4000-8000-%012d", sequence)
						extra[9] = json.RawMessage(`["` + evidence + `"]`)
						extra[11] = fmt.Sprintf("pid_89e24200-0000-4000-8000-%012d", sequence)
						extra[12] = fmt.Sprintf("pid_89e24300-0000-4000-8000-%012d", sequence)
						extra[13] = fmt.Sprintf("pid_89e24400-0000-4000-8000-%012d", sequence)
						var raw json.RawMessage
						if err := api.QueryRow(ctx, existingTestSimulateSQL, extra...).Scan(&raw); err != nil {
							t.Fatalf("authorized inventory simulation: %v", err)
						}
						var result SecurityAgentSimulationResult
						if json.Unmarshal(raw, &result) != nil || !validSecurityAgentSimulation(result, id, 2, []string{evidence}, expires) || result.RunID != extra[7] || result.Replayed {
							t.Fatalf("inventory simulation lost evidence: %s", raw)
						}
						replay(existingTestSimulateSQL, extra, raw)
					})
				}
				setTestVersion(2)
				refuse(existingTestSimulateSQL, simulate, "40001")
				// Validation replay is immutable history, not renewed execution authority.
				replay(existingTestActivateSQL, activate, activated)
				setTestVersion(1)
				for _, call := range []struct {
					query string
					args  []any
				}{{existingTestActivateSQL, activate}, {existingTestSimulateSQL, simulate}} {
					stale := append([]any(nil), call.args...)
					stale[len(stale)-1] = "wrong"
					refuse(call.query, stale, "55000")
				}
				var sideEffects int
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_red_team_runs)+(SELECT count(*) FROM zasp_red_team_outbox)+(SELECT count(*) FROM zasp_security_agent_test_links)+(SELECT count(*) FROM zasp_security_agent_effects)+(SELECT count(*) FROM zasp_security_agent_step_reservations)+(SELECT count(*) FROM zasp_security_agent_approvals)`).Scan(&sideEffects); err != nil || sideEffects != 0 {
					t.Fatalf("simulation created execution authority: %d %v", sideEffects, err)
				}
			})
		}
	})
}

// Scoped raw evidence fixture only; this does not claim a completed discovery sync.
func seedExistingTestSimulationEvidence(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, actor string) string {
	t.Helper()
	const evidence = "pid_89e23800-0000-4000-8000-000000000004"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000001','kubernetes','1','Simulation fixture');
 INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000002','pid_89e23800-0000-4000-8000-000000000001','lifecycle-evidence-sync-0001',decode(repeat('ab',32),'hex'),'manual',$4,'1','1');
 INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,complete,collected_at) VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000003','pid_89e23800-0000-4000-8000-000000000001','pid_89e23800-0000-4000-8000-000000000002',1,'kubernetes','s3://zasp-evidence/lifecycle/manifest.json',decode(repeat('ab',32),'hex'),'candidate',decode(repeat('ab',32),'hex'),false,clock_timestamp());
 INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at) VALUES($1,$2,$3,$5,'pid_89e23800-0000-4000-8000-000000000001','pid_89e23800-0000-4000-8000-000000000003','pid_89000011-0000-4000-8000-000000000001','s3://zasp-evidence/lifecycle/evidence.json',decode(repeat('ab',32),'hex'),'application/json','1','1',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, org, ws, env, actor, evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}
