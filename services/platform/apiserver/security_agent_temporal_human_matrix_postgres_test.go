package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// One installed fixture covers the remaining caller forms and authority
// fences. Definition and gateway source setup are controlled product rows;
// every request, ownership transfer and read uses a registered authority.
func TestTemporalHumanAdmissionMatrixPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		repository := &PostgresRepository{database: authority.repository.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		sequence := 10000
		id := func() string { sequence++; return fmt.Sprintf("pid_f0760000-0000-4000-8000-%012d", sequence) }
		config := SecurityAgentPublicHandlerConfig{Clock: time.Now, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { return id(), nil }}
		legacy, err := newSecurityAgentProductionHTTPHandler(ctx, repository, http.NotFoundHandler(), config, false)
		if err != nil {
			t.Fatal(err)
		}
		historicalRequest := func(key string) *httptest.ResponseRecorder {
			r := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": temporalTestLegacyProved}, http.MethodPost, "/api/v1/security-agents/"+temporalTestLegacyProved+"/runs", `{"environment_id":"`+e+`"}`)
			r.Header.Set("Idempotency-Key", key)
			r.Header.Set("If-Match", `"4"`)
			response := httptest.NewRecorder()
			legacy.ServeHTTP(response, r)
			return response
		}
		historicalResponse := historicalRequest("human-history-before76")
		var historical SecurityAgentRun
		if historicalResponse.Code != 202 || json.Unmarshal(historicalResponse.Body.Bytes(), &historical) != nil {
			t.Fatal("actual pre76 historical admission", historicalResponse.Code, historicalResponse.Body.String())
		}
		if err := runner.UpProductionTemporalHumanAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE human_matrix_executor LOGIN;CREATE ROLE human_matrix_compensation LOGIN;SELECT zasp_temporal68.register_principals('human_matrix_executor','human_matrix_compensation');
UPDATE zasp_risk_attack_paths SET state='observed' WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3);
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,'pid_f0760000-0000-4000-8000-000000070001','Human matrix gateway','active');
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,'pid_f0760000-0000-4000-8000-000000070002','pid_f0760000-0000-4000-8000-000000070001','runtime-gateway-enroll',decode(repeat('01',16),'hex'),decode(repeat('ab',32),'hex'),clock_timestamp()+interval '1 hour');
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,issued_at,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,'pid_f0760000-0000-4000-8000-000000070003','pid_f0760000-0000-4000-8000-000000070001','pid_f0760000-0000-4000-8000-000000070002',decode(repeat('cd',32),'hex'),'runtime-gateway','ref:gateway/public/human-matrix',decode(repeat('04',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',1,1,'human-matrix','Ed25519',clock_timestamp()-interval '1 hour')`, pgx.QueryExecModeSimpleProtocol, o, w, e); err != nil {
			t.Fatal(err)
		}
		connect := func(user string) *pgx.Conn {
			cfg := owner.Config().Copy()
			cfg.User = user
			c, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(context.Background()) })
			return c
		}
		executor := connect("human_matrix_executor")
		workerDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connect("security_agent_v33_worker_login")})
		if err != nil {
			t.Fatal(err)
		}
		retained, err := NewSecurityAgentWorkerRepository(workerDB)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := retained.ClaimSecurityAgentRuns(ctx, "human-historical-retained", "human-historical-retained-token", 30, 10)
		if err != nil || len(claims) != 1 || claims[0].RunID != historical.ID {
			t.Fatal("unmarked historical owner changed", claims, err)
		}
		var historicalProof bool
		if err := owner.QueryRow(ctx, `SELECT r.state='planning' AND r.version=2 AND r.attempt=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal76.admissions a WHERE a.run_id=r.run_id) AND EXISTS(SELECT 1 FROM zasp_temporal66.run_owners x WHERE x.run_id=r.run_id AND x.execution_owner='legacy') FROM zasp_security_agent_runs r WHERE r.run_id=$1`, historical.ID).Scan(&historicalProof); err != nil || !historicalProof {
			t.Fatal("unmarked historical retained proof", historicalProof, err)
		}
		if blocked := historicalRequest("human-history-shared-capacity"); blocked.Code != 409 {
			t.Fatal("retained work lost shared capacity", blocked.Code, blocked.Body.String())
		}
		if _, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: historical.ID, ExpectedVersion: 2, IdempotencyKey: "human-history-cancel", AuditID: id(), CorrelationID: testCorrelationID, ReceiptID: id()}); err != nil {
			t.Fatal("historical cleanup", err)
		}
		t.Log("actual pre76 human admission remained unmarked and retained-claimable; planning historical owner blocked new76 admission at shared capacity")
		for _, ordered := range []bool{false, true} {
			for _, action := range []string{"run_test", "rerun_test"} {
				for _, kind := range []string{"manual", "finding", "attack_path", "session"} {
					if action == "run_test" && (kind == "manual" || kind == "finding") {
						continue
					} // covered by the actual RED/GREEN caller group
					t.Run(fmt.Sprintf("ordered=%t/%s/%s", ordered, action, kind), func(t *testing.T) {
						definition := id()
						source, sqlKind, trigger := "credential", "finding", public62Finding
						if kind == "attack_path" {
							source, sqlKind, trigger = "observed", "attack_path", "pid_6a000005-0000-4000-8000-000000000005"
						}
						if kind == "session" {
							source, sqlKind, trigger = "gateway", "runtime_decision", id()
							if _, err := owner.Exec(ctx, `INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,'pid_f0760000-0000-4000-8000-000000070001','pid_f0760000-0000-4000-8000-000000070003',$4,$5,decode(repeat('fa',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$6::text),clock_timestamp())`, o, w, e, id(), int64(sequence), trigger); err != nil {
								t.Fatal(err)
							}
						}
						if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) SELECT organization_id,workspace_id,environment_id,$2,activation,version,definition_version,body||jsonb_build_object('id',$2::text,'allowed_actions',jsonb_build_array($3::text),'trigger_kind',$4::text,'trigger_source',$5::text),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($7,$8,$9,$3,true,$6) ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, temporalTestLegacyProved, definition, action, sqlKind, source, actor, o, w, e); err != nil {
							t.Fatal(err)
						}
						handler, err := newSecurityAgentProductionHTTPHandler(ctx, repository, http.NotFoundHandler(), config, ordered)
						if err != nil {
							t.Fatal(err)
						}
						var version int64
						if kind != "manual" {
							var raw []byte
							if err := owner.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_trigger($1,$2,$3,$4,$5,$6,0)`, o, w, e, sqlKind, trigger, source).Scan(&raw); err != nil {
								t.Fatal("controlled source eligibility", err)
							}
							var v struct {
								Version int64 `json:"version"`
							}
							json.Unmarshal(raw, &v)
							version = v.Version
						}
						body := map[string]any{"environment_id": e}
						if kind != "manual" {
							body["trigger_kind"], body["trigger_id"] = kind, trigger
							if ordered {
								body["trigger_version"], body["trigger_source"] = version, source
							}
						}
						key := fmt.Sprintf("human-matrix-%t-%s-%s", ordered, action, kind)
						request := func(target, key string, payload map[string]any) *httptest.ResponseRecorder {
							raw, _ := json.Marshal(payload)
							r := workflowRequest(t, identity, testCorrelationID, "runSecurityAgent", map[string]string{"id": target}, http.MethodPost, "/api/v1/security-agents/"+target+"/runs", string(raw))
							r.Header.Set("Idempotency-Key", key)
							r.Header.Set("If-Match", `"4"`)
							response := httptest.NewRecorder()
							handler.ServeHTTP(response, r)
							return response
						}
						response := request(definition, key, body)
						if response.Code != 202 {
							t.Fatal("supported human caller", response.Code, response.Body.String())
						}
						var run SecurityAgentRun
						if json.Unmarshal(response.Body.Bytes(), &run) != nil || run.ID == "" {
							t.Fatal("typed admission")
						}
						defer func() {
							var v int64
							if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, run.ID).Scan(&v); err != nil {
								t.Error(err)
								return
							}
							if _, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: run.ID, ExpectedVersion: v, IdempotencyKey: key + "-cancel", AuditID: id(), CorrelationID: testCorrelationID, ReceiptID: id()}); err != nil {
								t.Error("cleanup", err)
							}
						}()
						var proof bool
						if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal76.admissions a JOIN zasp_temporal65.commands c ON(c.organization_id,c.workspace_id,c.environment_id,c.event_id)=(a.organization_id,a.workspace_id,a.environment_id,a.event_id) JOIN zasp_security_agent_request_receipts r ON(r.organization_id,r.workspace_id,r.environment_id,r.receipt_id)=(a.organization_id,a.workspace_id,a.environment_id,a.event_id) WHERE a.run_id=$1 AND a.requester_id=$2 AND c.execution_owner='legacy' AND c.kind='start' AND r.principal_id=$2 AND NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions s WHERE s.run_id=a.run_id))`, run.ID, actor).Scan(&proof); err != nil || !proof {
							t.Fatal("atomic human provenance", proof, err)
						}
						if claims, err := retained.ClaimSecurityAgentRuns(ctx, "human-matrix-retained", "human-matrix-retained-token", 30, 10); err != nil || len(claims) != 0 {
							t.Fatal("dual retained ownership", claims, err)
						}
						var takeover []byte
						if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run.ID).Scan(&takeover); err != nil || !strings.Contains(string(takeover), action) {
							t.Fatal("specialized human takeover", string(takeover), err)
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE(organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
							t.Fatal(err)
						}
						var current []byte
						load, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run.ID, "definition_version": 4, "operation": "load"})
						deniedErr := executor.QueryRow(ctx, `SELECT zasp_temporal74.plan($1::jsonb)`, load).Scan(&current)
						denied := request(definition, key+"-revoked", body)
						if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE(organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
							t.Fatal(err)
						}
						if deniedErr == nil || denied.Code < 400 {
							t.Fatal("revoked human allowed fresh context/admission", deniedErr, denied.Code)
						}
						if _, err := executor.Exec(ctx, "BEGIN"); err != nil {
							t.Fatal(err)
						}
						loadErr := executor.QueryRow(ctx, `SELECT zasp_temporal74.plan($1::jsonb)`, load).Scan(&current)
						if _, err := executor.Exec(ctx, "ROLLBACK"); err != nil {
							t.Fatal(err)
						}
						if loadErr != nil {
							t.Fatal("restored human registered planning load", loadErr)
						}
						if ordered && action == "rerun_test" && kind == "finding" {
							var permissions []byte
							if err := owner.QueryRow(ctx, `SELECT permissions FROM zasp_authorized_scopes WHERE(organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor).Scan(&permissions); err != nil {
								t.Fatal(err)
							}
							if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions=permissions-'run_tests' WHERE(organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor); err != nil {
								t.Fatal(err)
							}
							permissionErr := executor.QueryRow(ctx, `SELECT zasp_temporal74.plan($1::jsonb)`, load).Scan(&current)
							denied := request(definition, key+"-permission", body)
							if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions=$5::jsonb WHERE(organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor, permissions); err != nil {
								t.Fatal(err)
							}
							if permissionErr == nil || denied.Code < 400 {
								t.Fatal("missing scoped run_tests allowed human IO", permissionErr, denied.Code)
							}
							for _, bad := range []map[string]any{{"environment_id": e, "trigger_kind": "finding", "trigger_id": trigger, "trigger_version": nil, "trigger_source": source}, {"environment_id": e, "trigger_kind": "finding", "trigger_id": trigger, "trigger_version": 0, "trigger_source": source}, {"environment_id": e, "trigger_kind": "finding", "trigger_id": trigger, "trigger_version": 1}, {"environment_id": e, "extra": "unknown"}} {
								if got := request(definition, key+"-malformed", bad); got.Code != 400 {
									t.Error("strict contract", got.Code, got.Body.String())
								}
							}
							if got := request(id(), key+"-missing", body); got.Code < 400 {
								t.Error("missing object accepted")
							}
							foreign := map[string]any{"environment_id": "pid_f0760000-0000-4000-8000-000000099999"}
							if got := request(definition, key+"-foreign", foreign); got.Code < 400 {
								t.Error("foreign scope accepted")
							}
							if got := request(definition, key+"-capacity", map[string]any{"environment_id": e}); got.Code != 409 {
								t.Error("shared capacity", got.Code, got.Body.String())
							}
						}
						t.Logf("registered caller=%T action=%s kind=%s version=%d committed human76/65 ->74 and current human revoke fence", handler, action, kind, version)
					})
				}
			}
		}
	})
}
