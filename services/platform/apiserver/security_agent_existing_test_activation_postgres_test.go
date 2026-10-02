package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// An API login must not bypass exact-reference validation through the old
// activation/simulation entrypoints. These are real API-created drafts, not
// owner-created definitions. No provider execution is exercised here.
func TestSecurityAgentExistingTestLegacyActivationFencePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		for index, mode := range []struct{ action, from, to string }{
			{"run_test", "draft", "validated"}, {"rerun_test", "draft", "validated"},
			{"run_test", "validated", "supervised"}, {"rerun_test", "validated", "supervised"},
			{"run_test", "supervised", "autonomous"}, {"rerun_test", "supervised", "autonomous"},
		} {
			t.Run(mode.action+"_"+mode.to, func(t *testing.T) {
				id := fmt.Sprintf("pid_89e10100-0000-4000-8000-%012d", index+1)
				createExistingTestLifecycleDraft(t, ctx, api, org, ws, env, id, testID, actor, mode.action)
				if mode.from != "draft" {
					// Isolate refusal from each predecessor activation state without
					// claiming the unfinished versioned activation path produced it.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation=$5,body=jsonb_set(body,'{enabled}',to_jsonb($6::boolean)) WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, id, mode.from, mode.from == "supervised"); err != nil {
						t.Fatal(err)
					}
				}
				before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
				var raw json.RawMessage
				err := api.QueryRow(ctx, postgresSecurityAgentActivateSQL, org, ws, env, id, actor,
					"existing-legacy-activation-"+mode.action+mode.to, int64(1), mode.to, time.Now().UTC().Add(time.Minute),
					fmt.Sprintf("pid_89e10200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e10300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e10400-0000-4000-8000-%012d", index+1)).Scan(&raw)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "55000" || pg.Message != "existing test lifecycle requires versioned authority" {
					t.Errorf("legacy activation bypass: result=%s err=%v", raw, err)
				}
				if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
					t.Error("refused activation changed definition/history/receipt/audit")
				}
			})
		}
	})
}

func TestSecurityAgentExistingTestLegacySimulationFencePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		const finding = "pid_89e10800-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Simulation evidence','high','open')`, org, ws, env, finding); err != nil {
			t.Fatal(err)
		}
		for index, action := range []string{"run_test", "rerun_test"} {
			t.Run(action, func(t *testing.T) {
				id := fmt.Sprintf("pid_89e10100-0000-4000-8000-%012d", index+1)
				createExistingTestLifecycleDraft(t, ctx, api, org, ws, env, id, testID, actor, action)
				// Owner validation isolates the old simulation entrypoint's refusal.
				// It is not evidence of a completed user activation workflow.
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='validated' WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, id); err != nil {
					t.Fatal(err)
				}
				before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
				var raw json.RawMessage
				err := api.QueryRow(ctx, postgresSecurityAgentSimulateSQL, org, ws, env, id, actor,
					"existing-legacy-simulation-"+action, int64(1), fmt.Sprintf("pid_89e10900-0000-4000-8000-%012d", index+1), "Verify the pinned test", json.RawMessage(`["`+finding+`"]`), time.Now().UTC().Add(time.Minute),
					fmt.Sprintf("pid_89e10200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e10300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e10400-0000-4000-8000-%012d", index+1)).Scan(&raw)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "55000" || pg.Message != "existing test lifecycle requires versioned authority" {
					t.Errorf("legacy simulation bypass: result=%s err=%v", raw, err)
				}
				if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
					t.Error("refused simulation changed durable authority")
				}
			})
		}
	})
}

func createExistingTestLifecycleDraft(t *testing.T, ctx context.Context, api *pgx.Conn, org, ws, env, id, testID, actor, action string) {
	createExistingTestLifecycleTriggerDraft(t, ctx, api, org, ws, env, id, testID, actor, action, "finding", "credential")
}

func createExistingTestLifecycleTriggerDraft(t *testing.T, ctx context.Context, api *pgx.Conn, org, ws, env, id, testID, actor, action, triggerKind, triggerSource string) {
	t.Helper()
	body := map[string]any{"name": "Lifecycle pinned test", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{env}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{action}, "verification_kind": "test_run", "definition_version": 1, "enabled": false, "existing_test": map[string]any{"definition_id": testID, "definition_version": 1}}
	body["trigger_kind"], body["trigger_source"] = triggerKind, triggerSource
	if action == "update_finding_response" {
		delete(body, "existing_test")
		body["verification_kind"] = "finding_state"
	}
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
	err = api.QueryRow(ctx, postgresSecurityAgentExistingTestDefinitionMutateSQL, "create", id, org, ws, env, actor, "createSecurityAgent", "lifecycle-create-"+id, int64(0), json.RawMessage(intent), json.RawMessage(payload),
		"pid_89e10500-0000-4000-8000-"+id[len(id)-12:], "pid_89e10600-0000-4000-8000-"+id[len(id)-12:], "pid_89e10700-0000-4000-8000-"+id[len(id)-12:], migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	var result WorkflowMutationResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Version != 1 || !equalIntegrationJSON(result.Body, payload) {
		t.Fatalf("create lifecycle draft: result=%s err=%v", raw, err)
	}
}

// Positive legacy control and negative historical replay share actual receipt
// generation. Only historical test receipt setup temporarily grants the saved
// predecessor to the fixture API login. No such grant ships in release55.
func TestSecurityAgentExistingTestLegacyLifecycleReplayPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		const finding = "pid_89e10800-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Simulation evidence','high','open')`, org, ws, env, finding); err != nil {
			t.Fatal(err)
		}
		for index, action := range []string{"update_finding_response", "run_test", "rerun_test"} {
			t.Run(action, func(t *testing.T) {
				id := fmt.Sprintf("pid_89e10100-0000-4000-8000-%012d", index+1)
				createExistingTestLifecycleDraft(t, ctx, api, org, ws, env, id, testID, actor, action)
				activationArgs := []any{org, ws, env, id, actor, "lifecycle-replay-activate-" + action, int64(1), "validated", time.Now().UTC().Add(time.Minute),
					fmt.Sprintf("pid_89e11200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e11300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e11400-0000-4000-8000-%012d", index+1)}
				simulationArgs := []any{org, ws, env, id, actor, "lifecycle-replay-simulate-" + action, int64(2), fmt.Sprintf("pid_89e11900-0000-4000-8000-%012d", index+1), "Verify bounded response", json.RawMessage(`["` + finding + `"]`), time.Now().UTC().Add(time.Minute),
					fmt.Sprintf("pid_89e12200-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e12300-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_89e12400-0000-4000-8000-%012d", index+1)}
				signatures := []string{"zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)", "zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text)"}
				queries := []string{postgresSecurityAgentActivateSQL, postgresSecurityAgentSimulateSQL}
				args := [][]any{activationArgs, simulationArgs}
				prior := make([]json.RawMessage, 2)
				for operation, query := range queries {
					if index > 0 {
						privateQuery := strings.Replace(query, "SELECT zasp_", "SELECT zasp_existing_tests_predecessor.zasp_", 1)
						var denied json.RawMessage
						var pg *pgconn.PgError
						if err := api.QueryRow(ctx, privateQuery, args[operation]...).Scan(&denied); !errors.As(err, &pg) || pg.Code != "42501" {
							t.Fatalf("private predecessor directly callable: %v", err)
						}
						if _, err := owner.Exec(ctx, `GRANT USAGE ON SCHEMA zasp_existing_tests_predecessor TO security_agent_v33_api_login; GRANT EXECUTE ON FUNCTION zasp_existing_tests_predecessor.`+signatures[operation]+` TO security_agent_v33_api_login`); err != nil {
							t.Fatal(err)
						}
						query = privateQuery
					}
					err := api.QueryRow(ctx, query, args[operation]...).Scan(&prior[operation])
					if index > 0 {
						if _, revokeErr := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_existing_tests_predecessor.`+signatures[operation]+` FROM security_agent_v33_api_login; REVOKE USAGE ON SCHEMA zasp_existing_tests_predecessor FROM security_agent_v33_api_login`); revokeErr != nil {
							t.Fatal(revokeErr)
						}
					}
					if err != nil {
						t.Fatalf("generate real lifecycle receipt: %v", err)
					}
				}
				if index > 0 {
					// Same-version owner mutation isolates the immutable history guard;
					// normal API updates advance the version and add their own history.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=(body-'existing_test')||'{"allowed_actions":["update_finding_response"],"verification_kind":"finding_state"}'::jsonb WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, id); err != nil {
						t.Fatal(err)
					}
				}
				before := existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)
				for operation, query := range queries {
					var raw json.RawMessage
					err := api.QueryRow(ctx, query, args[operation]...).Scan(&raw)
					if index > 0 {
						var pg *pgconn.PgError
						if !errors.As(err, &pg) || pg.Code != "55000" || pg.Message != "existing test lifecycle requires versioned authority" {
							t.Fatalf("historical test replay bypass: %s %v", raw, err)
						}
					} else {
						var expected map[string]any
						if err != nil || json.Unmarshal(prior[operation], &expected) != nil {
							t.Fatalf("legacy positive replay: %s %v", raw, err)
						}
						expected["replayed"] = true
						want, _ := json.Marshal(expected)
						if !equalIntegrationJSON(raw, want) {
							t.Fatalf("legacy replay response changed: %s", raw)
						}
					}
				}
				if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, org, ws, env, id)) {
					t.Fatal("lifecycle replay mutated durable state")
				}
				var ready bool
				if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_client_ready($1,$2)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || !ready {
					t.Fatalf("temporary fixture grant was not fully removed: %v %v", ready, err)
				}
			})
		}
	})
}

func existingTestActivationSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, id string) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'definition',(SELECT to_jsonb(d) FROM zasp_security_agent_definitions d WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'history',(SELECT jsonb_agg(to_jsonb(h) ORDER BY version) FROM zasp_security_agent_definition_versions h WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM zasp_security_agent_request_receipts r WHERE (organization_id,workspace_id,environment_id,resource_id)=($1,$2,$3,$4)),
 'trigger_receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY trigger_id,trigger_version) FROM zasp_security_agent_trigger_receipts r WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM zasp_security_agent_runs r WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)),
 'plans',(SELECT jsonb_agg(to_jsonb(p) ORDER BY run_id) FROM zasp_security_agent_plans p WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY run_id,step_id) FROM zasp_security_agent_steps s WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'links',(SELECT jsonb_agg(to_jsonb(l) ORDER BY run_id,step_id) FROM zasp_security_agent_test_links l WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'controls',(SELECT jsonb_agg(to_jsonb(c) ORDER BY organization_id,workspace_id,environment_id,action_key) FROM zasp_security_agent_kill_switches c WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) OR organization_id='*'),
 'test_runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM zasp_red_team_runs r WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM zasp_red_team_outbox o WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)))`, org, ws, env, id).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
