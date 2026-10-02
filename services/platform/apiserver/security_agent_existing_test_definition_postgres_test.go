package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This is a registered API-role database acceptance contract, not an owner
// fixture write or HTTP-capability proof. It shares the owned candidate fixture.
func exerciseSecurityAgentExistingTestDefinition(t *testing.T, ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string, versioned bool) {
	t.Helper()
	agentID := "pid_89000021-0000-4000-8000-000000000001"
	body := map[string]any{
		"id": agentID, "name": "Pinned existing test", "trigger_kind": "finding", "trigger_source": "credential",
		"environment_ids": []string{env}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300,
		"temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000,
		"concurrency_limit": 1, "allowed_actions": []string{"run_test"}, "verification_kind": "test_run",
		"definition_version": 1, "enabled": false,
		"existing_test": map[string]any{"definition_id": testID, "definition_version": 1},
	}
	marshal := func(value any) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	mutate := func(action, key string, expected int64, value map[string]any, sequence int) (WorkflowMutationResult, error) {
		op := "updateSecurityAgent"
		resourceID := agentID
		if action == "create" {
			op = "createSecurityAgent"
			resourceID = ""
		} else if action == "delete" {
			op = "deleteSecurityAgent"
		}
		input := make(map[string]any, len(value))
		for k, v := range value {
			input[k] = v
		}
		if action == "create" {
			delete(input, "id")
		}
		intent := marshal(map[string]any{"resource_id": resourceID, "expected_version": expected, "body": input})
		correlation := fmt.Sprintf("pid_89000022-0000-4000-8000-%012d", sequence)
		var raw json.RawMessage
		query := postgresSecurityAgentDefinitionMutateSQL
		args := []any{action, agentID, org, ws, env, actor, op, key, expected, intent, marshal(value), fmt.Sprintf("pid_89000023-0000-4000-8000-%012d", sequence), correlation, fmt.Sprintf("pid_89000024-0000-4000-8000-%012d", sequence)}
		if versioned {
			query = postgresSecurityAgentExistingTestDefinitionMutateSQL
			args = append(args, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
		}
		err := api.QueryRow(ctx, query, args...).Scan(&raw)
		var result WorkflowMutationResult
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	created, err := mutate("create", "existing-test-draft-create-0001", 0, body, 1)
	if err != nil || created.Version != 1 || created.Replayed {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	if !equalIntegrationJSON(created.Body, marshal(body)) {
		t.Fatalf("created body lost intent: %s", created.Body)
	}
	if versioned {
		input := make(map[string]any, len(body))
		for key, value := range body {
			if key != "id" {
				input[key] = value
			}
		}
		intent := marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": input})
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, org, ws, env, actor, "createSecurityAgent", "existing-test-draft-create-0001", intent, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatalf("versioned pre-mutation replay: %v", err)
		}
		var replay workflowReplayEnvelope
		if json.Unmarshal(raw, &replay) != nil || !replay.Found || !replay.Result.Replayed || replay.Result.Version != 1 || !equalIntegrationJSON(replay.Result.Body, created.Body) {
			t.Fatalf("versioned replay lost immutable result: %s", raw)
		}
	}
	replay, err := mutate("create", "existing-test-draft-create-0001", 0, body, 1)
	if err != nil || !replay.Replayed || replay.Version != created.Version || !equalIntegrationJSON(replay.Body, created.Body) {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT d.body=$5::jsonb AND d.version=1 AND d.definition_version=1 AND d.activation='draft'
 AND v.definition=d.body AND v.version=d.version AND v.actor_id=$6
 AND (SELECT count(*) FROM zasp_workflow_receipts r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.resource_id)=($1,$2,$3,$4))=1
 FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions v USING(organization_id,workspace_id,environment_id,definition_id)
 WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, org, ws, env, agentID, marshal(body), actor).Scan(&exact); err != nil || !exact {
		t.Fatalf("stored draft/version/receipt mismatch: %v", err)
	}

	// Every refused update must leave the complete scoped authority unchanged.
	snapshot := func() json.RawMessage {
		t.Helper()
		var value json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'definition',(SELECT to_jsonb(d) FROM zasp_security_agent_definitions d WHERE definition_id=$1 AND (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 'history',(SELECT jsonb_agg(to_jsonb(v) ORDER BY version) FROM zasp_security_agent_definition_versions v WHERE definition_id=$1 AND (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 'workflow',(SELECT to_jsonb(w) FROM zasp_workflow_records w WHERE kind='security_agent' AND id=$1 AND (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM zasp_workflow_receipts r WHERE resource_id=$1 AND (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_workflow_audit a WHERE resource_id=$1 AND (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 'idempotency',(SELECT jsonb_agg(to_jsonb(i) ORDER BY idempotency_key) FROM zasp_workflow_idempotency i WHERE idempotency_key LIKE 'existing-test-draft-%' AND (organization_id,workspace_id,environment_id)=($2,$3,$4)))`, agentID, org, ws, env).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for index, tc := range []struct {
		name      string
		reference any
		actions   []string
	}{
		{"missing", nil, []string{"run_test"}},
		{"null", json.RawMessage(`null`), []string{"run_test"}},
		{"versionless", map[string]any{"definition_id": testID}, []string{"run_test"}},
		{"zero_version", map[string]any{"definition_id": testID, "definition_version": 0}, []string{"run_test"}},
		{"excess_version", map[string]any{"definition_id": testID, "definition_version": 1000001}, []string{"run_test"}},
		{"string_version", map[string]any{"definition_id": testID, "definition_version": "1"}, []string{"run_test"}},
		{"fractional_version", map[string]any{"definition_id": testID, "definition_version": 1.5}, []string{"run_test"}},
		{"noncanonical_id", map[string]any{"definition_id": " " + testID, "definition_version": 1}, []string{"run_test"}},
		{"stale", map[string]any{"definition_id": testID, "definition_version": 2}, []string{"run_test"}},
		{"absent_test", map[string]any{"definition_id": "pid_89000025-0000-4000-8000-000000000001", "definition_version": 1}, []string{"run_test"}},
		{"override", map[string]any{"definition_id": testID, "definition_version": 1, "prompt": "override"}, []string{"run_test"}},
		{"other_action", body["existing_test"], []string{"update_finding_response"}},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			before := snapshot()
			candidate := make(map[string]any, len(body))
			for k, v := range body {
				candidate[k] = v
			}
			candidate["allowed_actions"] = tc.actions
			if tc.name == "other_action" {
				candidate["verification_kind"] = "finding_state"
			}
			candidate["existing_test"] = tc.reference
			if tc.reference == nil {
				delete(candidate, "existing_test")
			}
			_, err := mutate("update", "existing-test-draft-"+tc.name, 1, candidate, index+2)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || (pg.Code != "22023" && pg.Code != "40001") {
				t.Fatalf("unsafe draft accepted or unexpected error: %v", err)
			}
			if !equalIntegrationJSON(snapshot(), before) {
				t.Fatal("refused draft changed durable authority")
			}
		}) {
			// An incorrectly accepted update changes the version and would make
			// later cases pass on stale CAS instead of their intended refusal.
			t.FailNow()
		}
	}
	// Disabling the actual selected test must prevent a new draft version, even
	// when its ID/version and the caller's definition version are still current.
	// The final successful update below is the enabled-state positive control.
	if !t.Run("disabled_test", func(t *testing.T) {
		command, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=false WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4) AND enabled`, org, ws, env, testID)
		if err != nil || command.RowsAffected() != 1 {
			t.Fatalf("disable selected test: rows=%d err=%v", command.RowsAffected(), err)
		}
		defer func() {
			command, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4) AND NOT enabled`, org, ws, env, testID)
			if err != nil || command.RowsAffected() != 1 {
				t.Errorf("restore selected test: rows=%d err=%v", command.RowsAffected(), err)
			}
		}()
		before := snapshot()
		_, err = mutate("update", "existing-test-draft-disabled", 1, body, 30)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatalf("disabled test accepted or unexpected error: %v", err)
		}
		if !equalIntegrationJSON(snapshot(), before) {
			t.Fatal("disabled-test refusal changed durable authority")
		}
	}) {
		t.FailNow()
	}
	// Each foreign test is usable through the registered API in its own scope.
	// Differ exactly one scope dimension at a time, including reused workspace
	// and environment IDs across organizations, before attempting substitution.
	for index, scope := range []struct{ name, org, ws, env string }{
		{"organization", "pid_9a000001-0000-4000-8000-000000000001", ws, env},
		{"workspace", org, "pid_89000031-0000-4000-8000-000000000001", env},
		{"environment", org, ws, "pid_89000032-0000-4000-8000-000000000001"},
	} {
		if !t.Run("foreign_"+scope.name, func(t *testing.T) {
			foreignTest := fmt.Sprintf("pid_89000033-0000-4000-8000-%012d", index+1)
			foreignTarget := fmt.Sprintf("pid_89000034-0000-4000-8000-%012d", index+1)
			foreignCredential := fmt.Sprintf("pid_89000035-0000-4000-8000-%012d", index+1)
			foreignAgent := fmt.Sprintf("pid_89000036-0000-4000-8000-%012d", index+1)
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Definition boundary') ON CONFLICT(organization_id,id) DO NOTHING;
 INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Definition boundary','staging');
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 VALUES($1,$2,$3,$4,'agent_endpoint','Boundary target','active',now(),now(),'agent',now(),now()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/definition_boundary_0001","target_kinds":["agent_endpoint"]}}');
 SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,$5,$4,'ref:red-team/definition_boundary_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 VALUES($1,$2,$3,$6,'Boundary test',$4,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded evaluation"]}',$7)`, pgx.QueryExecModeSimpleProtocol, scope.org, scope.ws, scope.env, foreignTarget, foreignCredential, foreignTest, actor); err != nil {
				t.Fatal(err)
			}
			primaryOrg, primaryWS, primaryEnv, primaryAgent := org, ws, env, agentID
			defer func() { org, ws, env, agentID = primaryOrg, primaryWS, primaryEnv, primaryAgent }()
			foreignBody := make(map[string]any, len(body))
			for k, v := range body {
				foreignBody[k] = v
			}
			foreignBody["id"] = foreignAgent
			foreignBody["environment_ids"] = []string{scope.env}
			foreignBody["existing_test"] = map[string]any{"definition_id": foreignTest, "definition_version": 1}
			org, ws, env, agentID = scope.org, scope.ws, scope.env, foreignAgent
			positive, err := mutate("create", "existing-test-draft-boundary-"+scope.name, 0, foreignBody, 100+index)
			if err != nil || positive.Version != 1 || positive.Replayed || !equalIntegrationJSON(positive.Body, marshal(foreignBody)) {
				t.Fatalf("foreign positive control=%+v err=%v", positive, err)
			}
			foreignBefore := snapshot()
			org, ws, env, agentID = primaryOrg, primaryWS, primaryEnv, primaryAgent
			primaryBefore := snapshot()
			candidate := make(map[string]any, len(body))
			for k, v := range body {
				candidate[k] = v
			}
			candidate["existing_test"] = foreignBody["existing_test"]
			_, err = mutate("update", "existing-test-draft-cross-"+scope.name, 1, candidate, 110+index)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("cross-scope reference accepted or unexpected error: %v", err)
			}
			if !equalIntegrationJSON(snapshot(), primaryBefore) {
				t.Fatal("cross-scope refusal changed primary authority")
			}
			org, ws, env, agentID = scope.org, scope.ws, scope.env, foreignAgent
			if !equalIntegrationJSON(snapshot(), foreignBefore) {
				t.Fatal("cross-scope refusal changed foreign authority")
			}
		}) {
			t.FailNow()
		}
	}
	body["name"] = "Pinned rerun test"
	body["allowed_actions"] = []string{"rerun_test"}
	updated, err := mutate("update", "existing-test-draft-update-0001", 1, body, 20)
	if err != nil || updated.Version != 2 || updated.Replayed || !equalIntegrationJSON(updated.Body, marshal(body)) {
		t.Fatalf("update=%+v err=%v", updated, err)
	}
	var readRaw json.RawMessage
	if err := api.QueryRow(ctx, postgresSecurityAgentDefinitionValueSQL, org, ws, env, agentID).Scan(&readRaw); err != nil {
		t.Fatal(err)
	}
	var read WorkflowValue
	if json.Unmarshal(readRaw, &read) != nil || read.Version != 2 || !equalIntegrationJSON(read.Body, marshal(body)) {
		t.Fatalf("registered API read lost pinned intent: %s", readRaw)
	}
	if err := owner.QueryRow(ctx, `SELECT d.body=$5::jsonb AND d.version=2 AND d.activation='draft'
 AND v.definition=d.body AND v.actor_id=$6 AND v.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256')
 AND (SELECT count(*) FROM zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4))=2
 AND (SELECT count(*) FROM zasp_workflow_receipts WHERE (organization_id,workspace_id,environment_id,resource_id)=($1,$2,$3,$4))=2
 FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions v USING(organization_id,workspace_id,environment_id,definition_id,version)
 WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, org, ws, env, agentID, marshal(body), actor).Scan(&exact); err != nil || !exact {
		t.Fatalf("updated history/receipt authority mismatch: %v", err)
	}
	// A later operator can save a legacy non-test draft without rewriting the
	// provenance of either earlier version. Old idempotency replays stay exact.
	originalActor := actor
	actor = "pid_89000026-0000-4000-8000-000000000001"
	body["allowed_actions"] = []string{"update_finding_response"}
	body["verification_kind"] = "finding_state"
	delete(body, "existing_test")
	legacy, err := mutate("update", "existing-test-draft-legacy-update", 2, body, 40)
	if err != nil || legacy.Version != 3 || !equalIntegrationJSON(legacy.Body, marshal(body)) {
		t.Fatalf("legacy update=%+v err=%v", legacy, err)
	}
	if err := owner.QueryRow(ctx, `SELECT jsonb_agg(actor_id ORDER BY version)=jsonb_build_array($5::text,$5::text,$6::text) FROM zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, agentID, originalActor, actor).Scan(&exact); err != nil || !exact {
		t.Fatalf("later mutation rewrote earlier provenance: %v", err)
	}
	var originalBody map[string]any
	if err := json.Unmarshal(created.Body, &originalBody); err != nil {
		t.Fatal(err)
	}
	later := snapshot()
	actor = originalActor
	oldReplay, err := mutate("create", "existing-test-draft-create-0001", 0, originalBody, 1)
	if err != nil || !oldReplay.Replayed || oldReplay.Version != 1 || !equalIntegrationJSON(oldReplay.Body, created.Body) || !equalIntegrationJSON(snapshot(), later) {
		t.Fatalf("old replay changed current authority: %+v err=%v", oldReplay, err)
	}
	// Exercise legacy creation/deletion through the same registered mutation.
	agentID = "pid_89000027-0000-4000-8000-000000000001"
	body["id"] = agentID
	legacy, err = mutate("create", "existing-test-draft-legacy-create", 0, body, 41)
	if err != nil || legacy.Version != 1 || !equalIntegrationJSON(legacy.Body, marshal(body)) {
		t.Fatalf("legacy create=%+v err=%v", legacy, err)
	}
	if err := api.QueryRow(ctx, postgresSecurityAgentDefinitionValueSQL, org, ws, env, agentID).Scan(&readRaw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(readRaw, &read) != nil || read.Version != 1 || !equalIntegrationJSON(read.Body, marshal(body)) {
		t.Fatalf("legacy read lost body: %s", readRaw)
	}
	deleted, err := mutate("delete", "existing-test-draft-legacy-delete", 1, map[string]any{}, 42)
	if err != nil || deleted.Version != 2 || deleted.Replayed {
		t.Fatalf("legacy delete=%+v err=%v", deleted, err)
	}
	if err := owner.QueryRow(ctx, `SELECT d.deleted_at IS NOT NULL AND v.actor_id=$5 FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions v USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, org, ws, env, agentID, actor).Scan(&exact); err != nil || !exact {
		t.Fatalf("legacy delete provenance mismatch: %v", err)
	}
}
