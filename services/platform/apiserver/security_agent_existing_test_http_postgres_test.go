package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Real handler/repository/registered DB integration. Identity is supplied at the
// handler boundary; this does not prove authentication middleware or deployment.
func TestSecurityAgentExistingTestHTTPPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		identity := fixtureRequestIdentity(t)
		organization, _ := domain.ParseProductID(org)
		workspace, _ := domain.ParseProductID(ws)
		environment, _ := domain.ParseProductID(env)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		var err error
		identity.Scope, err = domain.NewScope(organization, workspace, environment)
		if err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatalf("real repository construction: %v", err)
		}
		if available, err := repository.SecurityAgentExistingTestDefinitionsAvailable(ctx); err != nil || !available {
			t.Fatalf("healthy55 draft capability: %v %v", available, err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if available, err := repository.SecurityAgentExistingTestDefinitionsAvailable(cancelled); err == nil || available {
			t.Fatalf("cancelled draft capability: %v %v", available, err)
		}
		runner := precisionMigrationRunner(t, owner)
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		if available, err := repository.SecurityAgentExistingTestDefinitionsAvailable(ctx); err != nil || available {
			t.Fatalf("warm54 draft capability: %v %v", available, err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		if available, err := repository.SecurityAgentExistingTestDefinitionsAvailable(ctx); err != nil || !available {
			t.Fatalf("warm55 draft capability: %v %v", available, err)
		}
		handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"name": "HTTP pinned draft", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{env}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 1, "allowed_actions": []string{"run_test"}, "verification_kind": "test_run", "definition_version": 1, "enabled": false, "existing_test": map[string]any{"definition_id": testID, "definition_version": 1}}
		var id string
		var created, createdInput json.RawMessage
		for index, operation := range []string{"createSecurityAgent", "updateSecurityAgent"} {
			method, path, status := http.MethodPost, "/api/v1/security-agents", http.StatusCreated
			var parameters map[string]string
			if index == 1 {
				method, path, status = http.MethodPatch, path+"/"+id, http.StatusOK
				parameters = map[string]string{"id": id}
				body["id"] = id
				body["name"] = "HTTP pinned rerun"
				body["allowed_actions"] = []string{"rerun_test"}
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			call := func() *httptest.ResponseRecorder {
				request := workflowRequest(t, identity, fmt.Sprintf("pid_89000061-0000-4000-8000-%012d", index+1), operation, parameters, method, path, string(raw))
				request.Header.Set("Idempotency-Key", fmt.Sprintf("existing-test-http-%d-0001", index))
				if index == 1 {
					request.Header.Set("If-Match", `"1"`)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				return response
			}
			response := call()
			if response.Code != status {
				t.Fatalf("%s status=%d body=%s", operation, response.Code, response.Body.String())
			}
			var result struct {
				ID           string          `json:"id"`
				ExistingTest json.RawMessage `json:"existing_test"`
				Enabled      bool            `json:"enabled"`
			}
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || !validProductID(result.ID) || result.Enabled || !equalIntegrationJSON(result.ExistingTest, []byte(`{"definition_id":"`+testID+`","definition_version":1}`)) {
				t.Fatalf("HTTP lost pinned draft: %s", response.Body.String())
			}
			id = result.ID
			if index == 0 {
				created = append(json.RawMessage(nil), response.Body.Bytes()...)
				createdInput = append(json.RawMessage(nil), raw...)
			}
			replay := call()
			if replay.Code != status || !equalIntegrationJSON(replay.Body.Bytes(), response.Body.Bytes()) {
				t.Fatalf("HTTP replay changed response: status=%d body=%s", replay.Code, replay.Body.String())
			}
			stored, err := repository.GetWorkflow(ctx, identity.Scope, "security_agent", id)
			if err != nil || stored.Version != int64(index+1) {
				t.Fatalf("stored version: %+v %v", stored, err)
			}
			body["id"] = id
			expected, err := json.Marshal(body)
			if err != nil || !equalIntegrationJSON(stored.Body, expected) {
				t.Fatalf("stored draft differs from submitted intent: %s %v", stored.Body, err)
			}
			var exact bool
			if err := owner.QueryRow(ctx, `SELECT d.body=$5::jsonb AND d.activation='draft' AND v.definition=d.body AND v.actor_id=$6 AND (SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition_id=$4)=$7 FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions v USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,$4)`, org, ws, env, id, stored.Body, actor, index+1).Scan(&exact); err != nil || !exact {
				t.Fatalf("HTTP durable draft/history: %v %v", exact, err)
			}
		}
		for index, test := range []struct {
			name      string
			reference any
			enabled   bool
			status    int
		}{
			{"stale", map[string]any{"definition_id": testID, "definition_version": 2}, false, http.StatusConflict},
			{"missing_test", map[string]any{"definition_id": "pid_89000071-0000-4000-8000-000000000001", "definition_version": 1}, false, http.StatusConflict},
			{"null_reference", nil, false, http.StatusBadRequest},
			{"activation_not_available", body["existing_test"], true, http.StatusBadRequest},
		} {
			candidate := make(map[string]any, len(body))
			for key, value := range body {
				candidate[key] = value
			}
			candidate["existing_test"] = test.reference
			candidate["enabled"] = test.enabled
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, fmt.Sprintf("pid_89000061-0000-4000-8000-%012d", index+10), "updateSecurityAgent", map[string]string{"id": id}, http.MethodPatch, "/api/v1/security-agents/"+id, string(raw))
			request.Header.Set("Idempotency-Key", "existing-test-http-refused-"+test.name)
			request.Header.Set("If-Match", `"2"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("%s HTTP refusal=%d body=%s", test.name, response.Code, response.Body.String())
			}
			stored, err := repository.GetWorkflow(ctx, identity.Scope, "security_agent", id)
			expected, _ := json.Marshal(body)
			if err != nil || stored.Version != 2 || !equalIntegrationJSON(stored.Body, expected) {
				t.Fatalf("%s refusal changed draft: %+v %v", test.name, stored, err)
			}
		}
		readRequest := workflowRequest(t, identity, "pid_89000061-0000-4000-8000-000000000020", "getSecurityAgent", map[string]string{"id": id}, http.MethodGet, "/api/v1/security-agents/"+id, "")
		readResponse := httptest.NewRecorder()
		handler.ServeHTTP(readResponse, readRequest)
		expectedRead, _ := json.Marshal(body)
		if readResponse.Code != http.StatusOK || !equalIntegrationJSON(readResponse.Body.Bytes(), expectedRead) {
			t.Fatalf("HTTP GET lost persisted draft: %d %s", readResponse.Code, readResponse.Body.String())
		}
		replayCreate := func() *httptest.ResponseRecorder {
			request := workflowRequest(t, identity, "pid_89000061-0000-4000-8000-000000000001", "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", string(createdInput))
			request.Header.Set("Idempotency-Key", "existing-test-http-0-0001")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			return response
		}
		if response := replayCreate(); response.Code != http.StatusCreated || !equalIntegrationJSON(response.Body.Bytes(), created) {
			t.Fatalf("old create replay after update changed: %d %s", response.Code, response.Body.String())
		}
		if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO PUBLIC`); err != nil {
			t.Fatal(err)
		}
		if available, err := repository.SecurityAgentExistingTestDefinitionsAvailable(ctx); err == nil || available {
			t.Fatalf("drifted55 draft capability: %v %v", available, err)
		}
		if response := replayCreate(); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("replay bypassed drifted55: %d %s", response.Code, response.Body.String())
		}
		if _, err := owner.Exec(ctx, `REVOKE ALL ON FUNCTION zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM PUBLIC`); err != nil {
			t.Fatal(err)
		}
		if response := replayCreate(); response.Code != http.StatusCreated || !equalIntegrationJSON(response.Body.Bytes(), created) {
			t.Fatalf("restored55 replay failed: %d %s", response.Code, response.Body.String())
		}
		var counts bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_definition_versions WHERE definition_id=$1)=2 AND (SELECT count(*) FROM zasp_workflow_receipts WHERE resource_id=$1)=2`, id).Scan(&counts); err != nil || !counts {
			t.Fatalf("HTTP replay/drift duplicated writes: %v %v", counts, err)
		}
	})
}
