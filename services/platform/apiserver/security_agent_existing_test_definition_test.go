package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The handler must retain bounded operator intent without exposing execution.
// Scope/version/safety authorization remains the database mutation's job.
func TestSecurityAgentExistingTestDefinitionContract(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	const id = "pid_90000001-0000-4000-8000-000000000001"
	const ref = `{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":7}`
	for _, create := range []bool{true, false} {
		for _, tc := range []struct {
			name, actions, verification, reference, extra string
			enabled, valid                                bool
		}{
			{name: "run_draft", actions: `["run_test"]`, verification: "test_run", reference: ref, valid: true},
			{name: "rerun_draft", actions: `["rerun_test"]`, verification: "test_run", reference: ref, valid: true},
			{name: "legacy_other_action", actions: `["update_finding_response"]`, verification: "finding_state", valid: true},
			{name: "missing", actions: `["run_test"]`, verification: "test_run"},
			{name: "null", actions: `["run_test"]`, verification: "test_run", reference: "null"},
			{name: "versionless", actions: `["run_test"]`, verification: "test_run", reference: `{"definition_id":"pid_89000012-0000-4000-8000-000000000002"}`},
			{name: "zero_version", actions: `["run_test"]`, verification: "test_run", reference: strings.Replace(ref, ":7", ":0", 1)},
			{name: "string_version", actions: `["run_test"]`, verification: "test_run", reference: strings.Replace(ref, ":7", `:"7"`, 1)},
			{name: "fraction_version", actions: `["run_test"]`, verification: "test_run", reference: strings.Replace(ref, ":7", ":7.5", 1)},
			{name: "noncanonical_id", actions: `["run_test"]`, verification: "test_run", reference: strings.Replace(ref, "pid_", "PID_", 1)},
			{name: "prompt_override", actions: `["run_test"]`, verification: "test_run", reference: strings.TrimSuffix(ref, "}") + `,"prompt":"override"}`},
			{name: "duplicate_nested", actions: `["run_test"]`, verification: "test_run", reference: strings.TrimSuffix(ref, "}") + `,"definition_version":7}`},
			{name: "duplicate_reference", actions: `["run_test"]`, verification: "test_run", reference: ref, extra: `,"existing_test":` + ref},
			{name: "casing_alias", actions: `["run_test"]`, verification: "test_run", extra: `,"EXISTING_TEST":` + ref},
			{name: "casing_duplicate", actions: `["run_test"]`, verification: "test_run", reference: ref, extra: `,"EXISTING_TEST":` + ref},
			{name: "oversized", actions: `["run_test"]`, verification: "test_run", reference: ref, extra: strings.Repeat(" ", 16*1024)},
			{name: "null_name", actions: `["run_test"]`, verification: "test_run", reference: ref},
			{name: "missing_enabled", actions: `["run_test"]`, verification: "test_run", reference: ref},
			{name: "wrong_verification", actions: `["run_test"]`, verification: "finding_state", reference: ref},
			{name: "other_action_reference", actions: `["update_finding_response"]`, verification: "finding_state", reference: ref},
			{name: "mixed_actions", actions: `["run_test","update_finding_response"]`, verification: "test_run", reference: ref},
			{name: "two_tests", actions: `["run_test","rerun_test"]`, verification: "test_run", reference: ref},
			{name: "cannot_enable", actions: `["run_test"]`, verification: "test_run", reference: ref, enabled: true},
			{name: "unknown_top_field", actions: `["run_test"]`, verification: "test_run", reference: ref, extra: `,"target_url":"https://other.invalid"`},
			{name: "trailing_document", actions: `["run_test"]`, verification: "test_run", reference: ref, extra: `} {`},
		} {
			prefix := "create/"
			if !create {
				prefix = "update/"
			}
			t.Run(prefix+tc.name, func(t *testing.T) {
				fields := map[string]any{"name": "Existing test response", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{identity.Scope.EnvironmentID().String()}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "concurrency_limit": 1, "allowed_actions": json.RawMessage(tc.actions), "verification_kind": tc.verification, "definition_version": 1, "enabled": tc.enabled}
				if !create {
					fields["id"] = id
				}
				if tc.name == "null_name" {
					fields["name"] = nil
				}
				if tc.name == "missing_enabled" {
					delete(fields, "enabled")
				}
				raw, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				body := strings.TrimSuffix(string(raw), "}")
				if tc.reference != "" {
					body += `,"existing_test":` + tc.reference
				}
				body += tc.extra + "}"
				result, resultID, err := securityAgentBody(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), identity.Scope, id, create, false, false, true)
				if !tc.valid {
					if err == nil {
						t.Fatalf("unsafe intent accepted: %s", result)
					}
					return
				}
				if err != nil || resultID != id {
					t.Fatalf("valid intent rejected: %v", err)
				}
				var persisted map[string]json.RawMessage
				if err := json.Unmarshal(result, &persisted); err != nil {
					t.Fatal(err)
				}
				if string(persisted["existing_test"]) != tc.reference {
					t.Fatalf("reference lost/changed: %s", persisted["existing_test"])
				}
				if string(persisted["enabled"]) != "false" {
					t.Fatal("draft enabled")
				}
			})
		}
	}
}

func TestSecurityAgentExistingTestDefinitionRequiresDurableCapability(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{}
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"Existing test draft","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + identity.Scope.EnvironmentID().String() + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":false,"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":7}}`
	request := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", body)
	request.Header.Set("Idempotency-Key", "existing-test-unavailable-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.mutation.Operation != "" {
		t.Fatalf("unavailable durable capability accepted: status=%d mutation=%s", response.Code, repository.mutation.Operation)
	}
}

type existingTestDefinitionRepositoryStub struct{ *workflowRepositoryStub }

func (*existingTestDefinitionRepositoryStub) SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error) {
	return true, nil
}

func TestSecurityAgentExistingTestDefinitionHTTPRejectsAmbiguityBeforeReplay(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	body := `{"name":"Existing test draft","trigger_kind":"finding","trigger_source":"credential","environment_ids":["` + identity.Scope.EnvironmentID().String() + `"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":false,"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":7}}`
	for _, tc := range []struct{ name, body string }{
		{"nested_duplicate", strings.Replace(body, `"definition_version":7}`, `"definition_version":7,"definition_version":8}`, 1)},
		{"outer_duplicate", strings.Replace(body, `"enabled":false`, `"enabled":true,"enabled":false`, 1)},
		{"casing_alias", strings.Replace(body, `"existing_test"`, `"EXISTING_TEST"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repository := &existingTestDefinitionRepositoryStub{&workflowRepositoryStub{}}
			handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", tc.body)
			request.Header.Set("Idempotency-Key", "existing-test-ambiguous-0001")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || repository.replayCalls != 0 || repository.mutationCalls != 0 {
				t.Fatalf("ambiguous input reached authority: status=%d replay=%d mutation=%d", response.Code, repository.replayCalls, repository.mutationCalls)
			}
		})
	}
}
