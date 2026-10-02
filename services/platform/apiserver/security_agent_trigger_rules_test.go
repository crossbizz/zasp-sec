package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Catches dropped or overpermissive configured rules at the real HTTP body
// boundary before canonicalization can erase duplicate/alternate-cased keys.
func TestTemporalAutomaticRulesHTTPBody(t *testing.T) {
	base := `{"name":"Configured responder","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["update_finding_response"],"verification_kind":"finding_state","definition_version":1,"enabled":false}`
	for _, tc := range []struct {
		name, rule string
		valid      bool
	}{
		{"legacy omitted", "", true},
		{"manual", `{"version":1,"mode":"manual"}`, true},
		{"finding", `{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"high"}}`, true},
		{"null", `null`, false},
		{"wrong family", `{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"network","minimum_severity":"high"}}`, false},
		{"missing cooldown", `{"version":1,"mode":"automatic","finding":{"family":"credential","minimum_severity":"high"}}`, false},
		{"duplicate key", `{"version":1,"mode":"automatic","mode":"manual"}`, false},
		{"alternate case", `{"version":1,"Mode":"manual"}`, false},
		{"manual extra", `{"version":1,"mode":"manual","cooldown_seconds":600}`, false},
		{"wrong kind", `{"version":1,"mode":"automatic","cooldown_seconds":600,"attack_path":{"state":"verified"}}`, false},
		{"unknown severity", `{"version":1,"mode":"automatic","cooldown_seconds":600,"finding":{"family":"credential","minimum_severity":"severe"}}`, false},
		{"zero cooldown", `{"version":1,"mode":"automatic","cooldown_seconds":0,"finding":{"family":"credential","minimum_severity":"high"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := base
			if tc.rule != "" {
				raw = base[:len(base)-1] + `,"trigger_rules":` + tc.rule + `}`
			}
			req := httptest.NewRequest("POST", "/api/v1/security-agents", bytes.NewBufferString(raw))
			body, _, err := securityAgentBody(req, fixtureRequestIdentity(t).Scope, "pid_90000001-0000-4000-8000-000000000001", true, true, true, true)
			if (err == nil) != tc.valid {
				t.Fatalf("configured body accepted=%v want=%v error=%v", err == nil, tc.valid, err)
			}
			if err != nil {
				return
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			if tc.rule == "" {
				if _, ok := got["trigger_rules"]; ok {
					t.Fatal("legacy omission changed")
				}
				return
			}
			var want, value any
			if json.Unmarshal([]byte(tc.rule), &want) != nil || json.Unmarshal(got["trigger_rules"], &value) != nil {
				t.Fatal("configured rule was not retained")
			}
			wantJSON, _ := json.Marshal(want)
			valueJSON, _ := json.Marshal(value)
			if !bytes.Equal(wantJSON, valueJSON) {
				t.Fatalf("retained rule=%s want=%s", valueJSON, wantJSON)
			}
		})
	}
}

type automaticRuleCapabilityRepository struct {
	*workflowRepositoryStub
	testReady bool
	labCalls  int
}

func (r *automaticRuleCapabilityRepository) SecurityAgentExistingTestDefinitionsAvailable(context.Context) (bool, error) {
	if !r.testReady {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}
func (r *automaticRuleCapabilityRepository) SecurityAgentAttackLabAvailable(context.Context) (bool, error) {
	r.labCalls++
	return false, ErrRepositoryUnavailable
}

func TestTemporalAutomaticRulesRequestedCapabilities(t *testing.T) {
	base := `{"name":"Configured responder","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":false,"existing_test":{"definition_id":"pid_89000012-0000-4000-8000-000000000002","definition_version":7}}`
	for _, tc := range []struct {
		name, body       string
		ready            bool
		status, labCalls int
	}{
		{"legacy test unrelated lab", base, true, 201, 0},
		{"configured test unrelated lab", base[:len(base)-1] + `,"trigger_rules":{"version":1,"mode":"manual"}}`, true, 201, 0},
		{"requested test unavailable", base, false, 503, 0},
		{"requested lab unavailable", strings.ReplaceAll(strings.ReplaceAll(base, `"run_test"`, `"start_attack_lab"`), `"test_run"`, `"attack_lab_run"`), true, 503, 1},
		{"mixed includes lab", strings.Replace(base, `["run_test"]`, `["run_test","start_attack_lab"]`, 1), true, 503, 1},
		{"invalid list", strings.Replace(base, `["run_test"]`, `"run_test"`, 1), true, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &automaticRuleCapabilityRepository{workflowRepositoryStub: &workflowRepositoryStub{}, testReady: tc.ready}
			h, err := newWorkflowHTTPHandler(r, securityAgentTestSigningKey, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			req := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", tc.body)
			req.Header.Set("Idempotency-Key", "automatic77-capability-test")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != tc.status || r.labCalls != tc.labCalls {
				t.Fatalf("status=%d labCalls=%d want=%d/%d: %s", response.Code, r.labCalls, tc.status, tc.labCalls, response.Body.String())
			}
		})
	}
}
