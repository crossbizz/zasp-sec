package securityagent

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

type apiBatchAction struct{ executions int }

func (action *apiBatchAction) Metadata() ActionMetadata {
	return ActionMetadata{Key: "run_test", InputSchema: map[string]string{"test_definition_id": "string"}, RiskClass: "low", TargetTypes: []string{"test_definition"}, ApprovalFloor: "none", Reversible: true, Idempotent: true, VerificationKind: "test_run"}
}
func (action *apiBatchAction) Validate(context.Context, ActionRequest) error { return nil }
func (action *apiBatchAction) Execute(context.Context, ActionRequest) (ActionResult, error) {
	action.executions++
	return ActionResult{OutcomeID: "unexpected", State: "succeeded"}, nil
}
func (action *apiBatchAction) Verify(context.Context, ActionRequest, ActionResult) error { return nil }

func TestAuditEventsHashPlansAndRejectSensitiveMetadata(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	plan := Plan{Version: 1, Summary: "bounded response", Steps: []PlanStep{{Index: 0, ActionKey: "run_test", Parameters: map[string]string{"test_definition_id": "test-1"}}}}
	event, err := BuildAuditEvent("plan", "org-a", "agent-1", "run-1", plan, map[string]string{"decision": "allow"}, now)
	if err != nil || event.PlanHash == "" || strings.Contains(event.PlanHash, "test-1") || event.At != now {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	for _, kind := range []string{"trigger", "plan", "authorization", "approval", "execute", "verify", "terminal"} {
		if _, err := BuildAuditEvent(kind, "org-a", "agent-1", "run-1", Plan{}, map[string]string{"outcome": "bounded"}, now); err != nil {
			t.Fatalf("kind %q rejected: %v", kind, err)
		}
	}
	for _, key := range []string{"secret", "access_token", "raw_credential", "arguments"} {
		if _, err := BuildAuditEvent("execute", "org-a", "agent-1", "run-1", Plan{}, map[string]string{key: "seeded-sensitive-value"}, now); err == nil {
			t.Fatalf("sensitive metadata %q accepted", key)
		}
	}
}

func TestSecurityAgentAPIBatchIsScopedStableAndSideEffectFree(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository()
	registry := NewRegistry()
	action := &apiBatchAction{}
	if err := registry.Register(action); err != nil {
		t.Fatal(err)
	}
	agent := fixtureAgent()
	agent.AllowedActions = []string{"run_test"}
	agent.Verification = Verification{Kind: "test_run"}
	agent.Autonomy = AutonomyAutonomous
	if err := repo.CreateAgent(context.Background(), agent); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{
		Repository:  repo,
		Registry:    registry,
		Plans:       NewPlanStore(),
		Templates:   BuiltInTemplates(),
		Now:         func() time.Time { return now },
		NewID:       func(kind string) string { return kind + "-manual-1" },
		Permissions: func(context.Context, string, string) bool { return true },
		ReferenceAuthorized: func(_ context.Context, organizationID, environmentID, kind, id string) bool {
			return organizationID == "org-a" && environmentID == "env-a" && kind == "finding" && id == "finding-1"
		},
		Planner: func(context.Context, SecurityAgent, PlannerScope, []string) (Plan, error) {
			return Plan{Version: 1, Summary: "bounded", Steps: []PlanStep{{Index: 0, ActionKey: "run_test", Parameters: map[string]string{"test_definition_id": "finding-1"}}}}, nil
		},
		FreshAuth: func(context.Context, string, time.Time) bool { return true },
		Enqueue:   func(context.Context, RunJob) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Zasp-Organization", "org-a")
		request.Header.Set("X-Zasp-Workspace", "workspace-a")
		request.Header.Set("X-Zasp-Environment", "env-a")
		request.Header.Set("X-Zasp-Principal", "principal-a")
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	for _, target := range []string{"/api/v1/security-agent-templates", "/api/v1/security-actions", "/api/v1/security-agents?limit=10"} {
		if response := call(http.MethodGet, target, ""); response.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", target, response.Code, response.Body.String())
		}
	}
	validDefinition := `{"id":"","name":"Bounded response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["env-a"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`
	if response := call(http.MethodPost, "/api/v1/security-agents", validDefinition); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"temporary_policy_seconds":3600`) || !strings.Contains(response.Body.String(), `"ai_token_budget":4000`) || !strings.Contains(response.Body.String(), `"concurrency_limit":2`) {
		t.Fatalf("create=%d %s", response.Code, response.Body.String())
	}
	for _, testCase := range [][2]string{{`"temporary_policy_seconds":3600`, `"temporary_policy_seconds":86401`}, {`"ai_token_budget":4000`, `"ai_token_budget":12001`}, {`"concurrency_limit":2`, `"concurrency_limit":11`}} {
		invalidLimits := strings.Replace(validDefinition, testCase[0], testCase[1], 1)
		if response := call(http.MethodPost, "/api/v1/security-agents", invalidLimits); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid limits accepted: %s => %d %s", testCase[1], response.Code, response.Body.String())
		}
	}
	incompatibleVerification := strings.Replace(validDefinition, `"id":""`, `"id":"agent-incompatible"`, 1)
	incompatibleVerification = strings.Replace(incompatibleVerification, `"verification_kind":"test_run"`, `"verification_kind":"export"`, 1)
	if response := call(http.MethodPost, "/api/v1/security-agents", incompatibleVerification); response.Code != http.StatusBadRequest {
		t.Fatalf("incompatible verification accepted: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/api/v1/security-agents/agent-1/simulate", `{"goal":"contain","environment_id":"env-a","evidence_ids":["finding-1"]}`); response.Code != http.StatusOK || action.executions != 0 || !strings.Contains(response.Body.String(), `"authorization":"allow"`) {
		t.Fatalf("simulate=%d %s executions=%d", response.Code, response.Body.String(), action.executions)
	}
	if response := call(http.MethodPost, "/api/v1/security-agents/agent-1/runs", `{"environment_id":"env-foreign","trigger_kind":"finding","trigger_id":"finding-1"}`); response.Code != http.StatusForbidden {
		t.Fatalf("cross-scope run=%d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/api/v1/security-agents/agent-1/runs", `{"environment_id":"env-a","trigger_kind":"finding","trigger_id":"finding-1"}`); response.Code != http.StatusCreated {
		t.Fatalf("manual run=%d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/api/v1/security-agent-runs?agent_id=agent-1&status=queued&environment_id=env-a&limit=10", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "run-manual-1") {
		t.Fatalf("runs=%d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/api/v1/security-agent-runs/run-manual-1", ""); response.Code != http.StatusOK || strings.Contains(response.Body.String(), "finding-1\"") && strings.Contains(response.Body.String(), "parameters") {
		t.Fatalf("detail=%d %s", response.Code, response.Body.String())
	}
	foreign := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/security-agents/agent-1", nil)
	request.Header.Set("X-Zasp-Organization", "org-foreign")
	request.Header.Set("X-Zasp-Workspace", "workspace-a")
	request.Header.Set("X-Zasp-Environment", "env-a")
	request.Header.Set("X-Zasp-Principal", "principal-a")
	handler.ServeHTTP(foreign, request)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign=%d %s", foreign.Code, foreign.Body.String())
	}

	invalid := call(http.MethodPost, "/api/v1/security-agents", `{}`)
	var envelope map[string]any
	if invalid.Code != http.StatusBadRequest || json.Unmarshal(invalid.Body.Bytes(), &envelope) != nil || envelope["code"] != "security_agent_invalid" {
		t.Fatalf("invalid=%d %s", invalid.Code, invalid.Body.String())
	}
}
