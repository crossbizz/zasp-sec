package securityagent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func monitorDefinitionFromWire(t *testing.T, mode string) SecurityAgent {
	t.Helper()
	agent := fixtureAgent()
	agent.Limits.MaxSteps = 1
	agent.Limits.TemporaryPolicyTTL = 600 * time.Second
	raw, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"temporary_policy_mode":`+mode+`}`)...)
	if err := json.Unmarshal(raw, &agent); err != nil {
		t.Fatal(err)
	}
	return agent
}

func TestTemporaryPolicyMonitorDefinitionPlannerBinding(t *testing.T) {
	agent := monitorDefinitionFromWire(t, `"monitor"`)
	if err := ValidateAgent(agent); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	action, _ := NewTemporaryPolicyAction(&fakePolicyService{})
	if err := registry.Register(action); err != nil {
		t.Fatal(err)
	}
	scope := PlannerScope{OrganizationID: "org-a", WorkspaceID: "ws-a", EnvironmentID: "env-a", RunID: "run-a", AllowedReferences: map[string]bool{"env-a": true}}
	plan := Plan{Version: 1, Summary: "Observe scoped traffic temporarily", Steps: []PlanStep{{Index: 0, ActionKey: "create_temporary_policy", Parameters: map[string]string{"mode": "monitor", "scope": "env-a", "ttl": "10m"}}}}
	if err := ValidatePlannerOutput(plan, agent, scope, registry, 1); err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Parameters["mode"] = "block"
	if err := ValidatePlannerOutput(plan, agent, scope, registry, 1); err == nil {
		t.Fatal("planner escalated saved Monitor to Block")
	}
	plan.Steps[0].Parameters["mode"] = "monitor"
	plan.Steps[0].Parameters["ttl"] = "11m"
	if err := ValidatePlannerOutput(plan, agent, scope, registry, 1); err == nil {
		t.Fatal("planner exceeded persisted TTL")
	}
	plan.Steps[0].Parameters["ttl"] = "10m"
	scope.OrganizationID = "org-b"
	if err := ValidatePlannerOutput(plan, agent, scope, registry, 1); err == nil {
		t.Fatal("cross-tenant Monitor plan accepted")
	}
	for _, mutate := range []func(*SecurityAgent){func(a *SecurityAgent) { a.Autonomy = AutonomyAutonomous }, func(a *SecurityAgent) { a.Limits.MaxSteps = 2 }, func(a *SecurityAgent) { a.AllowedActions = []string{"create_temporary_policy", "run_test"} }, func(a *SecurityAgent) { a.Verification.Kind = "test_run" }} {
		invalid := agent
		mutate(&invalid)
		if ValidateAgent(invalid) == nil {
			t.Fatal("Monitor accepted unsafe definition family")
		}
	}
}

func TestTemporaryPolicyMonitorPersistsModeWithoutChangingLegacySerialization(t *testing.T) {
	monitor := monitorDefinitionFromWire(t, `"monitor"`)
	repo := NewMemoryRepository()
	if err := repo.CreateAgent(context.Background(), monitor); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetAgent(context.Background(), "org-a", monitor.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(agentJSON(got))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"temporary_policy_mode":"monitor"`) {
		t.Fatalf("lost persisted selection: %s", raw)
	}
	legacy, err := json.Marshal(agentJSON(fixtureAgent()))
	if err != nil || strings.Contains(string(legacy), "temporary_policy_mode") {
		t.Fatalf("changed legacy omission: %s %v", legacy, err)
	}
	if _, err := repo.GetAgent(context.Background(), "org-b", monitor.ID); err == nil {
		t.Fatal("cross-tenant persisted Monitor read")
	}
}
