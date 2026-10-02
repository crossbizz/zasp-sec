package securityagent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test invocation cannot be undone. Advertising rollback in the catalog must
// fail this test even while the production execution capability remains off.
func TestExistingTestCatalogDoesNotPromiseRollback(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterResponseActions(registry, &fakeBuiltinBackend{}); err != nil {
		t.Fatal(err)
	}
	handler := &HTTPHandler{options: HTTPOptions{Registry: registry}}
	response := httptest.NewRecorder()
	handler.listActions(response, httptest.NewRequest(http.MethodGet, "/api/v1/security-agent-actions?target=test_definition", nil), requestScope{organizationID: "org-a", workspaceID: "workspace-a", environmentID: "env-a"})
	var body struct {
		Items []actionOutput `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Items) != 2 {
		t.Fatalf("catalog status=%d body=%s", response.Code, response.Body.String())
	}
	for index, key := range []string{"rerun_test", "run_test"} {
		t.Run(key, func(t *testing.T) {
			item := body.Items[index]
			if item.Key != key || item.Reversible || item.RiskClass != "low" || item.ApprovalFloor != "none" || item.VerificationKind != "test_run" {
				t.Errorf("test catalog promises unsupported behavior: %+v", item)
			}
			found := false
			for _, readiness := range ProductionActionReadiness() {
				if readiness.Key == key {
					found = true
					if readiness.Reversible || readiness.CleanupKind != "none" || readiness.ProductionState != "component-only" || readiness.MaximumAutonomy != "none" {
						t.Errorf("test readiness promises unsupported behavior: %+v", readiness)
					}
				}
			}
			if !found {
				t.Fatal("test readiness absent")
			}
			metadata, err := registry.Metadata(key)
			if err != nil {
				t.Fatal(err)
			}
			agent := fixtureAgent()
			agent.AllowedActions = []string{key}
			agent.Verification.Kind = "test_run"
			scope := PlannerScope{OrganizationID: "org-a", WorkspaceID: "workspace-a", EnvironmentID: "env-a", RunID: "run-1", AllowedReferences: map[string]bool{"test-1": true}}
			for _, mode := range []struct {
				autonomy Autonomy
				want     AuthorizationDecision
			}{{AutonomySupervised, AuthorizationApprovalRequired}, {AutonomyAutonomous, AuthorizationAllow}} {
				agent.Autonomy = mode.autonomy
				if got := AuthorizeAction(agent, metadata, scope); got != mode.want {
					t.Errorf("%s authorization=%s want=%s", mode.autonomy, got, mode.want)
				}
				if ProductionActionAvailable(key, mode.autonomy) {
					t.Errorf("unfinished %s execution enabled", mode.autonomy)
				}
			}
		})
	}
}
