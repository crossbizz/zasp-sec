package apiserver

import (
	"encoding/json"
	"testing"
)

func TestSecurityAgentAttackLabPreflightStopIsClosedAndClaimBound(t *testing.T) {
	claim := SecurityAgentRunClaim{OrganizationID: "pid_78000001-0000-4000-8000-000000000001", WorkspaceID: "pid_78000002-0000-4000-8000-000000000002", EnvironmentID: "pid_78000003-0000-4000-8000-000000000003", RunID: "pid_78000004-0000-4000-8000-000000000004", Attempt: 1, Version: 2}
	for _, mutation := range []string{"valid", "organization_id", "workspace_id", "environment_id", "run_id", "attempt", "version", "reason", "state", "extra", "envelope"} {
		t.Run(mutation, func(t *testing.T) {
			stop := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "attempt": 1, "version": 3, "state": "needs_human", "reason": "attack_lab_preflight_unavailable"}
			envelope := map[string]any{"attack_lab_preflight_stop": stop}
			switch mutation {
			case "valid":
			case "attempt":
				stop[mutation] = 2
			case "version":
				stop[mutation] = 2
			case "envelope":
				envelope["context"] = map[string]any{}
			default:
				stop[mutation] = "provider_unavailable"
			}
			raw, _ := json.Marshal(envelope)
			if validSecurityAgentAttackLabPreflightStop(raw, claim) != (mutation == "valid") {
				t.Fatal("unbound stop changed worker authority")
			}
		})
	}
}
