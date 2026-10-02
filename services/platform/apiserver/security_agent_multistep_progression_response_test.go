package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

func TestSecurityAgentMultistepProgressionResponsePostconditions(t *testing.T) {
	// Literal canonical IDs were checked independently against the PostgreSQL
	// identity authority. The fake is the transport, not the validator under test.
	const approval0 = "pid_eb91594a-05f2-436b-8594-33e3733e6556"
	for _, mode := range []string{"reject", "negative", "zero", "large", "versionless", "noncanonical", "reject_no_increment", "reject_no_approval", "reject_succeeded", "reject_cancelled_parent", "blocked_pending_version", "blocked_large_version", "blocked_step0_no_approval", "blocked_versionless", "approved_large_version"} {
		t.Run(mode, func(t *testing.T) {
			request := orderedProgressionRequest("pid_70000001-0000-4000-8000-000000000001", "pid_70000002-0000-4000-8000-000000000002", "pid_70000003-0000-4000-8000-000000000003", "pid_78000001-0000-4000-8000-000000000001", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", "reject", orderedProgressionApprover, 3)
			response := map[string]any{"contract_version": 61, "organization_id": request["organization_id"], "workspace_id": request["workspace_id"], "environment_id": request["environment_id"], "run_id": request["run_id"], "step_id": request["step_id"], "outcome": "blocked", "run_state": "needs_human", "step_state": "cancelled", "run_version": 4, "approval_id": approval0, "approval_version": 2}
			switch mode {
			case "negative":
				response["approval_version"] = -1
			case "zero":
				response["approval_version"] = 0
			case "large":
				response["approval_version"] = 1000000
			case "versionless", "blocked_versionless":
				delete(response, "approval_version")
			case "noncanonical":
				response["approval_id"] = request["run_id"]
			case "reject_no_increment":
				response["run_version"] = 3
			case "reject_no_approval", "blocked_step0_no_approval":
				response["approval_id"], response["approval_version"] = "", 0
			case "reject_succeeded":
				response["step_state"] = "succeeded"
			case "reject_cancelled_parent":
				response["run_state"] = "cancelled"
			case "blocked_pending_version":
				response["approval_version"] = 1
			case "blocked_large_version":
				response["approval_version"] = 999999
			case "approved_large_version":
				request["operation"], request["approval_version"] = "approve", 999999
				response["outcome"], response["run_state"], response["step_state"], response["approval_version"] = "approved", "running", "authorized", 1000000
			}
			if len(mode) >= 7 && mode[:7] == "blocked" {
				request["operation"] = "cancel"
				response["run_state"] = "cancelled"
			}
			input, _ := json.Marshal(request)
			output, _ := json.Marshal(response)
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.transition($1,$2,$3::jsonb)`: output}}
			repository := &securityAgentMultistepAdmissionRepository{database: database}
			_, err := repository.transition(context.Background(), input)
			if mode == "reject" && err != nil {
				t.Fatal("valid rejection refused", err)
			}
			if mode != "reject" && err == nil {
				t.Fatal("impossible authority response accepted", mode)
			}
		})
	}
}
