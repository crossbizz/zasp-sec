package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityAgentMultistepTestCancellationResponse(t *testing.T) {
	const request = `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","operation":"cancel","actor_id":"pid_78000002-0000-4000-8000-000000000002","run_version":9,"approval_version":2,"fresh_auth_at":"2026-09-20T00:00:00Z"}`
	const response = `{"contract_version":61,"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","outcome":"blocked","run_state":"cancelled","run_version":10,"step_state":"executing","approval_id":"pid_6b8a9b19-6501-4ada-8b7f-6769abf8d245","approval_version":2}`
	for _, mode := range []string{"exact", "reject", "approve", "progress", "noncanonical_step", "different_index", "approval", "version", "zero_version", "missing_approval", "versionless", "parent", "same_version", "large_increment", "receipt"} {
		t.Run(mode, func(t *testing.T) {
			input, output := request, response
			switch mode {
			case "reject", "approve", "progress":
				input = strings.Replace(input, `"cancel"`, `"`+mode+`"`, 1)
			case "noncanonical_step":
				input = strings.Replace(input, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_78000001-0000-4000-8000-000000000001", 1)
				output = strings.Replace(output, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_78000001-0000-4000-8000-000000000001", 1)
			case "different_index":
				output = strings.Replace(output, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", 1)
			case "approval":
				output = strings.Replace(output, "pid_6b8a9b19-6501-4ada-8b7f-6769abf8d245", "pid_eb91594a-05f2-436b-8594-33e3733e6556", 1)
			case "version":
				output = strings.Replace(output, `"approval_version":2`, `"approval_version":1`, 1)
			case "zero_version":
				output = strings.Replace(output, `"approval_version":2`, `"approval_version":0`, 1)
			case "missing_approval":
				output = strings.Replace(output, `"approval_id":"pid_6b8a9b19-6501-4ada-8b7f-6769abf8d245","approval_version":2`, `"approval_id":"","approval_version":0`, 1)
			case "versionless":
				output = strings.Replace(output, `,"approval_version":2`, "", 1)
			case "parent":
				output = strings.Replace(output, `"cancelled"`, `"needs_human"`, 1)
			case "same_version":
				output = strings.Replace(output, `"run_version":10`, `"run_version":9`, 1)
			case "large_increment":
				output = strings.Replace(output, `"run_version":10`, `"run_version":11`, 1)
			case "receipt":
				output = strings.TrimSuffix(output, "}") + `,"receipt_kind":"existing_test_settled.v1"}`
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.transition($1,$2,$3::jsonb)`: []byte(output)}}
			_, err := (&securityAgentMultistepAdmissionRepository{database: db}).transition(context.Background(), []byte(input))
			if mode == "exact" && err != nil {
				t.Fatal("legitimate successor cancellation refused", err)
			}
			if mode != "exact" && err == nil {
				t.Fatal("impossible successor cancellation accepted", mode)
			}
		})
	}
}
