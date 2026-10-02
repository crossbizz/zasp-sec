package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepProgressionRepositoryBoundary(t *testing.T) {
	const statement = `SELECT zasp_sa_multistep_prior.transition($1,$2,$3::jsonb)`
	const request = `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","operation":"progress","actor_id":"ordered-worker","run_version":3,"approval_version":1,"fresh_auth_at":"2026-09-20T00:00:00Z"}`
	const response = `{"contract_version":61,"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","outcome":"waiting","run_state":"waiting_approval","run_version":3,"step_state":"queued","approval_id":"","approval_version":0}`
	for _, mode := range []string{"exact", "invalid_request", "extra_request", "null_request", "duplicate_request", "unknown_operation", "foreign_response", "unexpected_effect", "extra_response", "null_response", "duplicate_response", "wrong_version", "wrong_approval", "wrong_step_state"} {
		t.Run(mode, func(t *testing.T) {
			input, output := request, response
			switch mode {
			case "invalid_request":
				input = strings.Replace(input, `"run_version":3`, `"run_version":0`, 1)
			case "extra_request":
				input = strings.Replace(input, `"run_version":3`, `"run_version":3,"execute":true`, 1)
			case "null_request":
				input = strings.Replace(input, `"run_version":3`, `"run_version":null`, 1)
			case "duplicate_request":
				input = strings.Replace(input, `"run_version":3`, `"run_version":2,"run_version":3`, 1)
			case "unknown_operation":
				input = strings.Replace(input, `"progress"`, `"claim"`, 1)
			case "foreign_response":
				output = strings.Replace(output, "pid_70000001", "pid_90000001", 1)
			case "unexpected_effect":
				output = strings.Replace(output, `"waiting"`, `"executed"`, 1)
			case "extra_response":
				output = strings.Replace(output, `"contract_version":61`, `"contract_version":61,"effect_id":"forged"`, 1)
			case "null_response":
				output = strings.Replace(output, `"contract_version":61`, `"contract_version":null`, 1)
			case "duplicate_response":
				output = strings.Replace(output, `"contract_version":61`, `"contract_version":60,"contract_version":61`, 1)
			case "wrong_version":
				output = strings.Replace(output, `"run_version":3`, `"run_version":4`, 1)
			case "wrong_approval":
				output = strings.Replace(output, `"approval_id":""`, `"approval_id":"pid_78000001-0000-4000-8000-000000000001"`, 1)
			case "wrong_step_state":
				output = strings.Replace(output, `"queued"`, `"authorized"`, 1)
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: json.RawMessage(output)}}
			repository, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				transition(context.Context, json.RawMessage) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private release61 repository has no progression boundary")
			}
			got, err := repository.transition(context.Background(), json.RawMessage(input))
			if mode == "exact" {
				if err != nil || string(got) != output {
					t.Fatal(string(got), err)
				}
			} else if err == nil {
				t.Fatal("unsafe repository boundary accepted", mode)
			}
			if strings.Contains(mode, "request") || mode == "unknown_operation" {
				if len(database.statements) != 0 {
					t.Fatal("invalid request reached authority")
				}
				return
			}
			if len(database.arguments) != 1 || len(database.arguments[0]) != 3 || database.arguments[0][0] != migrations.ProductionSecurityAgentMultistep().Checksum() || database.arguments[0][1] != migrations.SecurityAgentMultistepRegisteredFingerprint() {
				t.Fatal("authority identity not pinned", database.arguments)
			}
		})
	}
}
