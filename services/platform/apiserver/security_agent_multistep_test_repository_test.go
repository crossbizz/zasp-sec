package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentMultistepTestRepositoryBoundary(t *testing.T) {
	const statement = `SELECT zasp_sa_multistep_prior.test_action($1,$2,$3::jsonb)`
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f"
	for _, mode := range []string{"exact", "heartbeat", "recovery", "step0", "token", "worker", "zero", "negative", "large", "missing", "null", "extra", "duplicate", "state", "step_version", "run_increment", "reservation", "child", "attempt", "expired"} {
		t.Run(mode, func(t *testing.T) {
			request := orderedTestActionRequest(o, w, e, r, s, "claim", 8, 0)
			request["lease_token"] = strings.Repeat("a", 32)
			// Canonical IDs are independently computed literal fixtures.
			response := map[string]any{"contract_version": 61, "organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": "claim", "run_version": 9, "step_version": 4, "effect_version": 1, "effect_state": "leased", "attempt": 1, "reservation_id": "pid_48c4cba4-8700-44cb-85a5-b2ab662801ce", "test_run_id": "pid_dad9132a-b5e6-4ab0-8806-339039ccd10b", "plan_hash": "sha256:" + strings.Repeat("b", 64), "input_digest": "sha256:" + strings.Repeat("c", 64), "lease_expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
			switch mode {
			case "heartbeat":
				request["operation"], request["run_version"], request["effect_version"] = "heartbeat", 9, 1
				response["operation"], response["effect_version"] = "heartbeat", 2
			case "recovery":
				request["run_version"], request["effect_version"] = 9, 2
				response["run_version"], response["effect_version"], response["attempt"] = 10, 3, 2
			case "step0":
				request["step_id"] = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
			case "token":
				request["lease_token"] = strings.Repeat("z", 32)
			case "worker":
				request["worker_id"] = "invalid worker"
			case "zero":
				response["effect_version"] = 0
			case "negative":
				response["effect_version"] = -1
			case "large":
				response["effect_version"] = 1000000
			case "missing":
				delete(response, "effect_version")
			case "null":
				response["effect_version"] = nil
			case "extra":
				response["public_route"] = true
			case "state":
				response["effect_state"] = "done"
			case "step_version":
				response["step_version"] = 3
			case "run_increment":
				response["run_version"] = 10
			case "reservation":
				response["reservation_id"] = r
			case "child":
				response["test_run_id"] = r
			case "attempt":
				response["attempt"] = 2
			case "expired":
				response["lease_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
			}
			input, _ := json.Marshal(request)
			output, _ := json.Marshal(response)
			if mode == "duplicate" {
				output = []byte(strings.Replace(string(output), `"effect_version":1`, `"effect_version":0,"effect_version":1`, 1))
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: output}}
			repository, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				testAction(context.Context, json.RawMessage) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private release61 successor repository absent")
			}
			got, err := repository.testAction(context.Background(), input)
			if mode == "exact" || mode == "heartbeat" || mode == "recovery" {
				if err != nil || string(got) != string(output) {
					t.Fatal(string(got), err)
				}
			} else if err == nil {
				t.Fatal("fabricated successor authority accepted", mode)
			}
			if (mode == "step0" || mode == "token" || mode == "worker") && len(database.statements) != 0 {
				t.Fatal("invalid request reached SQL")
			}
		})
	}
}
