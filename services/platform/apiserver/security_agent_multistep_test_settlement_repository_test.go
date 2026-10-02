package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

// The PG caller supplies a real immutable artifact and exact SQL response.
// Each fabricated response is checked independently of SQL's own validation.
func orderedTestSettlementResponseRefusals(t *testing.T, ctx context.Context, request, response json.RawMessage, store artifactstore.ObjectReferencingArtifactStore) {
	t.Helper()
	const statement = `SELECT zasp_sa_multistep_prior.test_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15)`
	for _, mode := range []string{"exact", "contract", "run", "step", "child", "invocation", "zero", "negative", "large", "versionless", "null", "increment", "effect_increment", "step_version", "attempt", "state", "outcome", "kind", "proof", "snapshot", "result", "generation", "input", "output_version", "extra", "duplicate", "oversize"} {
		t.Run("repository_"+mode, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(response, &value) != nil {
				t.Fatal("response fixture malformed")
			}
			receipt := value["receipt"].(map[string]any)
			switch mode {
			case "contract":
				value["contract_version"] = 60
			case "run":
				value["run_id"] = "pid_79990001-0000-4000-8000-000000000001"
			case "step":
				value["step_id"] = value["run_id"]
			case "child":
				value["test_run_id"] = value["run_id"]
			case "invocation":
				receipt["invocation_id"] = value["run_id"]
			case "zero":
				value["run_version"] = 0
			case "negative":
				value["run_version"] = -1
			case "large":
				value["run_version"] = 1000000
			case "versionless":
				delete(value, "run_version")
			case "null":
				value["run_version"] = nil
			case "increment":
				value["run_version"] = value["run_version"].(float64) + 1
			case "effect_increment":
				value["effect_version"] = value["effect_version"].(float64) + 1
			case "step_version":
				value["step_version"] = 4
			case "attempt":
				value["attempt"] = 6
			case "state":
				value["run_state"] = "remediated"
			case "outcome":
				value["outcome"] = "reproduced"
				receipt["outcome"] = "reproduced"
			case "kind":
				value["receipt_kind"] = "temporary_policy_applied.v1"
			case "proof":
				receipt["proof_digest"] = strings.Repeat("f", 64)
			case "snapshot":
				receipt["snapshot_digest"] = strings.Repeat("0", 64)
			case "result":
				value["result_digest"] = "sha256:" + strings.Repeat("f", 64)
			case "generation":
				receipt["settlement_generation"] = 2
			case "input":
				value["input_artifact"].(map[string]any)["version_id"] = "foreign"
			case "output_version":
				value["output_artifact"].(map[string]any)["version_id"] = "foreign"
			case "extra":
				value["public_activation"] = true
			}
			body, _ := json.Marshal(value)
			if mode == "duplicate" {
				body = append([]byte(`{"run_version":10,`), body[1:]...)
			}
			if mode == "oversize" {
				body = append(body, bytes.Repeat([]byte(" "), 16385-len(body))...)
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: body}}
			got, err := (&securityAgentMultistepAdmissionRepository{database: database}).testSettle(ctx, request, store)
			if mode == "exact" {
				if err != nil || string(got) != string(body) {
					t.Fatal("exact SQL response refused", err)
				}
			} else if err == nil {
				t.Fatal("fabricated settlement response accepted", mode)
			}
		})
	}
}

func TestSecurityAgentMultistepTestArtifactJSON(t *testing.T) {
	for _, item := range []struct {
		name, body string
		valid      bool
	}{
		{"null_field", `{"error_code":null}`, true},
		{"duplicate", `{"error_code":null,"error_code":null}`, false},
		{"nested_duplicate", `{"error_code":{"x":1,"x":2}}`, false},
		{"array_duplicate", `{"error_code":[{"x":1,"x":2}]}`, false},
		{"trailing", `{"error_code":null}{}`, false},
		{"wrong_case", `{"Error_Code":null}`, false},
		{"depth", `{"error_code":` + strings.Repeat("[", 25) + "0" + strings.Repeat("]", 25) + `}`, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, ok := orderedTestArtifactObject([]byte(item.body), 1048576, "error_code")
			if ok != item.valid {
				t.Fatal("artifact ambiguity decision", ok)
			}
		})
	}
	for _, length := range []int{65536, 1048576, 1048577} {
		body := append([]byte(`{"error_code":null}`), bytes.Repeat([]byte(" "), length-len(`{"error_code":null}`))...)
		_, ok := orderedTestArtifactObject(body, 1048576, "error_code")
		if ok != (length <= 1048576) {
			t.Fatal("artifact byte boundary", length, ok)
		}
	}
}
