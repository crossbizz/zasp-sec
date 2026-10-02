package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityAgentMultistepTestExpiryResponse(t *testing.T) {
	const query = `SELECT zasp_sa_multistep_prior.test_reconcile_uncertain($1,$2,$3::jsonb)`
	const request = `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","operation":"reconcile_uncertain","worker_id":"ordered-test-reconciler","run_version":9,"effect_version":1}`
	const response = `{"contract_version":61,"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f","test_run_id":"pid_dad9132a-b5e6-4ab0-8806-339039ccd10b","operation":"reconcile_uncertain","attempt":1,"run_version":10,"step_version":5,"effect_version":2,"run_state":"needs_human","step_state":"inconclusive","effect_state":"unknown_outcome","receipt_created":false,"journal_state":"started","reason":"test_outcome_unknown"}`
	for _, mode := range []string{"exact", "completed_unsettled", "request_command", "step0", "worker", "request_version", "response_command", "receipt", "child", "state", "step", "effect", "reason", "journal_missing", "journal_null", "journal_unknown", "journal_reason_mismatch", "completed_reason_mismatch", "run_increment", "effect_increment", "negative", "zero", "large", "versionless", "duplicate", "extra", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			input, output := request, response
			switch mode {
			case "completed_unsettled":
				output = strings.Replace(output, `"journal_state":"started","reason":"test_outcome_unknown"`, `"journal_state":"completed_unsettled","reason":"test_evidence_unsettled"`, 1)
			case "request_command":
				input = strings.Replace(input, "reconcile_uncertain", "uncertain", 1)
			case "step0":
				input = strings.Replace(input, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", 1)
			case "worker":
				input = strings.Replace(input, "ordered-test-reconciler", "bad worker", 1)
			case "request_version":
				input = strings.Replace(input, `"run_version":9`, `"run_version":0`, 1)
			case "response_command":
				output = strings.Replace(output, "reconcile_uncertain", "uncertain", 1)
			case "receipt":
				output = strings.Replace(output, `"receipt_created":false`, `"receipt_created":true`, 1)
			case "child":
				output = strings.Replace(output, "pid_dad9132a-b5e6-4ab0-8806-339039ccd10b", "pid_78000001-0000-4000-8000-000000000001", 1)
			case "state":
				output = strings.Replace(output, "needs_human", "contained", 1)
			case "step":
				output = strings.Replace(output, "inconclusive", "succeeded", 1)
			case "effect":
				output = strings.Replace(output, "unknown_outcome", "verified", 1)
			case "reason":
				output = strings.Replace(output, "test_outcome_unknown", "test_condition_persists", 1)
			case "journal_missing":
				output = strings.Replace(output, `"journal_state":"started",`, "", 1)
			case "journal_null":
				output = strings.Replace(output, `"journal_state":"started"`, `"journal_state":null`, 1)
			case "journal_unknown":
				output = strings.Replace(output, `"journal_state":"started"`, `"journal_state":"empty"`, 1)
			case "journal_reason_mismatch":
				output = strings.Replace(output, "test_outcome_unknown", "test_evidence_unsettled", 1)
			case "completed_reason_mismatch":
				output = strings.Replace(output, `"journal_state":"started"`, `"journal_state":"completed_unsettled"`, 1)
			case "run_increment":
				output = strings.Replace(output, `"run_version":10`, `"run_version":9`, 1)
			case "effect_increment":
				output = strings.Replace(output, `"effect_version":2`, `"effect_version":3`, 1)
			case "negative":
				output = strings.Replace(output, `"effect_version":2`, `"effect_version":-2`, 1)
			case "zero":
				output = strings.Replace(output, `"effect_version":2`, `"effect_version":0`, 1)
			case "large":
				output = strings.Replace(output, `"effect_version":2`, `"effect_version":1000000`, 1)
			case "versionless":
				output = strings.Replace(output, `"effect_version":2,`, "", 1)
			case "duplicate":
				output = strings.Replace(output, `"effect_version":2`, `"effect_version":1,"effect_version":2`, 1)
			case "extra":
				output = strings.Replace(output, `"receipt_created":false`, `"receipt_created":false,"receipt":{}`, 1)
			case "oversize":
				output += strings.Repeat(" ", 4096)
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{query: []byte(output)}}
			repository, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				testReconcileUncertain(context.Context, json.RawMessage) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private expiry reconciler response boundary absent")
			}
			got, err := repository.testReconcileUncertain(context.Background(), []byte(input))
			if mode == "exact" || mode == "completed_unsettled" {
				if err != nil || string(got) != output {
					t.Fatal(string(got), err)
				}
			} else if err == nil {
				t.Fatal("fabricated expiry reconciliation accepted", mode)
			}
			if stringIn(mode, "request_command", "step0", "worker", "request_version") && len(database.statements) != 0 {
				t.Fatal("invalid expiry request reached SQL")
			}
		})
	}
}
