package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityAgentExistingTestReferenceClosedContract(t *testing.T) {
	const id = "pid_8a000002-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		name, raw string
		valid     bool
		version   int64
	}{
		{"first", `{"definition_id":"` + id + `","definition_version":1}`, true, 1},
		{"maximum", `{"definition_id":"` + id + `","definition_version":1000000}`, true, 1000000},
		{"missing_version", `{"definition_id":"` + id + `"}`, false, 0},
		{"missing_id", `{"definition_version":1}`, false, 0},
		{"null_id", `{"definition_id":null,"definition_version":1}`, false, 0},
		{"null_version", `{"definition_id":"` + id + `","definition_version":null}`, false, 0},
		{"duplicate_version", `{"definition_id":"` + id + `","definition_version":0,"definition_version":1}`, false, 0},
		{"overflow", `{"definition_id":"` + id + `","definition_version":9223372036854775808}`, false, 0},
		{"oversized", `{"definition_id":"` + id + `","definition_version":1}` + strings.Repeat(" ", 1024), false, 0},
		{"zero", `{"definition_id":"` + id + `","definition_version":0}`, false, 0},
		{"stale_sentinel", `{"definition_id":"` + id + `","definition_version":-1}`, false, 0},
		{"too_large", `{"definition_id":"` + id + `","definition_version":1000001}`, false, 0},
		{"fraction", `{"definition_id":"` + id + `","definition_version":1.5}`, false, 0},
		{"string_version", `{"definition_id":"` + id + `","definition_version":"1"}`, false, 0},
		{"exponent", `{"definition_id":"` + id + `","definition_version":1e0}`, false, 0},
		{"duplicate", `{"definition_id":"invalid","definition_id":"` + id + `","definition_version":1}`, false, 0},
		{"prompt", `{"definition_id":"` + id + `","definition_version":1,"prompt":"override"}`, false, 0},
		{"url", `{"definition_id":"` + id + `","definition_version":1,"url":"https://override.invalid"}`, false, 0},
		{"target", `{"definition_id":"` + id + `","definition_version":1,"target_id":"` + id + `"}`, false, 0},
		{"scope", `{"definition_id":"` + id + `","definition_version":1,"organization_id":"` + id + `"}`, false, 0},
		{"bad_id", `{"definition_id":"test-1","definition_version":1}`, false, 0},
		{"null", `null`, false, 0},
		{"array", `[]`, false, 0},
		{"trailing", `{"definition_id":"` + id + `","definition_version":1}{}`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSecurityAgentExistingTestReference(json.RawMessage(tc.raw))
			if !tc.valid {
				if err != ErrRepositoryOperation || got != (securityAgentExistingTestReference{}) {
					t.Fatalf("unsafe reference result=%#v err=%v", got, err)
				}
				return
			}
			if err != nil || got.DefinitionID != id || got.DefinitionVersion != tc.version {
				t.Fatalf("reference=%#v err=%v", got, err)
			}
		})
	}
}

func TestSecurityAgentWebhookDestinationDefinitionContract(t *testing.T) {
	const prefix = `{"name":"Response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_8a000002-0000-4000-8000-000000000002"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["send_response_webhook"],"verification_kind":"webhook","definition_version":1,"enabled":false,"response_webhook_destination":`
	const id = `pid_8a000002-0000-4000-8000-000000000002`
	for _, tc := range []struct {
		name, reference string
		valid           bool
	}{
		{"saved", `{"integration_id":"` + id + `","integration_version":1}`, true},
		{"maximum", `{"integration_id":"` + id + `","integration_version":1000000}`, true},
		{"missing", `{"integration_id":"` + id + `"}`, false},
		{"zero", `{"integration_id":"` + id + `","integration_version":0}`, false},
		{"null", `null`, false},
		{"raw_url", `{"integration_id":"` + id + `","integration_version":1,"url":"https://other.invalid"}`, false},
		{"secret", `{"integration_id":"` + id + `","integration_version":1,"signing_secret_reference":"secret_ref_other"}`, false},
		{"case_alias", `{"Integration_ID":"` + id + `","integration_version":1}`, false},
		{"duplicate", `{"integration_id":"invalid","integration_id":"` + id + `","integration_version":1}`, false},
		{"fraction", `{"integration_id":"` + id + `","integration_version":1.5}`, false},
		{"exponent", `{"integration_id":"` + id + `","integration_version":1e0}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecurityAgentDefinitionObject(json.RawMessage(prefix + tc.reference + `}`))
			if (err == nil) != tc.valid {
				t.Fatalf("closed saved destination valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
