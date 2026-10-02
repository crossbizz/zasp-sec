package apiserver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// A wrong action allowlist, permissive scalar decoder or arbitrary JSON copy
// must fail at this boundary before any private argument can reach the handler.
func TestSecurityAgentActionArguments(t *testing.T) {
	for _, test := range []struct{ action, raw string }{
		{"update_finding_response", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":2,"target_status":"under_review"}`},
		{"create_temporary_policy", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","mode":"block","scope":"pid_78000005-0000-4000-8000-000000000005","ttl_seconds":60}`},
		{"isolate_session", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","session_id":"pid_78000005-0000-4000-8000-000000000005","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":3600}`},
		{"revoke_integration_connection", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","integration_id":"pid_78000009-0000-4000-8000-000000000009"}`},
	} {
		t.Run(test.action, func(t *testing.T) {
			got, err := decodeSecurityAgentActionArguments(test.action, json.RawMessage(test.raw))
			if err != nil || got == nil {
				t.Fatal("valid persisted arguments rejected")
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var want, actual map[string]any
			if json.Unmarshal([]byte(test.raw), &want) != nil || json.Unmarshal(encoded, &actual) != nil || !reflect.DeepEqual(want, actual) {
				t.Fatal("typed projection changed or added persisted arguments")
			}
			if unavailable, err := decodeSecurityAgentActionArguments(test.action, json.RawMessage("null")); err != nil || unavailable != nil {
				t.Fatal("missing legacy arguments were fabricated")
			}
			for _, invalid := range []string{
				strings.TrimSuffix(test.raw, "}") + `,"password":"protected-action-sentinel"}`,
				strings.Replace(test.raw, `"target_id":"pid_78000005-0000-4000-8000-000000000005"`, `"target_id":"protected-action-sentinel"`, 1),
				strings.Replace(test.raw, `"target_id":"pid_78000005-0000-4000-8000-000000000005",`, "", 1),
				`{}`, `[]`, `"protected-action-sentinel"`, `{"target_id":null}`, "",
			} {
				value, err := decodeSecurityAgentActionArguments(test.action, json.RawMessage(invalid))
				if err != ErrRepositoryUnavailable || value != nil || strings.Contains(err.Error(), "protected-action-sentinel") {
					t.Fatal("malformed/protected arguments crossed the projection boundary")
				}
			}
		})
	}
}

func TestSecurityAgentActionArgumentsRejectContradictions(t *testing.T) {
	for _, test := range []struct{ action, raw string }{
		{"arbitrary_action", `null`},
		{"update_finding_response", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":0,"target_status":"under_review"}`},
		{"update_finding_response", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":9007199254740992,"target_status":"under_review"}`},
		{"update_finding_response", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":1.5,"target_status":"under_review"}`},
		{"update_finding_response", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":1,"target_status":"resolved"}`},
		{"create_temporary_policy", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","mode":"allow","scope":"pid_78000005-0000-4000-8000-000000000005","ttl_seconds":60}`},
		{"create_temporary_policy", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","mode":"block","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":60}`},
		{"create_temporary_policy", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","mode":"block","scope":"pid_78000005-0000-4000-8000-000000000005","ttl_seconds":59}`},
		{"create_temporary_policy", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","mode":"block","scope":"pid_78000005-0000-4000-8000-000000000005","ttl_seconds":3601}`},
		{"isolate_session", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","session_id":"pid_78000006-0000-4000-8000-000000000006","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":60}`},
		{"isolate_session", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","session_id":"pid_78000005-0000-4000-8000-000000000005","device_id":"secret","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":60}`},
		{"isolate_session", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","session_id":"pid_78000005-0000-4000-8000-000000000005","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"secret","ttl_seconds":60}`},
		{"revoke_integration_connection", `{"target_id":"pid_78000005-0000-4000-8000-000000000005","integration_id":"secret"}`},
	} {
		if value, err := decodeSecurityAgentActionArguments(test.action, json.RawMessage(test.raw)); err != ErrRepositoryUnavailable || value != nil {
			t.Fatalf("contradictory %s arguments accepted", test.action)
		}
	}
}
