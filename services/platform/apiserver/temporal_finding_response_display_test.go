package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingResponseMetadataArguments(t *testing.T) {
	const target = "pid_78000005-0000-4000-8000-000000000005"
	const assignee = "pid_78000006-0000-4000-8000-000000000006"
	base := map[string]any{"target_id": target, "expected_version": 2, "target_status": "under_review", "assignee_id": assignee, "response_status": "investigating", "note": "Investigate the credential exposure"}
	for _, status := range []string{"investigating", "open"} {
		t.Run(status, func(t *testing.T) {
			value := cloneFindingDisplayFixture(base)
			value["response_status"] = status
			if status == "open" {
				value["target_status"] = "open"
			}
			raw, _ := json.Marshal(value)
			decoded, err := decodeSecurityAgentActionArguments("update_finding_response", raw)
			if err != nil {
				t.Fatal("safe finding metadata rejected", err)
			}
			roundtrip, _ := json.Marshal(decoded)
			assertAutomaticRuleJSON(t, "finding metadata display", raw, roundtrip)
		})
	}
	for _, test := range []struct {
		name, field string
		value       any
	}{
		{"resolved", "response_status", "resolved"}, {"safe", "response_status", "safe"}, {"closed", "target_status", "closed"},
		{"mapping", "target_status", "open"}, {"assignee", "assignee_id", "someone"}, {"empty_note", "note", ""},
		{"long_note", "note", strings.Repeat("x", 513)}, {"byte_bound", "note", strings.Repeat("é", 257)},
		{"control", "note", "line\nbreak"}, {"padded", "note", " padded"}, {"partial", "assignee_id", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := cloneFindingDisplayFixture(base)
			value[test.field] = test.value
			raw, _ := json.Marshal(value)
			if result, err := decodeSecurityAgentActionArguments("update_finding_response", raw); err == nil || result != nil {
				t.Fatal("unsafe finding display accepted")
			}
		})
	}
	duplicate, _ := json.Marshal(base)
	duplicate = append([]byte(`{"note":"old",`), duplicate[1:]...)
	if result, err := decodeSecurityAgentActionArguments("update_finding_response", duplicate); err == nil || result != nil {
		t.Fatal("duplicate finding note accepted")
	}
	legacy := []byte(`{"target_id":"` + target + `","expected_version":2,"target_status":"under_review"}`)
	if _, err := decodeSecurityAgentActionArguments("update_finding_response", legacy); err != nil {
		t.Fatal("historical omitted metadata rejected", err)
	}
}

func cloneFindingDisplayFixture(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
