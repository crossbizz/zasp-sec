package redteamadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func targetComparisonFixture(r JournalRequest) json.RawMessage {
	endpoint := sha256.Sum256([]byte(r.Invocation.Binding.Endpoint))
	body, _ := json.Marshal(map[string]any{"schema_version": "red-team-target-comparison-v1", "organization_id": testOrganizationID, "workspace_id": testWorkspaceID, "environment_id": testEnvironmentID, "test_definition_id": testRunID, "test_definition_version": 1, "target_id": testTargetID, "target_kind": "agent_endpoint", "categories": []string{"prompt_injection"}, "safety_digest": strings.Repeat("a", 64), "endpoint_digest": hex.EncodeToString(endpoint[:]), "configuration_digest": strings.Repeat("b", 64), "credential_binding_id": testRunID, "credential_binding_version": 1, "credential_binding_digest": strings.Repeat("c", 64)})
	return body
}

func TestJournalReceiptRejectsUnboundTargetComparison(t *testing.T) {
	r := journalRequestFixture(t)
	for _, completed := range []bool{false, true} {
		valid := journalReceiptFixture(r, completed)
		got, err := decodeJournalReceipt(valid, r)
		if err != nil || !json.Valid(got.TargetComparison) {
			t.Fatalf("valid comparison refused: %v", err)
		}
		for field, bad := range map[string]any{"schema_version": "unknown", "organization_id": testTargetID, "workspace_id": testTargetID, "environment_id": testTargetID, "test_definition_id": "bad", "test_definition_version": 0, "target_id": testRunID, "target_kind": "mcp_server", "categories": []string{"tool_abuse"}, "safety_digest": strings.Repeat("0", 64), "endpoint_digest": strings.Repeat("e", 64), "configuration_digest": "bad", "credential_binding_id": "bad", "credential_binding_version": 0, "credential_binding_digest": "invalid"} {
			for _, mutation := range []string{"missing", "null", "changed", "alias", "duplicate"} {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(valid, &fields)
				var comparison map[string]any
				_ = json.Unmarshal(fields["target_comparison"], &comparison)
				switch mutation {
				case "missing":
					delete(comparison, field)
				case "null":
					comparison[field] = nil
				case "changed":
					comparison[field] = bad
				case "alias":
					comparison[strings.ToUpper(field)] = comparison[field]
					delete(comparison, field)
				}
				raw, _ := json.Marshal(comparison)
				if mutation == "duplicate" {
					raw = []byte(`{"` + field + `":null,` + string(raw[1:]))
				}
				fields["target_comparison"] = raw
				body, _ := json.Marshal(fields)
				if _, err := decodeJournalReceipt(body, r); err == nil {
					t.Fatalf("accepted %s %s", field, mutation)
				}
			}
		}
	}
}

func TestJournalReceiptRequiresPinnedTargetComparison(t *testing.T) {
	r := journalRequestFixture(t)
	for _, completed := range []bool{false, true} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(journalReceiptFixture(r, completed), &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, "target_comparison")
		body, _ := json.Marshal(fields)
		if _, err := decodeJournalReceipt(body, r); err == nil {
			t.Fatal("journal receipt accepted without pinned comparison identity")
		}
	}
}
