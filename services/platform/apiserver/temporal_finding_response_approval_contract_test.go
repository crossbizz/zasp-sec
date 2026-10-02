package apiserver

import (
	"encoding/json"
	"testing"
)

// The approver must receive the exact safe metadata that the78 plan will apply.
// Relabelling a legacy projection without its arguments must fail closed.
func TestFindingResponseApprovalContract(t *testing.T) {
	const effect = "Assign investigator and update finding response"
	for _, status := range []string{"open", "investigating"} {
		t.Run(status, func(t *testing.T) {
			approval, wire := approvalContextFixture("update_finding_response")
			approval.ExpectedEffect = effect
			args := wire["arguments"].(map[string]any)
			args["assignee_id"], args["response_status"], args["note"] = approval.ID, status, "Investigate the credential exposure"
			if status == "open" {
				args["target_status"] = "open"
			}
			raw, _ := json.Marshal(wire)
			context, err := decodeSecurityAgentApprovalContext(raw, approval)
			if err != nil || context == nil {
				t.Fatal("complete finding approval projection rejected", err)
			}
			encoded, _ := json.Marshal(context)
			var public map[string]json.RawMessage
			if json.Unmarshal(encoded, &public) != nil {
				t.Fatal("public context encoding")
			}
			want, _ := json.Marshal(args)
			assertAutomaticRuleJSON(t, "concrete approved finding changes", public["finding_response"], want)
			approval.Context = context
			if !validSecurityAgentApproval(approval) {
				t.Fatal("complete public approval rejected")
			}
			approval.ExpectedEffect = "Move finding to under review"
			if validSecurityAgentApproval(approval) {
				t.Fatal("enriched metadata accepted under legacy effect")
			}
		})
	}
	for _, mutation := range []string{"missing_note", "legacy_arguments", "old_effect", "null_arguments", "unsafe_status", "inconsistent_status"} {
		t.Run(mutation, func(t *testing.T) {
			approval, wire := approvalContextFixture("update_finding_response")
			approval.ExpectedEffect = effect
			args := wire["arguments"].(map[string]any)
			args["assignee_id"], args["response_status"], args["note"] = approval.ID, "investigating", "Investigate exposure"
			switch mutation {
			case "missing_note":
				delete(args, "note")
			case "legacy_arguments":
				delete(args, "note")
				delete(args, "assignee_id")
				delete(args, "response_status")
			case "old_effect":
				approval.ExpectedEffect = "Move finding to under review"
			case "null_arguments":
				wire["arguments"] = nil
			case "unsafe_status":
				args["response_status"], args["target_status"] = "safe", "safe"
			case "inconsistent_status":
				args["response_status"] = "open"
			}
			raw, _ := json.Marshal(wire)
			if _, err := decodeSecurityAgentApprovalContext(raw, approval); err == nil {
				t.Fatal("incomplete or contradictory finding approval accepted")
			}
		})
	}
	approval, _ := approvalContextFixture("update_finding_response")
	approval.ExpectedEffect = effect
	if validSecurityAgentApproval(approval) {
		t.Fatal("new finding effect accepted without concrete context")
	}
}
