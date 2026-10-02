package apiserver

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSecurityAgentExportApprovalContext(t *testing.T) {
	approval, wire := approvalContextFixture("create_evidence_export")
	approval.ExpectedEffect = "Create run-scoped evidence export"
	_, _, pin, _ := agentDownloadFixture(t)
	wire["arguments"] = map[string]any{"target_id": approval.RunID, "evidence_ids": pin.Binding.Selection}
	raw, _ := json.Marshal(wire)
	got, err := decodeSecurityAgentApprovalContext(raw, approval)
	if err != nil || got == nil {
		t.Fatalf("export approval context refused: %v", err)
	}
	approval.Context = got
	if !validSecurityAgentApproval(approval) || got.Risk.Class != "low" || got.TargetID == nil || *got.TargetID != approval.RunID {
		t.Fatal("export approval lost parent or catalog authority")
	}
	encoded, _ := json.Marshal(got)
	var public map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &public)
	var selected []SecurityAgentExportSelection
	if json.Unmarshal(public["export_selection"], &selected) != nil || !reflect.DeepEqual(selected, pin.Binding.Selection) {
		t.Fatal("approval lost original export selection")
	}
	for _, mutation := range []string{"missing_selection", "foreign_parent", "invalid_selection", "wrong_action", "ttl", "reversibility"} {
		t.Run(mutation, func(t *testing.T) {
			var context map[string]any
			_ = json.Unmarshal(encoded, &context)
			candidate := approval
			switch mutation {
			case "missing_selection":
				delete(context, "export_selection")
			case "foreign_parent":
				context["target_id"] = approval.StepID
			case "invalid_selection":
				context["export_selection"] = []any{}
			case "wrong_action":
				context["action"] = "update_finding_response"
				candidate.ExpectedEffect = "Move finding to under review"
			case "ttl":
				candidate.TTLSeconds = 60
			case "reversibility":
				candidate.Reversible = false
			}
			changed, _ := json.Marshal(context)
			candidate.Context = &SecurityAgentApprovalContext{}
			_ = json.Unmarshal(changed, candidate.Context)
			if validSecurityAgentApproval(candidate) {
				t.Fatal("contradictory export approval accepted")
			}
		})
	}
}

func TestSecurityAgentExportApprovalRejectsForeignSelectionTarget(t *testing.T) {
	approval, wire := approvalContextFixture("create_evidence_export")
	approval.ExpectedEffect = "Create run-scoped evidence export"
	_, _, pin, _ := agentDownloadFixture(t)
	for _, args := range []any{nil, map[string]any{"target_id": approval.StepID, "evidence_ids": pin.Binding.Selection}} {
		wire["arguments"] = args
		raw, _ := json.Marshal(wire)
		if got, err := decodeSecurityAgentApprovalContext(raw, approval); err == nil || got != nil {
			t.Fatal("export approval accepted missing or foreign parent selection")
		}
	}
}

func TestSecurityAgentExportApprovalRunDetail(t *testing.T) {
	_, detail := actionProjectionFixture(t, "create_evidence_export", "", [2]int{}, [2]int{}, nil)
	approval, _ := approvalContextFixture("create_evidence_export")
	approval.RunID, approval.StepID = detail.Run.ID, detail.Plan.Steps[0].ID
	approval.ExpectedEffect = "Create run-scoped evidence export"
	approval.EvidenceSummary = append([]string(nil), detail.EvidenceIDs...)
	detail.Plan.Steps[0].Authorization = "approval_required"
	detail.Approvals = []SecurityAgentApproval{approval}
	if !validSecurityAgentRunDetail(detail, detail.Run.ID) {
		t.Fatal("export approval refused in run detail")
	}
	detail.Approvals[0].ExpectedEffect = "Move finding to under review"
	if validSecurityAgentRunDetail(detail, detail.Run.ID) {
		t.Fatal("export step borrowed another action's approval")
	}
}
