package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func approvalContextFixture(action string) (SecurityAgentApproval, map[string]any) {
	const id = "pid_78000001-0000-4000-8000-000000000001"
	const run = "pid_78000002-0000-4000-8000-000000000002"
	const step = "pid_78000003-0000-4000-8000-000000000003"
	const target = "pid_78000004-0000-4000-8000-000000000004"
	approval := SecurityAgentApproval{ID: id, RunID: run, StepID: step, State: "pending", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Version: 1, ExpectedEffect: "Move finding to under review", Reversible: true, EvidenceSummary: []string{target}}
	args := map[string]any{"target_id": target, "expected_version": 2, "target_status": "under_review"}
	switch action {
	case "create_temporary_policy", "isolate_session":
		approval.ExpectedEffect, approval.TTLSeconds = "Apply temporary containment policy", 120
		args = map[string]any{"target_id": target, "scope": target, "mode": "block", "ttl_seconds": 120}
		if action == "isolate_session" {
			approval.ExpectedEffect = "Isolate runtime session"
			args = map[string]any{"target_id": target, "session_id": target, "device_id": id, "scope": target, "ttl_seconds": 120}
		}
	case "revoke_integration_connection":
		approval.ExpectedEffect, approval.Reversible = "Revoke integration connection", false
		args = map[string]any{"target_id": target, "integration_id": id}
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	return approval, map[string]any{"approval_id": id, "run_id": run, "step_id": step, "agent_id": id, "approval_plan_hash": hash, "plan_hash": hash, "catalog_version": "security-agent-actions-v1", "action": action, "authorization": "approval_required", "arguments": args, "requester_id": id, "planner_receipt": nil}
}

func TestSecurityAgentApprovalContextProjection(t *testing.T) {
	for _, tc := range []struct{ action, risk string }{{"update_finding_response", "low"}, {"create_temporary_policy", "containment"}, {"isolate_session", "containment"}, {"revoke_integration_connection", "destructive"}} {
		t.Run(tc.action, func(t *testing.T) {
			approval, value := approvalContextFixture(tc.action)
			raw, _ := json.Marshal(value)
			got, err := decodeSecurityAgentApprovalContext(raw, approval)
			if err != nil || got == nil || got.Action != tc.action || got.Risk.Class != tc.risk || got.Risk.Source != "action_catalog" || got.TargetID == nil || *got.TargetID != "pid_78000004-0000-4000-8000-000000000004" || got.Requester.ID == nil || got.Reason.Code != "operator_approval_required" || got.Rationale != nil {
				t.Fatal("bound approval context lost", err)
			}
			value["arguments"], value["requester_id"] = nil, "password=protected-requester-sentinel"
			value["planner_receipt"] = map[string]any{"run_id": approval.RunID, "plan_hash": value["plan_hash"], "outcome": "accepted", "summary": "Review password=protected-rationale-sentinel before acting."}
			raw, _ = json.Marshal(value)
			got, err = decodeSecurityAgentApprovalContext(raw, approval)
			if err != nil || got.TargetID != nil || got.Requester.State != "withheld" || got.Requester.ID != nil || got.Rationale == nil || got.Rationale.Summary != "Review password=[REDACTED] before acting." {
				t.Fatal("legacy or protected context misrepresented", err)
			}
			public, _ := json.Marshal(got)
			if strings.Contains(string(public), "sentinel") {
				t.Fatal("protected context disclosed")
			}
		})
	}
}

func TestSecurityAgentApprovalContextRejectsUnboundAuthority(t *testing.T) {
	for _, field := range []string{"approval_id", "run_id", "step_id", "approval_plan_hash"} {
		t.Run("valid_but_foreign_"+field, func(t *testing.T) {
			approval, value := approvalContextFixture("update_finding_response")
			value[field] = "pid_99000009-0000-4000-8000-000000000009"
			if field == "approval_plan_hash" {
				value[field] = "sha256:" + strings.Repeat("b", 64)
			}
			raw, _ := json.Marshal(value)
			if got, err := decodeSecurityAgentApprovalContext(raw, approval); err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("valid foreign binding accepted")
			}
		})
	}
	for _, field := range []string{"approval_id", "run_id", "step_id", "agent_id", "approval_plan_hash", "plan_hash", "catalog_version", "action", "authorization", "arguments", "planner_receipt", "unexpected"} {
		t.Run(field, func(t *testing.T) {
			approval, value := approvalContextFixture("update_finding_response")
			value[field] = "protected-invalid-sentinel"
			raw, _ := json.Marshal(value)
			if got, err := decodeSecurityAgentApprovalContext(raw, approval); err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("malformed or unbound context accepted")
			}
		})
	}
	for _, field := range []string{"requester_id", "planner_receipt", "arguments"} {
		t.Run("missing_"+field, func(t *testing.T) {
			approval, value := approvalContextFixture("update_finding_response")
			delete(value, field)
			raw, _ := json.Marshal(value)
			if got, err := decodeSecurityAgentApprovalContext(raw, approval); err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("incomplete private projection accepted")
			}
		})
	}
}

func TestSecurityAgentApprovalContextRejectsContradictoryActionAndReceipt(t *testing.T) {
	for _, kind := range []string{"effect", "ttl", "receipt_run", "receipt_plan", "receipt_outcome"} {
		t.Run(kind, func(t *testing.T) {
			approval, value := approvalContextFixture("create_temporary_policy")
			receipt := map[string]any{"run_id": approval.RunID, "plan_hash": value["plan_hash"], "outcome": "accepted", "summary": "Safe rationale."}
			value["planner_receipt"] = receipt
			switch kind {
			case "effect":
				approval.ExpectedEffect = "Isolate runtime session"
			case "ttl":
				approval.TTLSeconds = 300
			case "receipt_run":
				receipt["run_id"] = "pid_99000009-0000-4000-8000-000000000009"
			case "receipt_plan":
				receipt["plan_hash"] = "sha256:" + strings.Repeat("b", 64)
			case "receipt_outcome":
				receipt["outcome"] = "planner_rejected"
			}
			raw, _ := json.Marshal(value)
			if got, err := decodeSecurityAgentApprovalContext(raw, approval); err != ErrRepositoryUnavailable || got != nil {
				t.Fatal("contradictory approval context accepted")
			}
		})
	}
}

func TestSecurityAgentApprovalContextWithholdsInvalidRationale(t *testing.T) {
	for _, summary := range []any{strings.Repeat("x", 501), 42, map[string]any{"password": "protected-summary-sentinel"}, nil} {
		approval, value := approvalContextFixture("update_finding_response")
		value["planner_receipt"] = map[string]any{"run_id": approval.RunID, "plan_hash": value["plan_hash"], "outcome": "accepted", "summary": summary}
		raw, _ := json.Marshal(value)
		got, err := decodeSecurityAgentApprovalContext(raw, approval)
		if err != nil || got.Rationale == nil || got.Rationale.State != "withheld" || got.Rationale.Summary != "" {
			t.Fatal("malformed rationale was exposed or invented", err)
		}
	}
}
