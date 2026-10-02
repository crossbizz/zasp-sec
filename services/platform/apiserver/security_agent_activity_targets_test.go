package apiserver

import (
	"encoding/json"
	"fmt"
	"testing"
)

func activityTargetEnvelope(t *testing.T, action string, arguments json.RawMessage, trigger any) json.RawMessage {
	t.Helper()
	actions, detail := actionProjectionFixture(t, action, "", [2]int{}, [2]int{}, func(_, step map[string]any) { step["arguments"] = arguments })
	raw, err := json.Marshal(map[string]any{"detail": detail, "context": map[string]any{"trigger": trigger, "planner_receipt": nil}, "action_details": actions})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityAgentActivityTargetsMaximumPlan(t *testing.T) {
	actions, detail := actionProjectionFixture(t, "update_finding_response", "", [2]int{}, [2]int{}, nil)
	var wire map[string]any
	if json.Unmarshal(actions, &wire) != nil {
		t.Fatal("fixture")
	}
	stepTemplate := detail.Plan.Steps[0]
	executionTemplate := detail.Execution[0]
	detail.Plan.Steps = nil
	detail.Execution = nil
	steps := make([]any, 0, 100)
	for i := 0; i < 100; i++ {
		stepID := fmt.Sprintf("pid_7900%04x-0000-4000-8000-%012x", i, i)
		targetID := fmt.Sprintf("pid_7a00%04x-0000-4000-8000-%012x", i, i)
		step := stepTemplate
		step.ID = stepID
		step.Index = i
		detail.Plan.Steps = append(detail.Plan.Steps, step)
		execution := executionTemplate
		execution.StepID = stepID
		detail.Execution = append(detail.Execution, execution)
		steps = append(steps, map[string]any{"step_id": stepID, "index": i, "action": "update_finding_response", "arguments": map[string]any{"target_id": targetID, "expected_version": 1, "target_status": "under_review"}, "effect": nil, "control_expires_at": nil, "apply_targets": map[string]any{"total": 0, "verified": 0}, "cleanup_targets": map[string]any{"total": 0, "verified": 0}})
	}
	wire["steps"] = steps
	raw, err := json.Marshal(map[string]any{"detail": detail, "context": map[string]any{"trigger": map[string]any{"kind": "finding", "id": activityRelatedTarget, "version": 1}, "planner_receipt": nil}, "action_details": wire})
	if err != nil {
		t.Fatal(err)
	}
	page, err := projectSecurityAgentActivityTargets(raw, runContextTestRunID, "finding", "", 100)
	if err != nil || len(page.Items) != 100 || page.NextID == "" || page.Items[0].ID != activityRelatedTarget {
		t.Fatalf("maximum plan first page=%#v %v", page, err)
	}
	last, err := projectSecurityAgentActivityTargets(raw, runContextTestRunID, "finding", page.NextID, 100)
	if err != nil || len(last.Items) != 1 || last.NextID != "" || last.Items[0].ID <= page.NextID {
		t.Fatalf("101st target missing=%#v %v", last, err)
	}
}

func TestSecurityAgentActivityTargetsTypedPagination(t *testing.T) {
	const target = "pid_78000009-0000-4000-8000-000000000009"
	args := json.RawMessage(`{"target_id":"` + target + `","expected_version":1,"target_status":"under_review"}`)
	trigger := map[string]any{"kind": "finding", "id": activityRelatedTarget, "version": 1}
	raw := activityTargetEnvelope(t, "update_finding_response", args, trigger)
	page, err := projectSecurityAgentActivityTargets(raw, runContextTestRunID, "finding", "", 1)
	if err != nil || page.Coverage != "complete" || len(page.Items) != 1 || page.Items[0].ID != activityRelatedTarget || page.Items[0].Kind != "finding" || page.NextID != activityRelatedTarget {
		t.Fatalf("first target page=%#v err=%v", page, err)
	}
	next, err := projectSecurityAgentActivityTargets(raw, runContextTestRunID, "finding", page.NextID, 1)
	if err != nil || len(next.Items) != 1 || next.Items[0].ID != target || next.NextID != "" {
		t.Fatalf("next target page=%#v err=%v", next, err)
	}
	trigger["id"] = target
	page, err = projectSecurityAgentActivityTargets(activityTargetEnvelope(t, "update_finding_response", args, trigger), runContextTestRunID, "finding", "", 100)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != target || page.NextID != "" {
		t.Fatalf("target not deduplicated=%#v %v", page, err)
	}
}

func TestSecurityAgentActivityTargetsCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, kind, action, args, triggerKind, coverage string
		count                                           int
	}{
		{"known missing finding", "finding", "create_temporary_policy", `null`, "manual", "complete", 0},
		{"unknown trigger", "finding", "create_temporary_policy", `null`, "", "partial", 0},
		{"legacy finding args", "finding", "update_finding_response", `null`, "manual", "partial", 0},
		{"legacy session args", "session", "isolate_session", `null`, "manual", "partial", 0},
		{"path trigger", "attack_path", "update_finding_response", `null`, "attack_path", "complete", 1},
		{"session trigger", "session", "update_finding_response", `null`, "runtime_decision", "complete", 1},
		{"policy environment not finding", "finding", "create_temporary_policy", `{"target_id":"` + activityRelatedTarget + `","scope":"` + activityRelatedTarget + `","mode":"block","ttl_seconds":60}`, "manual", "complete", 0},
		{"session action", "session", "isolate_session", `{"target_id":"` + activityRelatedTarget + `","session_id":"` + activityRelatedTarget + `","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":60}`, "manual", "complete", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var trigger any
			if tc.triggerKind != "" {
				trigger = map[string]any{"kind": tc.triggerKind, "id": activityRelatedTarget, "version": 1}
			}
			page, err := projectSecurityAgentActivityTargets(activityTargetEnvelope(t, tc.action, json.RawMessage(tc.args), trigger), runContextTestRunID, tc.kind, "", 10)
			if err != nil || page.Coverage != tc.coverage || len(page.Items) != tc.count || page.Items == nil {
				t.Fatalf("target coverage=%#v %v", page, err)
			}
		})
	}
}

func TestSecurityAgentActivityTargetsRejectInvalidAuthority(t *testing.T) {
	raw := activityTargetEnvelope(t, "update_finding_response", json.RawMessage(`null`), nil)
	for _, tc := range []struct {
		run, kind, after string
		limit            int
	}{
		{activityRelatedTarget, "finding", "", 10}, {runContextTestRunID, "audit", "", 10}, {runContextTestRunID, "manual", "", 10}, {runContextTestRunID, "finding", "invalid", 10}, {runContextTestRunID, "finding", "", 0}, {runContextTestRunID, "finding", "", 101},
	} {
		if _, err := projectSecurityAgentActivityTargets(raw, tc.run, tc.kind, tc.after, tc.limit); err == nil {
			t.Fatalf("invalid target projection accepted: %#v", tc)
		}
	}
	if _, err := projectSecurityAgentActivityTargets([]byte(`{}`), runContextTestRunID, "finding", "", 10); err != ErrRepositoryUnavailable {
		t.Fatalf("unvalidated envelope accepted: %v", err)
	}
}
