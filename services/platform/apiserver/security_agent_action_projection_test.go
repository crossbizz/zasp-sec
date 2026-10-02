package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func actionProjectionFixture(t *testing.T, action, state string, apply, cleanup [2]int, mutate func(map[string]any, map[string]any)) (json.RawMessage, SecurityAgentRunDetail) {
	t.Helper()
	detail := runContextDetailFixture(t, "")
	detail.Plan.Steps[0].Action = action
	detail.Execution[0].Action = action
	stepID := detail.Plan.Steps[0].ID
	step := map[string]any{"step_id": stepID, "index": 0, "action": action, "arguments": nil, "effect": nil, "control_expires_at": nil,
		"apply_targets": map[string]any{"total": apply[0], "verified": apply[1]}, "cleanup_targets": map[string]any{"total": cleanup[0], "verified": cleanup[1]}}
	if state != "" {
		step["effect"] = map[string]any{"step_id": stepID, "action": action, "state": state, "outcome_id": nil, "result_digest": nil}
		if state == "verified" || state == "succeeded" || state == "cleanup_pending" || state == "cleaned" || state == "cleanup_failed" {
			detail.Execution[0].OutcomeID = "pid_78000009-0000-4000-8000-000000000009"
			detail.Execution[0].ResultDigest = "sha256:" + strings.Repeat("c", 64)
			step["effect"].(map[string]any)["outcome_id"] = detail.Execution[0].OutcomeID
			step["effect"].(map[string]any)["result_digest"] = detail.Execution[0].ResultDigest
		}
	}
	envelope := map[string]any{"run_id": detail.Run.ID, "plan_hash": detail.Plan.PlanHash, "steps": []any{step}}
	if mutate != nil {
		mutate(envelope, step)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload, detail
}

func TestSecurityAgentActionProjectionSeparatesEvidence(t *testing.T) {
	for _, test := range []struct {
		name, action, effect, verification, source, support, rollback, cleanup string
		applyTargets, cleanupTargets                                           [2]int
	}{
		{"no effect", "update_finding_response", "", "unavailable", "none", "manual", "unavailable", "unavailable", [2]int{}, [2]int{}},
		{"direct verified", "update_finding_response", "verified", "verified", "effect_record", "manual", "unavailable", "unavailable", [2]int{}, [2]int{}},
		{"digest not verification", "revoke_integration_connection", "succeeded", "pending", "effect_record", "not_supported", "unavailable", "unavailable", [2]int{}, [2]int{}},
		{"unknown connector", "revoke_integration_connection", "unknown_outcome", "inconclusive", "effect_record", "not_supported", "unavailable", "unavailable", [2]int{}, [2]int{}},
		{"failed finding", "update_finding_response", "known_failure", "failed", "effect_record", "manual", "unavailable", "unavailable", [2]int{}, [2]int{}},
		{"policy applied", "create_temporary_policy", "cleanup_pending", "verified", "policy_targets", "automatic", "pending", "unavailable", [2]int{2, 2}, [2]int{}},
		{"partial application", "isolate_session", "leased", "pending", "policy_targets", "automatic", "not_started", "unavailable", [2]int{2, 1}, [2]int{}},
		{"cleaned without application", "create_temporary_policy", "cleaned", "unavailable", "policy_targets", "automatic", "completed", "unavailable", [2]int{}, [2]int{}},
		{"cleaned without active targets", "isolate_session", "cleaned", "verified", "policy_targets", "automatic", "completed", "unavailable", [2]int{2, 2}, [2]int{}},
		{"verified cleanup", "isolate_session", "cleaned", "verified", "policy_targets", "automatic", "completed", "verified", [2]int{2, 2}, [2]int{2, 2}},
		{"failed cleanup", "create_temporary_policy", "cleanup_failed", "verified", "policy_targets", "automatic", "failed", "pending", [2]int{2, 2}, [2]int{2, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, detail := actionProjectionFixture(t, test.action, test.effect, test.applyTargets, test.cleanupTargets, nil)
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil || len(got) != 1 {
				t.Fatal("persisted action detail rejected")
			}
			step := got[0]
			if step.Verification.State != test.verification || step.Verification.Source != test.source || step.Rollback.Support != test.support || step.Rollback.State != test.rollback || step.Rollback.Verification.State != test.cleanup {
				t.Fatalf("application and rollback evidence were conflated: %+v", step)
			}
			if step.Arguments != nil || step.TTLSeconds != nil || step.ControlExpiresAt != nil || (step.Result == nil) != (test.effect == "") {
				t.Fatal("missing evidence was fabricated")
			}
			if step.Result != nil && step.Result.State != test.effect {
				t.Fatal("persisted effect state changed")
			}
		})
	}
}

func TestSecurityAgentActionProjectionRefusesUnboundEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"foreign run", func(e, _ map[string]any) { e["run_id"] = "pid_78000009-0000-4000-8000-000000000009" }},
		{"foreign plan", func(e, _ map[string]any) { e["plan_hash"] = "sha256:" + strings.Repeat("b", 64) }},
		{"foreign step", func(_, s map[string]any) { s["step_id"] = "pid_78000009-0000-4000-8000-000000000009" }},
		{"wrong index", func(_, s map[string]any) { s["index"] = 1 }},
		{"wrong action", func(_, s map[string]any) { s["action"] = "revoke_integration_connection" }},
		{"duplicate step", func(e, s map[string]any) { e["steps"] = []any{s, s} }},
		{"missing step", func(e, _ map[string]any) { e["steps"] = []any{} }},
		{"private field", func(_, s map[string]any) { s["credential"] = "protected-action-sentinel" }},
		{"wrong effect", func(_, s map[string]any) {
			s["effect"].(map[string]any)["step_id"] = "pid_78000009-0000-4000-8000-000000000009"
		}},
		{"wrong effect action", func(_, s map[string]any) { s["effect"].(map[string]any)["action"] = "isolate_session" }},
		{"invalid effect", func(_, s map[string]any) { s["effect"].(map[string]any)["state"] = "protected-action-sentinel" }},
		{"outcome without digest", func(_, s map[string]any) {
			s["effect"].(map[string]any)["outcome_id"] = "pid_78000009-0000-4000-8000-000000000009"
		}},
		{"invalid counts", func(_, s map[string]any) { s["apply_targets"] = map[string]any{"total": 1, "verified": 2} }},
		{"missing count", func(_, s map[string]any) { s["apply_targets"] = map[string]any{"total": nil, "verified": 0} }},
		{"targets without effect", func(_, s map[string]any) {
			s["effect"] = nil
			s["apply_targets"] = map[string]any{"total": 1, "verified": 1}
		}},
		{"unsafe expiry", func(_, s map[string]any) { s["control_expires_at"] = "protected-action-sentinel" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, detail := actionProjectionFixture(t, "create_temporary_policy", "pending", [2]int{}, [2]int{}, test.mutate)
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != ErrRepositoryUnavailable || got != nil || strings.Contains(err.Error(), "protected-action-sentinel") {
				t.Fatal("unbound or private evidence escaped the authority boundary")
			}
		})
	}
}

func TestSecurityAgentActionProjectionPreservesTTLAndResult(t *testing.T) {
	raw, detail := actionProjectionFixture(t, "isolate_session", "cleanup_pending", [2]int{1, 1}, [2]int{}, func(_, s map[string]any) {
		s["arguments"] = json.RawMessage(`{"target_id":"pid_78000005-0000-4000-8000-000000000005","session_id":"pid_78000005-0000-4000-8000-000000000005","device_id":"pid_78000009-0000-4000-8000-000000000009","scope":"pid_78000003-0000-4000-8000-000000000003","ttl_seconds":120}`)
		s["control_expires_at"] = "2026-09-16T12:05:00Z"
		s["effect"].(map[string]any)["outcome_id"] = "pid_78000009-0000-4000-8000-000000000009"
		s["effect"].(map[string]any)["result_digest"] = "sha256:" + strings.Repeat("c", 64)
	})
	detail.Execution[0].OutcomeID = "pid_78000009-0000-4000-8000-000000000009"
	detail.Execution[0].ResultDigest = "sha256:" + strings.Repeat("c", 64)
	got, err := decodeSecurityAgentActionDetails(raw, detail)
	if err != nil || len(got) != 1 || got[0].TTLSeconds == nil || *got[0].TTLSeconds != 120 || got[0].ControlExpiresAt == nil || got[0].ControlExpiresAt.Format("2006-01-02T15:04:05Z07:00") != "2026-09-16T12:05:00Z" || got[0].Result == nil || got[0].Result.OutcomeID != "pid_78000009-0000-4000-8000-000000000009" {
		t.Fatal("TTL, control expiry and persisted effect were not kept distinct")
	}
	detail.Execution[0].OutcomeID = "pid_78000008-0000-4000-8000-000000000008"
	if got, err := decodeSecurityAgentActionDetails(raw, detail); err != ErrRepositoryUnavailable || got != nil {
		t.Fatal("effect inconsistent with displayed execution was accepted")
	}
}

func TestSecurityAgentActionProjectionReachesRunDetail(t *testing.T) {
	actions, detail := actionProjectionFixture(t, "update_finding_response", "verified", [2]int{}, [2]int{}, nil)
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(runContextEnvelopeFixture(t, nil), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["action_details"] = actions
	encodedDetail, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	envelope["detail"] = encodedDetail
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSecurityAgentRunContextEnvelope(payload, runContextTestRunID)
	if err != nil {
		t.Fatal("run detail discarded the validated action projection", err)
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(public, &fields) != nil || !strings.Contains(string(fields["action_details"]), `"source":"effect_record"`) || strings.Contains(string(public), "planner_receipt") || strings.Contains(string(public), "apply_targets") || strings.Contains(string(public), "seeded") {
		t.Fatal("public action detail missing or private authority fields exposed")
	}
}

func TestSecurityAgentActionProjectionStoppedPartialCleanup(t *testing.T) {
	for _, state := range []string{"cleanup_pending", "leased"} {
		t.Run(state, func(t *testing.T) {
			raw, detail := actionProjectionFixture(t, "isolate_session", state, [2]int{1, 0}, [2]int{1, 0}, func(_, s map[string]any) {
				s["effect"].(map[string]any)["outcome_id"] = nil
				s["effect"].(map[string]any)["result_digest"] = nil
			})
			detail.Execution[0].OutcomeID = ""
			detail.Execution[0].ResultDigest = ""
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil || len(got) != 1 || got[0].Rollback.State != "pending" || got[0].Verification.State != "pending" || got[0].Result == nil || got[0].Result.OutcomeID != "" {
				t.Fatal("stopped partial cleanup was rejected, mislabeled or given a fabricated outcome", err)
			}
			detail.ActionDetails = got
			if response := actionDetailHTTP(t, detail, []string{"v1"}, false); response.Code != 200 {
				t.Fatal("public validator rejected legitimate stopped cleanup")
			}
		})
	}
}
