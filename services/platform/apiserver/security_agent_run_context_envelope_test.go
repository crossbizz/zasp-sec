package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func runContextEnvelopeFixture(t *testing.T, mutate func(map[string]any, map[string]any)) json.RawMessage {
	t.Helper()
	detail := runContextDetailFixture(t, "")
	receipt := map[string]any{"run_id": runContextTestRunID, "plan_hash": detail.Plan.PlanHash, "outcome": "accepted", "summary": "Review password=seeded; contain the finding."}
	context := map[string]any{"trigger": json.RawMessage(runContextTestTrigger), "planner_receipt": receipt}
	if mutate != nil {
		mutate(context, receipt)
	}
	payload, err := json.Marshal(map[string]any{"detail": detail, "context": context})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSecurityAgentRunContextEnvelopeSanitizesBeforePublicConstruction(t *testing.T) {
	payload := runContextEnvelopeFixture(t, nil)
	value, err := decodeSecurityAgentRunContextEnvelope(payload, runContextTestRunID)
	if err != nil {
		t.Fatal(err)
	}
	if value.RunContext == nil || value.RunContext.Trigger == nil || value.RunContext.Trigger.Kind != "finding" || value.RunContext.Rationale == nil || value.RunContext.Rationale.State != "available" || value.RunContext.Rationale.Summary != "Review password=[REDACTED]; contain the finding." {
		t.Fatal("private receipt was not projected through redaction")
	}
	public, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "seeded") || strings.Contains(string(public), "planner_receipt") || strings.Contains(string(public), `"outcome":"accepted"`) {
		t.Fatal("private receipt fields escaped into public detail")
	}
	if value.Authorization != "authorized" || value.BudgetStopReason != "budget_usage_unknown" {
		t.Fatal("projection changed existing authority")
	}
}

func TestSecurityAgentRunContextEnvelopeWithholdsOnlyUnsafeSummary(t *testing.T) {
	for _, summary := range []any{nil, 3, map[string]any{"secret": "seeded"}, "", strings.Repeat("é", 251), "unsafe\ntext", `https` + `://alice:"seeded"@example.invalid`} {
		payload := runContextEnvelopeFixture(t, func(_ map[string]any, receipt map[string]any) { receipt["summary"] = summary })
		value, err := decodeSecurityAgentRunContextEnvelope(payload, runContextTestRunID)
		if err != nil || value.RunContext == nil || value.RunContext.Rationale == nil || value.RunContext.Rationale.State != "withheld" || value.RunContext.Rationale.Summary != "" || value.Plan == nil {
			t.Fatal("unsafe summary must be withheld without discarding valid run data")
		}
	}
}

func TestSecurityAgentRunContextEnvelopePreservesMissingReceipt(t *testing.T) {
	for _, missingTrigger := range []bool{false, true} {
		payload := runContextEnvelopeFixture(t, func(context map[string]any, _ map[string]any) {
			context["planner_receipt"] = nil
			if missingTrigger {
				context["trigger"] = nil
			}
		})
		value, err := decodeSecurityAgentRunContextEnvelope(payload, runContextTestRunID)
		if err != nil || value.RunContext == nil || value.RunContext.Rationale != nil || (value.RunContext.Trigger == nil) != missingTrigger {
			t.Fatal("missing receipt was fabricated or rejected")
		}
	}
}

func TestSecurityAgentRunContextEnvelopeRefusesMismatchedAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"foreign run", func(_ map[string]any, receipt map[string]any) {
			receipt["run_id"] = "pid_78000099-0000-4000-8000-000000000099"
		}},
		{"other plan", func(_ map[string]any, receipt map[string]any) {
			receipt["plan_hash"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{"rejected receipt", func(_ map[string]any, receipt map[string]any) { receipt["outcome"] = "planner_rejected" }},
		{"budget stopped", func(_ map[string]any, receipt map[string]any) { receipt["outcome"] = "budget_stopped" }},
		{"extra raw field", func(_ map[string]any, receipt map[string]any) { receipt["provider_error"] = "seeded" }},
		{"missing summary", func(_ map[string]any, receipt map[string]any) { delete(receipt, "summary") }},
		{"unbound trigger", func(context map[string]any, _ map[string]any) { context["trigger"] = nil }},
		{"unknown context field", func(context map[string]any, _ map[string]any) { context["secret"] = "seeded" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := decodeSecurityAgentRunContextEnvelope(runContextEnvelopeFixture(t, test.mutate), runContextTestRunID)
			if err != ErrRepositoryUnavailable || value.Run.ID != "" || value.RunContext != nil {
				t.Fatal("mismatched envelope returned authority or leaked a noncanonical error")
			}
		})
	}
}
