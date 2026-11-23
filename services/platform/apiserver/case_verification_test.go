package apiserver

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func caseFixture(t *testing.T) storedCaseEvidence {
	t.Helper()
	var bundle redteam.TicketProofBundle
	for _, file := range []struct {
		file   string
		target any
	}{{"scenario", &bundle.Scenario}, {"adapter", &bundle.Adapter}, {"recorder", &bundle.Recorder}} {
		data, err := os.ReadFile("../cmd/verify-ticket/testdata/" + file.file + ".json")
		if err != nil || json.Unmarshal(data, file.target) != nil {
			t.Fatal("invalid fixture", file.file, err)
		}
	}
	fixture := "pid_10000000-0000-4000-8000-000000000101"
	target := "pid_10000000-0000-4000-8000-000000000102"
	bundle.Scenario.RunID, bundle.Scenario.TargetID = fixture, target
	bundle.Recorder.TicketRunBinding, bundle.Adapter.TicketRunBinding = bundle.Scenario.TicketRunBinding, bundle.Scenario.TicketRunBinding
	now := bundle.Scenario.WindowEnd.Add(time.Minute)
	return storedCaseEvidence{CaseID: runtimeReadSessionID, TargetID: target, RemediationVerified: true, FixtureRunID: &fixture, SubmittedAt: &now, Bundle: &bundle}
}

func TestCaseVerificationRequiresBothAttestedChecks(t *testing.T) {
	for _, test := range []struct {
		name         string
		change       func(*redteam.TicketProofBundle)
		signed, want bool
	}{
		{"verified", nil, true, true}, {"unsigned", nil, false, false},
		{"business_task_failed", func(b *redteam.TicketProofBundle) { b.Recorder.Writes = []redteam.TicketWriteReceipt{} }, true, false},
		{"protected_write_observed", func(b *redteam.TicketProofBundle) {
			write := b.Recorder.Writes[0]
			write.ActionID = b.Scenario.ProtectedActionID
			b.Recorder.Writes = append(b.Recorder.Writes, write)
		}, true, false},
		{"missing_enforcement_receipt", func(b *redteam.TicketProofBundle) { b.Adapter.Decisions = b.Adapter.Decisions[:1] }, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := caseFixture(t)
			if test.change != nil {
				test.change(evidence.Bundle)
			}
			if test.signed {
				path := installTestTicketAttestations(t, evidence.Bundle, *evidence.SubmittedAt)
				t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", path)
			}
			result, err := verifyCase(evidence, evidence.Bundle.Scenario.Scope, ticketProofQualification)
			if err != nil || (result.State == "verified_complete") != test.want || (result.SecurityCheckPassed && result.BusinessTaskPreserved) != test.want {
				t.Fatalf("%+v %v", result, err)
			}
			if test.want && (result.SecurityReceiptID == nil || result.BusinessReceiptID == nil) {
				t.Fatal("missing independent checks")
			}
		})
	}
}

func TestRuntimeOutcomeProjectionPreservesCanonicalEvidence(t *testing.T) {
	raw := json.RawMessage(`{"items":[{"id":"one","class":"policy","action":"block","source":"gateway","evidence_id":"receipt"},{"id":"two","class":"policy","action":"block","source":"otlp"}],"page_info":{"has_more":false,"next_cursor":null}}`)
	out, err := runtimePageOutcomes(raw)
	var page struct {
		Items []struct {
			ID       string
			Evidence string `json:"evidence_id"`
			Outcome  string
		}
		PageInfo map[string]any `json:"page_info"`
	}
	if err != nil || json.Unmarshal(out, &page) != nil || len(page.Items) != 2 || page.Items[0].Evidence != "receipt" || page.Items[0].Outcome != "prevented" || page.Items[1].Outcome != "outcome_unknown" || page.PageInfo["has_more"] != false {
		t.Fatalf("page=%s err=%v", out, err)
	}
}

func TestSessionIntentLateOutcomeReplacesOnlyExactDecision(t *testing.T) {
	first, second := "pid_10000000-0000-4000-8000-000000000001", "pid_10000000-0000-4000-8000-000000000002"
	now := time.Now()
	rows := []sessionActionEvidence{{ID: second, Source: "authenticated_workload", Action: "block", Class: "tool", Operation: "review", ObservedAt: now, EvidenceIDs: []string{second}}, {ID: first, Source: "authenticated_workload", Action: "allow", Class: "tool", Operation: "draft", ObservedAt: now.Add(-time.Minute), EvidenceIDs: []string{first}}}
	before, _ := projectSessionActions(rows)
	rows[0].Receipt = "not_dispatched"
	rows[0].EvidenceIDs = append(rows[0].EvidenceIDs, runtimeReadSessionID)
	after, err := projectSessionActions(rows)
	if err != nil || before[0].Outcome != "outcome_unknown" || after[0].Outcome != "prevented" || !after[0].Attention || after[1].Outcome != "outcome_unknown" {
		t.Fatalf("%+v %+v %v", before, after, err)
	}
}
