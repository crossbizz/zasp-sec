package redteam

import (
	"testing"
	"time"
)

type ticketProofFixture struct {
	s   TicketScenario
	a   TicketAdapterEvidence
	r   TicketRecorderEvidence
	now time.Time
}

func ticketProof() ticketProofFixture {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	run := TicketRunBinding{Scope: TicketScope{OrganizationID: "pid_ef000001-0000-4000-8000-000000000001", WorkspaceID: "pid_ef000002-0000-4000-8000-000000000002", EnvironmentID: "pid_ef000003-0000-4000-8000-000000000003"}, RunID: "run-1", TargetID: "ticket", Operation: "synthetic_ticket_update"}
	binding := TicketPolicyBinding{AdapterID: "adapter-1", CohortID: "cohort-1", PolicyRevision: "policy-1"}
	s := TicketScenario{Version: TicketProofVersion, TicketRunBinding: run, TicketPolicyBinding: binding, Environment: "staging", CredentialClass: "test_write", RecorderID: "recorder", ControlActionID: "first", ProtectedActionID: "second", WindowStart: start, WindowEnd: start.Add(time.Minute)}
	a := TicketAdapterEvidence{Version: s.Version, TicketRunBinding: run, TicketPolicyBinding: binding, Capability: "supported", Decisions: []TicketActionDecision{
		{ActionID: s.ControlActionID, DecisionID: "decision-1", Verdict: "allow", Mode: "enforce", Applied: true, DecidedAt: start.Add(time.Second)},
		{ActionID: s.ProtectedActionID, DecisionID: "decision-2", Verdict: "block", Mode: "enforce", Applied: true, DecidedAt: start.Add(4 * time.Second)},
	}}
	r := TicketRecorderEvidence{Version: s.Version, TicketRunBinding: run, RecorderID: s.RecorderID, Healthy: true, CompleteFrom: start, CompleteThrough: s.WindowEnd, Writes: []TicketWriteReceipt{{ActionID: s.ControlActionID, ReceiptID: "write-1", RecordedAt: start.Add(2 * time.Second)}}}
	return ticketProofFixture{s, a, r, s.WindowEnd.Add(time.Minute)}
}

func TestTicketProofVerifiesPositiveEvidenceAndFailsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, verdict string
		change        func(*ticketProofFixture)
	}{
		{"healthy pair", "passed", func(f *ticketProofFixture) {}},
		{"unsupported", "unsupported", func(f *ticketProofFixture) { f.a.Capability = "unsupported" }},
		{"unattested coverage", "inconclusive", func(f *ticketProofFixture) { f.a.Capability = "" }},
		{"foreign capability", "inconclusive", func(f *ticketProofFixture) {
			f.a.Capability = "unsupported"
			f.a.Scope.WorkspaceID = f.s.Scope.EnvironmentID
		}},
		{"distinct target", "inconclusive", func(f *ticketProofFixture) { f.r.TargetID = "other" }},
		{"foreign recorder", "inconclusive", func(f *ticketProofFixture) { f.r.RecorderID = "other" }},
		{"foreign run", "inconclusive", func(f *ticketProofFixture) { f.r.RunID = "other" }},
		{"older policy", "inconclusive", func(f *ticketProofFixture) { f.a.PolicyRevision = "old" }},
		{"different adapter", "inconclusive", func(f *ticketProofFixture) { f.a.AdapterID = "other" }},
		{"other cohort", "inconclusive", func(f *ticketProofFixture) { f.a.CohortID = "other" }},
		{"different operation", "inconclusive", func(f *ticketProofFixture) { f.r.Operation = "other" }},
		{"missing denial", "inconclusive", func(f *ticketProofFixture) { f.a.Decisions = f.a.Decisions[:1] }},
		{"monitor would block", "inconclusive", func(f *ticketProofFixture) { f.a.Decisions[1].Mode = "monitor" }},
		{"unapplied block", "inconclusive", func(f *ticketProofFixture) { f.a.Decisions[1].Applied = false }},
		{"cloned decision receipt", "inconclusive", func(f *ticketProofFixture) { f.a.Decisions[1].DecisionID = f.a.Decisions[0].DecisionID }},
		{"duplicate same decision", "passed", func(f *ticketProofFixture) { f.a.Decisions = append(f.a.Decisions, f.a.Decisions[1]) }},
		{"conflicting decision", "inconclusive", func(f *ticketProofFixture) {
			v := f.a.Decisions[1]
			v.DecisionID = "conflict"
			f.a.Decisions = append(f.a.Decisions, v)
		}},
		{"unavailable recorder", "inconclusive", func(f *ticketProofFixture) { f.r.Healthy = false }},
		{"late recorder start", "inconclusive", func(f *ticketProofFixture) { f.r.CompleteFrom = f.s.WindowStart.Add(time.Second) }},
		{"incomplete watermark", "inconclusive", func(f *ticketProofFixture) { f.r.CompleteThrough = f.s.WindowEnd.Add(-time.Second) }},
		{"future watermark", "inconclusive", func(f *ticketProofFixture) { f.r.CompleteThrough = f.now.Add(time.Second) }},
		{"missing control write", "inconclusive", func(f *ticketProofFixture) { f.r.Writes = nil }},
		{"prior control write", "inconclusive", func(f *ticketProofFixture) { f.r.Writes[0].RecordedAt = f.s.WindowStart }},
		{"late control write", "inconclusive", func(f *ticketProofFixture) { f.r.Writes[0].RecordedAt = f.s.WindowEnd }},
		{"malformed record", "inconclusive", func(f *ticketProofFixture) { f.r.Writes = append(f.r.Writes, TicketWriteReceipt{}) }},
		{"write despite missing control and adapter", "unexpected_effect", func(f *ticketProofFixture) {
			f.a = TicketAdapterEvidence{}
			f.r.Healthy = false
			f.r.Writes[0].ActionID = f.s.ProtectedActionID
		}},
		{"late correlated write", "unexpected_effect", func(f *ticketProofFixture) {
			f.r.Writes[0].ActionID = f.s.ProtectedActionID
			f.r.Writes[0].RecordedAt = f.s.WindowEnd.Add(time.Second)
		}},
		{"protected write on different target", "inconclusive", func(f *ticketProofFixture) { f.r.TargetID = "other"; f.r.Writes[0].ActionID = f.s.ProtectedActionID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := ticketProof()
			tc.change(&f)
			v, err := VerifyTicketProof(f.s, f.a, f.r, f.now)
			if err != nil || v.Verdict != tc.verdict || v.Mode != "side_effect_verified" || v.Reason == "" {
				t.Fatalf("%+v %v", v, err)
			}
			if v.Verdict == "passed" && (v.ControlReceiptID == "" || v.ControlDecisionID == "" || v.ProtectedDecisionID == "") {
				t.Fatalf("missing receipt references %+v", v)
			}
			if v.Verdict == "unexpected_effect" && v.ProtectedReceiptID == "" {
				t.Fatal(v)
			}
		})
	}
}

func TestTicketProofRejectsUnsafeOrAmbiguousScenario(t *testing.T) {
	for _, mutate := range []func(*ticketProofFixture){
		func(f *ticketProofFixture) { f.s.Version = "future" }, func(f *ticketProofFixture) { f.s.Environment = "production" },
		func(f *ticketProofFixture) { f.s.Environment = "unknown" }, func(f *ticketProofFixture) { f.s.CredentialClass = "production_write" },
		func(f *ticketProofFixture) { f.s.Operation = "other" }, func(f *ticketProofFixture) { f.s.Scope.WorkspaceID = f.s.Scope.EnvironmentID },
		func(f *ticketProofFixture) { f.s.RecorderID = f.s.AdapterID }, func(f *ticketProofFixture) { f.s.ControlActionID = f.s.ProtectedActionID },
		func(f *ticketProofFixture) { f.s.WindowEnd = f.s.WindowStart }, func(f *ticketProofFixture) { f.s.WindowEnd = f.s.WindowStart.Add(2 * time.Hour) },
		func(f *ticketProofFixture) { f.r.Writes = make([]TicketWriteReceipt, 65) }, func(f *ticketProofFixture) { f.now = time.Time{} },
	} {
		f := ticketProof()
		mutate(&f)
		if _, err := VerifyTicketProof(f.s, f.a, f.r, f.now); err != ErrRejected {
			t.Fatal("accepted invalid scenario", f)
		}
	}
}
