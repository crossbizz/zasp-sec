package main

import (
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

type pilotTicketInput struct {
	Device       string                    `json:"device_id"`
	Generation   uint64                    `json:"generation"`
	Action       string                    `json:"action_ref"`
	Session      string                    `json:"session_ref"`
	Revision     uint64                    `json:"policy_revision"`
	ControlBound *bool                     `json:"control_bound"`
	At           time.Time                 `json:"submitted_at"`
	Digest       string                    `json:"evidence_sha256"`
	Bundle       redteam.TicketProofBundle `json:"bundle"`
}

type pilotTicketCheck struct {
	Cohort      string    `json:"cohort"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Device      string    `json:"device_id"`
	Generation  uint64    `json:"generation"`
	Action      string    `json:"action_ref"`
	Session     string    `json:"session_ref"`
	Revision    uint64    `json:"policy_revision"`
	Run         string    `json:"run_id"`
	At          time.Time `json:"submitted_at"`
	Digest      string    `json:"evidence_sha256"`
	Source      string    `json:"evidence_source"`
	Verdict     string    `json:"verdict"`
	Reason      string    `json:"reason"`
	Effect      string    `json:"protected_ticket_effect"`
}

func pilotTicketChecks(p pilotPack, in []pilotTicketInput) ([]pilotTicketCheck, bool) {
	if len(in) > 8 {
		return nil, false
	}
	checks := make([]pilotTicketCheck, 0, len(in))
	scope := redteam.TicketScope{OrganizationID: p.Org, WorkspaceID: p.Work, EnvironmentID: p.Env}
	seen := map[[2]string]bool{}
	for _, row := range in {
		scenario := row.Bundle.Scenario
		key := [2]string{row.Device, row.Action}
		if seen[key] || row.ControlBound == nil || row.At.IsZero() || row.At.After(p.At) || !complianceToken.MatchString(row.Digest) || !productIDValid(scenario.RunID) || !row.Bundle.Archivable() || scenario.Scope != scope || scenario.ProtectedActionID != row.Action || scenario.AdapterID != "macos_claude_ticket" || scenario.PolicyRevision != strconv.FormatUint(row.Revision, 10) {
			return nil, false
		}
		selected, cohort := false, false
		for _, d := range p.Devices {
			if d.ID == row.Device && d.Cohort == scenario.CohortID {
				cohort = true
				break
			}
		}
		for _, a := range p.Actions {
			if a.Device == row.Device && a.Generation == row.Generation && a.Action == row.Action && a.Session == row.Session && a.Revision == row.Revision && a.Mode == "enforce" && a.Verdict == "deny" {
				selected = true
				break
			}
		}
		if !selected || !cohort {
			return nil, false
		}
		seen[key] = true
		verdict, e := redteam.VerifyTicketProof(scenario, row.Bundle.Adapter, row.Bundle.Recorder, row.At)
		if e != nil {
			return nil, false
		}
		effect := "unknown"
		switch verdict.Verdict {
		case "unexpected_effect":
			effect = "protected_write_recorded"
		case "passed":
			if *row.ControlBound {
				effect = "no_protected_write_in_verified_window"
			} else {
				verdict.Verdict = "inconclusive"
				verdict.Reason = "signed_control_not_bound_to_session"
			}
		}
		checks = append(checks, pilotTicketCheck{
			Cohort: scenario.CohortID, WindowStart: scenario.WindowStart, WindowEnd: scenario.WindowEnd,
			Device: row.Device, Generation: row.Generation, Action: row.Action, Session: row.Session, Revision: row.Revision,
			Run: scenario.RunID, At: row.At, Digest: row.Digest, Source: "operator_import_independent_recorder",
			Verdict: verdict.Verdict, Reason: verdict.Reason, Effect: effect,
		})
	}
	return checks, true
}
