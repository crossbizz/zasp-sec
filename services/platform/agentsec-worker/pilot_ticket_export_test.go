package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

func ticketExportFixture(o, w, e, run, target, cohort, control, protected string, start time.Time) redteam.TicketProofBundle {
	bind := redteam.TicketRunBinding{Scope: redteam.TicketScope{OrganizationID: o, WorkspaceID: w, EnvironmentID: e}, RunID: run, TargetID: target, Operation: "synthetic_ticket_update"}
	rule := redteam.TicketPolicyBinding{AdapterID: "macos_claude_ticket", CohortID: cohort, PolicyRevision: "5"}
	s := redteam.TicketScenario{Version: redteam.TicketProofVersion, TicketRunBinding: bind, TicketPolicyBinding: rule, Environment: "staging", CredentialClass: "test_write", RecorderID: "operator-recorder-private-id", ControlActionID: control, ProtectedActionID: protected, WindowStart: start, WindowEnd: start.Add(30 * time.Second)}
	adapter := redteam.TicketAdapterEvidence{Version: s.Version, TicketRunBinding: bind, TicketPolicyBinding: rule, Capability: "supported", Decisions: []redteam.TicketActionDecision{
		{ActionID: control, DecisionID: "control-decision", Verdict: "allow", Mode: "enforce", Applied: true, DecidedAt: start.Add(time.Second)},
		{ActionID: protected, DecisionID: "protected-decision", Verdict: "block", Mode: "enforce", Applied: true, DecidedAt: start.Add(4 * time.Second)},
	}}
	recorder := redteam.TicketRecorderEvidence{Version: s.Version, TicketRunBinding: bind, RecorderID: s.RecorderID, Healthy: true, CompleteFrom: start, CompleteThrough: s.WindowEnd, Writes: []redteam.TicketWriteReceipt{{ActionID: control, ReceiptID: "recorder-private-write-receipt", RecordedAt: start.Add(2 * time.Second)}}}
	return redteam.TicketProofBundle{Scenario: s, Adapter: adapter, Recorder: recorder}
}

func seedPilotExportTicketProof(t *testing.T, ctx context.Context, db *pgx.Conn, o, w, e, actor, device, session, agent, definition, run string) (string, string) {
	t.Helper()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	control, protected := strings.Repeat("7", 64), strings.Repeat("6", 64)
	start := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	b := ticketExportFixture(o, w, e, run, agent, "export-test", control, protected, start)
	if !b.Archivable() {
		t.Fatal("invalid static ticket fixture")
	}
	raw, _ := json.Marshal(b)
	exec("INSERT INTO public.zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Pilot proof',$5,'agent_endpoint','[\"prompt_injection\"]','{\"environment\":\"staging\",\"credential_class\":\"test_write\",\"expected_side_effects\":[\"synthetic_ticket_update\"]}',$6)", o, w, e, definition, agent, actor)
	exec("INSERT INTO public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,queued_at,completed_at,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size) VALUES($1,$2,$3,$4,$5,1,$6,'complete',1,digest('pilot-input','sha256'),$7,$8,'pass','pilot-ref','pilot-key','version-1',digest('pilot-proof','sha256'),10)", o, w, e, run, definition, actor, start.Add(-time.Minute), b.Scenario.WindowEnd)
	exec("INSERT INTO public.zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'safe control','ticket observation','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)", o, w, e, run)
	exec("INSERT INTO public.zasp_ticket_verification_imports(organization_id,workspace_id,environment_id,run_id,definition_version,submitted_by,bundle) VALUES($1,$2,$3,$4,1,$5,$6::jsonb)", o, w, e, run, actor, string(raw))
	exec("INSERT INTO public.zasp_ticket_cohort_rollouts(organization_id,workspace_id,environment_id,cohort,revision,phase,destination,targets,actor,request_key,request_digest,created_at) VALUES($1,$2,$3,'export-test',1,'canary','approved',jsonb_build_array(jsonb_build_object('id',$4::text,'generation',1,'revision',5,'mode','enforce')),$5,'test-rollout-key','test-rollout-digest',$6)", o, w, e, device, actor, start.Add(-time.Minute))
	for _, i := range []struct {
		action, verdict, classification string
		blocks                          bool
		at                              time.Time
	}{{control, "continue", "allowed_destination", false, start.Add(time.Second)}, {protected, "deny", "outside_allowed_destination", true, start.Add(4 * time.Second)}} {
		exec("INSERT INTO public.zasp_endpoint_observations(organization_id,workspace_id,environment_id,device_id,credential_generation,action_id,observation) VALUES($1,$2,$3,$4,1,$5,jsonb_build_object('session_ref',$6::text,'mode','enforce','would_block',$7::boolean,'policy_revision',5,'tool','mcp__pilot__update_ticket','verdict',$8::text,'target_class',$9::text,'observed_at',$10::timestamptz,'local_uid',909))", o, w, e, device, i.action, session, i.blocks, i.verdict, i.classification, i.at)
	}
	return control, protected
}

func TestPilotTicketOutcomeRequiresExactScopeAndPositiveControl(t *testing.T) {
	o, w, e := "pid_00000000-0000-4000-8000-000000000001", "pid_00000000-0000-4000-8000-000000000002", "pid_00000000-0000-4000-8000-000000000003"
	d, run := "pid_00000000-0000-4000-8000-000000000004", "pid_00000000-0000-4000-8000-000000000005"
	protected, session := strings.Repeat("6", 64), strings.Repeat("c", 64)
	now := time.Now().UTC()
	b := ticketExportFixture(o, w, e, run, d, "Pilot", strings.Repeat("7", 64), protected, now.Add(-time.Hour))
	bound := false
	p := pilotPack{Org: o, Work: w, Env: e, At: now, Devices: []pilotDevice{{ID: d, Cohort: "Pilot"}}, Actions: []pilotObservation{{Device: d, Generation: 1, Action: protected, Session: session, Revision: 5, Mode: "enforce", Verdict: "deny"}}}
	in := []pilotTicketInput{{Device: d, Generation: 1, Action: protected, Session: session, Revision: 5, ControlBound: &bound, At: now, Digest: strings.Repeat("a", 64), Bundle: b}}
	for _, state := range []struct {
		bound    bool
		expected string
	}{{false, "unknown"}, {true, "no_protected_write_in_verified_window"}} {
		bound = state.bound
		checks, ok := pilotTicketChecks(p, in)
		if !ok || len(checks) != 1 || checks[0].Effect != state.expected {
			t.Fatal("wrong bound-control outcome", checks)
		}
	}
	bound = false
	in[0].Bundle.Recorder.Writes = append(in[0].Bundle.Recorder.Writes, redteam.TicketWriteReceipt{ActionID: protected, ReceiptID: "actual-adverse-write", RecordedAt: b.Scenario.WindowEnd})
	if c, ok := pilotTicketChecks(p, in); !ok || c[0].Effect != "protected_write_recorded" {
		t.Fatal("failed to preserve observed side effect")
	}
	in[0].Session = strings.Repeat("b", 64)
	if _, ok := pilotTicketChecks(p, in); ok {
		t.Fatal("different session accepted")
	}
}
