package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessionintent"
)

func TestV3SessionIntentInstalledReceipts(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	exerciseSessionOutcomes(t, b, admin, b.id())
}

func exerciseSessionOutcomes(t *testing.T, b *installedBaseline, admin installedPrincipal, agent string) {
	t.Helper()
	session, credential, event, decision := b.id(), b.id(), b.id(), b.id()
	readEvent, execEvent := b.id(), b.id()
	b.seed(func() {
		b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time)
VALUES($1,$2,$3,$4,$5,$6,'strong','gateway','policy','block','Gateway request blocked',$7,now())`, b.o, b.w, b.e, event, session, agent, b.id())
		b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES
		($1,$2,$3,$4,$5,$6,'strong','otlp','file','read','Read observed',$7,now()-interval '1 minute'),
		($1,$2,$3,$8,$5,$6,'strong','tetragon','process','exec','Process executed',$9,now()-interval '30 seconds')`, b.o, b.w, b.e, readEvent, session, agent, b.id(), execEvent, b.id())
		b.exec(`INSERT INTO zasp_runtime_session_summaries(organization_id,workspace_id,environment_id,id,first_event_at,last_event_at,projected_at,event_count,exact_count,strong_count,probable_count,unattributed_count,minimum_agent_id,maximum_agent_id) VALUES($1,$2,$3,$4,now()-interval '1 minute',now(),now(),3,0,3,0,0,$5,$5)`, b.o, b.w, b.e, session, agent)
		b.exec(`INSERT INTO zasp_workload_bindings(organization_id,workspace_id,environment_id,credential_id,agent_id,session_id,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()-interval '1 hour')`, b.o, b.w, b.e, credential, agent, session, admin.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_workload_actions(organization_id,workspace_id,environment_id,credential_id,action_id,principal_id,request,receipt) VALUES($1,$2,$3,$4,'draft',$5,'{"operation":"draft_reply"}',jsonb_build_object('decision_id',$6::text,'verdict','allow'))`, b.o, b.w, b.e, credential, admin.identity.PrincipalID.String(), decision)
	})
	path := "/api/v1/sessions/" + session + "/intent"
	read := func() map[string]sessionActionResult {
		out := b.serve(&discoveryWorkflowSurface{evidenceDB: b.product}, admin, "getSessionIntent", http.MethodGet, path, map[string]string{"id": session}, "", nil)
		var doc struct {
			Actions []sessionActionResult `json:"actions"`
			Links   []sessionintent.Link  `json:"links"`
		}
		if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &doc) != nil || len(doc.Actions) != 4 {
			t.Fatalf("read=%d %s", out.Code, out.Body)
		}
		foundLink := false
		for _, link := range doc.Links {
			if link.Source == readEvent && link.Target == execEvent && link.Reason == "read_then_activity" {
				foundLink = true
			}
		}
		if !foundLink {
			t.Fatalf("missing observed-time sequence %v", doc.Links)
		}
		results := map[string]sessionActionResult{}
		for _, row := range doc.Actions {
			results[row.ID] = row
		}
		return results
	}
	first := read()
	if first[event].Outcome != "prevented" || !first[event].Attention || first[decision].Outcome != "outcome_unknown" {
		t.Fatalf("missing evidence incorrectly interpreted: %+v", first)
	}
	b.seed(func() {
		b.exec(`UPDATE zasp_workload_actions SET outcome='{"status":"returned"}',observed_at=now() WHERE (organization_id,workspace_id,environment_id,credential_id,action_id)=($1,$2,$3,$4,'draft')`, b.o, b.w, b.e, credential)
	})
	after := read()
	if after[decision].Outcome != "completed" || len(after[decision].EvidenceIDs) != 2 || after[event].Outcome != "prevented" {
		t.Fatalf("late receipt lost: %+v", after)
	}
}

func TestV3CaseVerificationInstalledBoundOwnerFixture(t *testing.T) {
	b := startInstalledV2Baseline(t)
	owner := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	other := b.member("security_engineer", "investigate_sessions", "manage_findings", "manage_workflows", "run_tests", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	r, step, target, fixture := b.id(), b.id(), b.id(), b.id()
	// One Environment, browser principal and agent flow through deployment
	// approval, widened permissions, session evidence, and the verified case.
	exerciseDeploymentReview(t, b, owner, target)
	exerciseSessionOutcomes(t, b, owner, target)
	record := caseFixture(t)
	bundle := record.Bundle
	scope := &bundle.Scenario.Scope
	scope.OrganizationID, scope.WorkspaceID, scope.EnvironmentID = b.o, b.w, b.e
	bundle.Scenario.RunID, bundle.Scenario.TargetID = fixture, target
	bundle.Adapter.TicketRunBinding, bundle.Recorder.TicketRunBinding = bundle.Scenario.TicketRunBinding, bundle.Scenario.TicketRunBinding
	start := time.Now().UTC().Add(-3 * time.Minute)
	end := start.Add(time.Minute)
	bundle.Scenario.WindowStart, bundle.Scenario.WindowEnd = start, end
	bundle.Adapter.Decisions[0].DecidedAt = start.Add(time.Second)
	bundle.Recorder.Writes[0].RecordedAt = start.Add(2 * time.Second)
	bundle.Adapter.Decisions[1].DecidedAt = start.Add(3 * time.Second)
	bundle.Recorder.CompleteFrom, bundle.Recorder.CompleteThrough = start, end
	issued := end.Add(time.Minute)
	key := installTestTicketAttestations(t, bundle, issued)
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", key)
	blob, _ := json.Marshal(bundle)
	seedRemediated := func(run string) {
		b.exec(`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,$4,$5,1,$6,$7,'remediated')`, b.o, b.w, b.e, run, b.id(), b.id(), owner.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_security_agent_provider_remediations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,finding_id,finding_version,integration_id,entity_id,target,parameters,remediation_role_arn,external_id_reference,input_digest,state,prior,observed,completed_at) VALUES($1,$2,$3,$4,$5,'attach_bedrock_guardrail',$6,1,$7,$8,'{}','{}','fixture','fixture',decode(repeat('ab',32),'hex'),'verified','{}','{}',$9)`, b.o, b.w, b.e, run, step, b.id(), b.id(), target, bundle.Scenario.WindowStart.Add(-time.Hour))
	}
	fallbackRun := b.id()
	b.seed(func() {
		seedRemediated(r)
		seedRemediated(fallbackRun)
		b.exec(`INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value) VALUES($1,$2,$3,$4,$5)`, b.o, b.w, b.e, target, owner.identity.PrincipalID.String())
		def := b.id()
		b.exec(`UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3)`, b.o, b.w, b.e)
		b.exec(`INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$4,'Ticket verification',$5,'agent_endpoint','["tool_abuse"]','{"environment":"staging","credential_class":"test_write","expected_side_effects":["synthetic_ticket_update"]}',$6)`, b.o, b.w, b.e, def, target, owner.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest,queued_at) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('ab',32),'hex'),$7)`, b.o, b.w, b.e, fixture, def, owner.identity.PrincipalID.String(), start.Add(-time.Minute))
	})
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	archive := b.serve(surface, owner, "putTicketVerification", http.MethodPut, "/api/v1/test-runs/"+fixture+"/ticket-verification", map[string]string{"id": fixture}, string(blob), nil)
	if archive.Code != 200 || !strings.Contains(archive.Body.String(), `"evidence_qualification":"verified_prevention"`) {
		t.Fatalf("signed archive %d %s", archive.Code, archive.Body)
	}
	requestRun := func(run, op, method string, actor installedPrincipal, body string, status int) caseVerification {
		out := b.serve(surface, actor, op, method, "/api/v1/security-agents/cases/"+run+"/verify", map[string]string{"id": run}, body, nil)
		var doc caseVerification
		if out.Code != status || status == 200 && json.Unmarshal(out.Body.Bytes(), &doc) != nil {
			t.Fatalf("%s=%d %s", op, out.Code, out.Body)
		}
		return doc
	}
	request := func(op, method string, actor installedPrincipal, body string, status int) caseVerification {
		t.Helper()
		return requestRun(r, op, method, actor, body, status)
	}
	if request("getSecurityCaseVerification", "GET", owner, "", 200).State != "open" {
		t.Fatal("unverified case closed")
	}
	body := `{"fixture_run_id":"` + fixture + `"}`
	request("verifySecurityCase", "POST", other, body, 403)
	request("verifySecurityCase", "POST", owner, `{"fixture_run_id":"`+b.id()+`"}`, 400)
	for range 2 {
		if request("verifySecurityCase", "POST", owner, body, 200).State != "verified_complete" {
			t.Fatal("both checks must pass")
		}
	}
	fallback := `{"fixture_run_id":"` + fixture + `","business_fixture_unavailable":true}`
	request("verifySecurityCase", "POST", owner, fallback, 409)
	requestRun(fallbackRun, "verifySecurityCase", "POST", other, fallback, 403)
	fallbackResult := requestRun(fallbackRun, "verifySecurityCase", "POST", owner, fallback, 200)
	if fallbackResult.State != "closed_business_task_unverified" || !fallbackResult.SecurityCheckPassed || fallbackResult.BusinessTaskPreserved || fallbackResult.BusinessReceiptID != nil {
		t.Fatalf("unexpected fallback %+v", fallbackResult)
	}
	if got := requestRun(fallbackRun, "getSecurityCaseVerification", "GET", owner, "", 200); got.State != fallbackResult.State {
		t.Fatal("fallback state lost")
	}
	if n := b.text(`SELECT count(*)::text FROM public.zasp_admin_audit WHERE (organization_id,workspace_id,environment_id,target_id,actor_id,action)=($1,$2,$3,$4,$5,'attach_case_verification_evidence') AND (metadata->>'business_fixture_unavailable')='true'`, b.o, b.w, b.e, fallbackRun, owner.identity.PrincipalID.String()); n != "1" {
		t.Fatal("missing fallback audit", n)
	}

	if n := b.text(`SELECT count(*)::text FROM public.zasp_admin_audit WHERE (organization_id,workspace_id,environment_id,target_id,actor_id,action)=($1,$2,$3,$4,$5,'attach_case_verification_evidence') AND (metadata->>'business_fixture_unavailable')='false'`, b.o, b.w, b.e, r, owner.identity.PrincipalID.String()); n != "1" {
		t.Fatal("missing or duplicated owner audit", n)
	}
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", "")
	if request("getSecurityCaseVerification", "GET", owner, "", 200).State != "open" {
		t.Fatal("revoked fixture kept closure")
	}
}

func TestV3OwnerAcknowledgesMissingBusinessFixture(t *testing.T) {
	record := caseFixture(t)
	record.BusinessFixtureUnavailable = true
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", installTestTicketAttestations(t, record.Bundle, *record.SubmittedAt))
	v, err := verifyCase(record, record.Bundle.Scenario.Scope, ticketProofQualification)
	if err != nil || v.State != "closed_business_task_unverified" || !v.SecurityCheckPassed || v.BusinessTaskPreserved || v.BusinessReceiptID != nil {
		t.Fatalf("%+v, %v", v, err)
	}
	record.Bundle.Recorder.Healthy = false
	v, err = verifyCase(record, record.Bundle.Scenario.Scope, ticketProofQualification)
	if err != nil || v.State != "open" {
		t.Fatalf("broken security check: %+v, %v", v, err)
	}
}
