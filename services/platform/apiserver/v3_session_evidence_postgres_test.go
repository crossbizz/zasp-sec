package apiserver

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestV3SessionIntentInstalledReceipts(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	session, agent, credential, event, decision := b.id(), b.id(), b.id(), b.id(), b.id()
	b.seed(func() {
		b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time)
VALUES($1,$2,$3,$4,$5,$6,'strong','gateway','policy','block','Gateway request blocked',$7,now())`, b.o, b.w, b.e, event, session, agent, b.id())
		b.exec(`INSERT INTO zasp_runtime_session_summaries(organization_id,workspace_id,environment_id,id,first_event_at,last_event_at,projected_at,event_count,exact_count,strong_count,probable_count,unattributed_count,minimum_agent_id,maximum_agent_id) VALUES($1,$2,$3,$4,now(),now(),now(),1,0,1,0,0,$5,$5)`, b.o, b.w, b.e, session, agent)
		b.exec(`INSERT INTO zasp_workload_bindings(organization_id,workspace_id,environment_id,credential_id,agent_id,session_id,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()-interval '1 hour')`, b.o, b.w, b.e, credential, agent, session, admin.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_workload_actions(organization_id,workspace_id,environment_id,credential_id,action_id,principal_id,request,receipt) VALUES($1,$2,$3,$4,'draft',$5,'{"operation":"draft_reply"}',jsonb_build_object('decision_id',$6::text,'verdict','allow'))`, b.o, b.w, b.e, credential, admin.identity.PrincipalID.String(), decision)
	})
	path := "/api/v1/sessions/" + session + "/intent"
	read := func() map[string]sessionActionResult {
		out := b.serve(&discoveryWorkflowSurface{evidenceDB: b.product}, admin, "getSessionIntent", http.MethodGet, path, map[string]string{"id": session}, "", nil)
		var doc struct {
			Actions []sessionActionResult `json:"actions"`
		}
		if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &doc) != nil || len(doc.Actions) != 2 {
			t.Fatalf("read=%d %s", out.Code, out.Body)
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
	record := caseFixture(t)
	bundle := record.Bundle
	scope := &bundle.Scenario.Scope
	scope.OrganizationID, scope.WorkspaceID, scope.EnvironmentID = b.o, b.w, b.e
	bundle.Scenario.RunID, bundle.Scenario.TargetID = fixture, target
	bundle.Adapter.TicketRunBinding, bundle.Recorder.TicketRunBinding = bundle.Scenario.TicketRunBinding, bundle.Scenario.TicketRunBinding
	issued := bundle.Scenario.WindowEnd.Add(time.Minute)
	key := installTestTicketAttestations(t, bundle, issued)
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", key)
	blob, _ := json.Marshal(bundle)
	b.seed(func() {
		b.exec(`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,$4,$5,1,$6,$7,'remediated')`, b.o, b.w, b.e, r, b.id(), b.id(), owner.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_security_agent_provider_remediations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,finding_id,finding_version,integration_id,entity_id,target,parameters,remediation_role_arn,external_id_reference,input_digest,state,prior,observed,completed_at) VALUES($1,$2,$3,$4,$5,'attach_bedrock_guardrail',$6,1,$7,$8,'{}','{}','fixture','fixture',decode(repeat('ab',32),'hex'),'verified','{}','{}',$9)`, b.o, b.w, b.e, r, step, b.id(), b.id(), target, bundle.Scenario.WindowStart.Add(-time.Hour))
		b.exec(`INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value) VALUES($1,$2,$3,$4,$5)`, b.o, b.w, b.e, target, owner.identity.PrincipalID.String())
		b.exec(`INSERT INTO zasp_ticket_verification_imports(organization_id,workspace_id,environment_id,run_id,definition_version,submitted_by,bundle,submitted_at) VALUES($1,$2,$3,$4,1,$5,$6::jsonb,$7)`, b.o, b.w, b.e, fixture, owner.identity.PrincipalID.String(), string(blob), issued)
	})
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	request := func(op, method string, actor installedPrincipal, body string, status int) caseVerification {
		out := b.serve(surface, actor, op, method, "/api/v1/security-agents/cases/"+r+"/verify", map[string]string{"id": r}, body, nil)
		var doc caseVerification
		if out.Code != status || status == 200 && json.Unmarshal(out.Body.Bytes(), &doc) != nil {
			t.Fatalf("%s=%d %s", op, out.Code, out.Body)
		}
		return doc
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
	t.Setenv("ZASP_TICKET_ATTESTATION_TRUST_FILE", "")
	if request("getSecurityCaseVerification", "GET", owner, "", 200).State != "open" {
		t.Fatal("revoked fixture kept closure")
	}
}
