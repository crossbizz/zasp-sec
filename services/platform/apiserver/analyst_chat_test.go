package apiserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

type testAnalystModel struct {
	id    string
	calls int
}

func (d *testAnalystModel) Evaluate(_ context.Context, _ aigateway.Purpose, input json.RawMessage) (json.RawMessage, error) {
	d.calls++
	return json.Marshal(map[string]any{"summary": "The gateway blocked the recorded request.", "evidence_ids": []string{d.id}})
}

func TestV3AnalystChatScopedPrivateInvestigation(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	other := b.member("security_engineer", "investigate_sessions", "manage_findings", "manage_workflows", "run_tests", "view")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	s, event, agent, receipt := b.id(), b.id(), b.id(), b.id()
	model := &testAnalystModel{id: receipt}
	cfg := aigateway.BedrockBinding{Provider: aigateway.ModeBedrock, Model: "anthropic.claude-sonnet-4-6", Region: "us", CredentialReference: "secret_ref_planner/" + b.o + "/" + b.w + "/" + b.e + "/v1", CredentialDigest: "sha256:" + strings.Repeat("a", 64), DeploymentDigest: "sha256:" + strings.Repeat("b", 64), Cost: 20}
	h := &discoveryWorkflowSurface{evidenceDB: b.product, analyst: &analystChat{driver: model, binding: cfg}}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,'strong','gateway','policy','block','Gateway blocked the request',$7,now())`, b.o, b.w, b.e, event, s, agent, receipt)
		b.exec(`INSERT INTO zasp_runtime_session_summaries(organization_id,workspace_id,environment_id,id,first_event_at,last_event_at,projected_at,event_count,exact_count,strong_count,probable_count,unattributed_count,minimum_agent_id,maximum_agent_id) VALUES($1,$2,$3,$4,now(),now(),now(),1,0,1,0,0,$5,$5)`, b.o, b.w, b.e, s, agent)
	})
	path := "/api/v1/security-agents/chat/threads"
	query := "?session_id=" + s
	threadInput := `{"session_id":"` + s + `"}`
	create := func() *httptest.ResponseRecorder {
		return b.serve(h, admin, "createAnalystThread", "POST", path+query, nil, threadInput, map[string]string{"Idempotency-Key": "analyst-thread-fixture-001"})
	}
	if out := create(); out.Code != 409 || model.calls != 0 {
		t.Fatalf("default off=%d %s", out.Code, out.Body)
	}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'security_agent_triage',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
		b.exec(`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,'fixture') ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, b.o, b.w, b.e)
	})
	settingsOwner := b.member("organization_admin", "manage_data_controls", "manage_identity", "view", "view_compliance")
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	settings := &identityHTTPHandler{administration: repo, now: time.Now}
	control := func(op, path, method, body, match string) {
		t.Helper()
		r := b.serve(settings, settingsOwner, op, method, path, nil, body, map[string]string{"If-Match": match})
		if r.Code != 200 {
			t.Fatalf("%s returned %d: %s", op, r.Code, r.Body)
		}
	}
	orgControls, envControls := "/api/v1/organization/ai-controls", "/api/v1/settings/ai-controls"
	control("getOrganizationAIControls", orgControls, "GET", "", "")
	control("getEnvironmentAIControls", envControls, "GET", "", "")
	control("updateOrganizationAIControls", orgControls, "PATCH", `{"ai_enabled":true,"allowed_modes":["deterministic_only","privatelink_bedrock"],"allowed_residency":"us_only"}`, `"1"`)
	enable, _ := json.Marshal(map[string]any{"mode": cfg.Provider, "tier3_provider": cfg.Provider, "tier3_model_pin": cfg.Model, "tier3_security_agent_planner_enabled": true, "allow_redacted_summaries": true, "monthly_budget_nano_credits": 25, "credential_reference": cfg.CredentialReference, "credential_digest": cfg.CredentialDigest})
	control("updateEnvironmentAIControls", envControls, "PATCH", string(enable), `"1"`)
	workflow := studioDefinition{ApprovalTools: []string{"inspect_session"}, MinimumConfidence: "strong", Name: "Session containment review", Mission: "Review recorded session activity", Trigger: "manual", Tools: []string{"inspect_session"}, Proposal: "request_containment", Approval: true, Steps: 3, Budget: 25, Model: cfg.Model}
	save, _ := json.Marshal(workflow)
	saved := b.serve(h, admin, "createCustomSecurityAgent", "POST", "/api/v1/security-agents/custom", nil, string(save), map[string]string{"Idempotency-Key": b.id()})
	var definition struct {
		ID       string `json:"id"`
		Revision int    `json:"revision"`
	}
	if saved.Code != 200 || json.Unmarshal(saved.Body.Bytes(), &definition) != nil || !validProductID(definition.ID) || definition.Revision != 1 {
		t.Fatalf("studio=%d %s", saved.Code, saved.Body)
	}
	threadInput = `{"session_id":"` + s + `","studio_id":"` + definition.ID + `","studio_revision":1}`
	out := create()
	var thread analystThread
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &thread) != nil {
		t.Fatalf("thread=%d %s", out.Code, out.Body)
	}
	if replay := create(); replay.Code != 200 || replay.Body.String() != out.Body.String() {
		t.Fatal("thread replay changed")
	}
	params := map[string]string{"id": thread.ID}
	if foreign := b.serve(h, other, "getAnalystThread", "GET", path+"/"+thread.ID+query, params, "", nil); foreign.Code != 404 {
		t.Fatal("foreign thread disclosed", foreign.Code)
	}
	k := b.id()
	unapproved := b.serve(h, admin, "streamAnalystThread", "POST", path+"/"+thread.ID+"/stream"+query, params, `{"request_id":"`+k+`","message":"Review the session"}`, nil)
	if unapproved.Code != 409 || !strings.Contains(unapproved.Body.String(), "tool_approval_required") || model.calls != 0 {
		t.Fatalf("approval bypass %d %s", unapproved.Code, unapproved.Body)
	}
	stream := func(k string) *httptest.ResponseRecorder {
		return b.serve(h, admin, "streamAnalystThread", "POST", path+"/"+thread.ID+"/stream"+query, params, `{"request_id":"`+k+`","message":"Which actions were blocked?","approved_read_tools":["inspect_session"]}`, nil)
	}
	exactProfile := workflow
	exactProfile.MinimumConfidence = "exact"
	exactBody, _ := json.Marshal(exactProfile)
	exactSave := b.serve(h, admin, "createCustomSecurityAgent", "POST", "/api/v1/security-agents/custom", nil, string(exactBody), map[string]string{"Idempotency-Key": b.id()})
	var otherDef struct {
		ID string `json:"id"`
	}
	if exactSave.Code != 200 || json.Unmarshal(exactSave.Body.Bytes(), &otherDef) != nil || !validProductID(otherDef.ID) {
		t.Fatalf("exact-only definition: %d %s", exactSave.Code, exactSave.Body)
	}
	createExact := b.serve(h, admin, "createAnalystThread", "POST", path+query, nil, `{"session_id":"`+s+`","studio_id":"`+otherDef.ID+`","studio_revision":1}`, map[string]string{"Idempotency-Key": b.id()})
	var exactThread analystThread
	if createExact.Code != 200 || json.Unmarshal(createExact.Body.Bytes(), &exactThread) != nil {
		t.Fatalf("exact-only thread: %d %s", createExact.Code, createExact.Body)
	}
	insufficient := b.serve(h, admin, "streamAnalystThread", "POST", path+"/"+exactThread.ID+"/stream"+query, map[string]string{"id": exactThread.ID}, `{"request_id":"`+b.id()+`","message":"Review","approved_read_tools":["inspect_session"]}`, nil)
	if insufficient.Code != 409 || !strings.Contains(insufficient.Body.String(), "session_evidence_missing") || model.calls != 0 {
		t.Fatalf("weak evidence escaped filter: %d %s", insufficient.Code, insufficient.Body)
	}
	first := stream(k)
	if first.Code != 200 || !strings.Contains(first.Body.String(), "[DONE]") || !strings.Contains(first.Body.String(), receipt) {
		t.Fatalf("stream=%d %s", first.Code, first.Body)
	}
	if replay := stream(k); replay.Code != 200 || replay.Body.String() != first.Body.String() || model.calls != 1 {
		t.Fatalf("replayed model: %d %s", model.calls, replay.Body)
	}
	history := b.serve(h, admin, "getAnalystThread", "GET", path+"/"+thread.ID+query, params, "", nil)
	var persisted analystThread
	if history.Code != 200 || json.Unmarshal(history.Body.Bytes(), &persisted) != nil || len(persisted.Messages) != 2 || persisted.Messages[0].Role != "user" || persisted.Messages[0].ID != k || persisted.Messages[1].Role != "assistant" || len(persisted.Messages[1].EvidenceIDs) != 1 || persisted.Messages[1].EvidenceIDs[0] != receipt {
		t.Fatalf("missing scoped message history: %d %s", history.Code, history.Body)
	}
	if !persisted.RequiresReadApproval {
		t.Fatal("required per-question approval missing from history")
	}
	if persisted.Handoff == nil || persisted.Handoff.StudioID != definition.ID || persisted.Handoff.Proposal != "request_containment" || persisted.Handoff.MessageID != persisted.Messages[1].ID {
		t.Fatalf("unbound handoff %+v", persisted.Handoff)
	}
	if limited := stream(b.id()); limited.Code != 409 || model.calls != 1 {
		t.Fatalf("budget ignored: %d", limited.Code)
	}
	control("updateEnvironmentAIControls", envControls, "PATCH", `{"monthly_budget_nano_credits":30}`, `"2"`)
	exerciseStudioAdvisory(t, b, h, admin, cfg, thread, *persisted.Handoff)
	workflow.Proposal = "none"
	save, _ = json.Marshal(workflow)
	updated := b.serve(h, admin, "updateCustomSecurityAgent", "PUT", "/api/v1/security-agents/custom/"+definition.ID, map[string]string{"id": definition.ID}, string(save), map[string]string{"Idempotency-Key": b.id(), "If-Match": `"1"`})
	if updated.Code != 200 {
		t.Fatalf("revision=%d %s", updated.Code, updated.Body)
	}
	history = b.serve(h, admin, "getAnalystThread", "GET", path+"/"+thread.ID+query, params, "", nil)
	if history.Code != 200 || strings.Contains(history.Body.String(), `"handoff"`) {
		t.Fatalf("superseded proposal survived: %d %s", history.Code, history.Body)
	}
	control("updateEnvironmentAIControls", envControls, "PATCH", `{"tier3_security_agent_planner_enabled":false}`, `"3"`)
	disabled := b.serve(h, admin, "getAnalystThread", "GET", path+"/"+thread.ID+query, params, "", nil)
	if disabled.Code != 409 || strings.Contains(disabled.Body.String(), receipt) {
		t.Fatalf("disabled history leaked: %d", disabled.Code)
	}
	if denied := stream(k); denied.Code != 409 || model.calls != 1 {
		t.Fatalf("disabled replay=%d calls=%d", denied.Code, model.calls)
	}
	control("updateEnvironmentAIControls", envControls, "PATCH", `{"tier3_security_agent_planner_enabled":true,"monthly_budget_nano_credits":1000}`, `"4"`)
	exerciseStudioInventoryTurn(t, b, h, admin, s, event, agent)
}
