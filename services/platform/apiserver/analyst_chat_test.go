package apiserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

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
	cfg := aigateway.BedrockBinding{Provider: aigateway.ModeBedrock, Model: "anthropic.claude-haiku-4-5", Region: "us", CredentialReference: "secret_ref_planner/" + b.o + "/" + b.w + "/" + b.e + "/v1", CredentialDigest: "sha256:" + strings.Repeat("a", 64), DeploymentDigest: "sha256:" + strings.Repeat("b", 64), Cost: 20}
	h := &discoveryWorkflowSurface{evidenceDB: b.product, analyst: &analystChat{model, cfg}}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,'strong','gateway','policy','block','Gateway blocked the request',$7,now())`, b.o, b.w, b.e, event, s, agent, receipt)
		b.exec(`INSERT INTO zasp_runtime_session_summaries(organization_id,workspace_id,environment_id,id,first_event_at,last_event_at,projected_at,event_count,exact_count,strong_count,probable_count,unattributed_count,minimum_agent_id,maximum_agent_id) VALUES($1,$2,$3,$4,now(),now(),now(),1,0,1,0,0,$5,$5)`, b.o, b.w, b.e, s, agent)
	})
	path := "/api/v1/security-agents/chat/threads"
	query := "?session_id=" + s
	create := func() *httptest.ResponseRecorder {
		return b.serve(h, admin, "createAnalystThread", "POST", path+query, nil, `{"session_id":"`+s+`"}`, map[string]string{"Idempotency-Key": "analyst-thread-fixture-001"})
	}
	if out := create(); out.Code != 409 || model.calls != 0 {
		t.Fatalf("default off=%d %s", out.Code, out.Body)
	}
	b.seed(func() {
		b.exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency) VALUES($1,true,ARRAY['deterministic_only','privatelink_bedrock'],'us_only')`, b.o)
		b.exec(`INSERT INTO zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier3_provider,tier3_model_pin,tier3_security_agent_planner_enabled,allow_redacted_summaries,monthly_budget_nano_credits,credential_reference,credential_digest) VALUES($1,$2,$3,'production','privatelink_bedrock','privatelink_bedrock',$4,true,true,20,$5,$6)`, b.o, b.w, b.e, cfg.Model, cfg.CredentialReference, cfg.CredentialDigest)
		b.exec(`INSERT INTO model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,deployment_digest,evidence_digest,expires_at) VALUES($1,$2,$3,'privatelink_bedrock',$4,'security_agent_triage',true,$5,$5,now()+interval '1 hour')`, b.o, b.w, b.e, cfg.Model, cfg.DeploymentDigest)
		b.exec(`INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'*',true,'fixture') ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, b.o, b.w, b.e)
	})
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
	stream := func(k string) *httptest.ResponseRecorder {
		return b.serve(h, admin, "streamAnalystThread", "POST", path+"/"+thread.ID+"/stream"+query, params, `{"request_id":"`+k+`","message":"Which actions were blocked?"}`, nil)
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
	if limited := stream(b.id()); limited.Code != 409 || model.calls != 1 {
		t.Fatalf("budget ignored: %d", limited.Code)
	}
	b.seed(func() {
		b.exec(`UPDATE zasp_environment_ai_controls SET tier3_security_agent_planner_enabled=false WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, b.o, b.w, b.e)
	})
	disabled := b.serve(h, admin, "getAnalystThread", "GET", path+"/"+thread.ID+query, params, "", nil)
	if disabled.Code != 409 || strings.Contains(disabled.Body.String(), receipt) {
		t.Fatalf("disabled history leaked: %d", disabled.Code)
	}
	if denied := stream(k); denied.Code != 409 || model.calls != 1 {
		t.Fatalf("disabled replay=%d calls=%d", denied.Code, model.calls)
	}
}
