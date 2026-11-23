package apiserver

import (
	"encoding/json"
	"testing"
)

func TestAgentPostureSeparatesRepositoryFromAttributedUse(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	agent := b.id()
	b.seed(func() {
		b.exec("INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_provider) VALUES($1,$2,$3,$4,'agent','project','{}',now(),now(),'agent','github')", b.o, b.w, b.e, agent)
	})
	get := func(wantKind, why string) {
		r := b.serve(&discoveryWorkflowSurface{evidenceDB: b.product}, admin, "getAgentPostureSummary", "GET", "/api/v1/agents/"+agent+"/posture-summary", map[string]string{"id": agent}, "", nil)
		var received map[string]any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &received) != nil || received["deployment_kind"] != wantKind || received["deployment_evidence"] != why || received["agent_id"] != agent {
			t.Fatalf("got %d %s", r.Code, r.Body.String())
		}
	}
	get("repo_code", "repository")
	record := func(confidence string) {
		b.seed(func() {
			b.exec("INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,$7,'otlp','tool','invoke','Tool invocation',$8,now())", b.o, b.w, b.e, b.id(), b.id(), agent, confidence, b.id())
		})
	}
	record("strong")
	get("repo_code", "repository")
	record("exact")
	get("deployed_agent", "runtime_receipt")
}
