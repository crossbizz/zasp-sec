package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
	"net/http"
	"sort"
	"testing"
	"time"
)

func TestAgentPurposeOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	agent, tool1, tool2 := b.id(), b.id(), b.id()
	b.seed(func() {
		b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,'agent','support',jsonb_build_object('name','support'),now(),now(),'agent')`, b.o, b.w, b.e, agent)
	})
	surface := &discoveryWorkflowSurface{evidenceDB: b.product}
	params := map[string]string{"id": agent}
	path := "/api/v1/agents/" + agent + "/purpose"
	get := func() agentPurpose {
		t.Helper()
		rec := b.serve(surface, admin, "getAgentPurpose", http.MethodGet, path, params, "", nil)
		var purpose agentPurpose
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &purpose) != nil || purpose.AgentID != agent {
			t.Fatalf("read %d %s", rec.Code, rec.Body)
		}
		return purpose
	}
	if p := get(); p.Revision != 0 || p.UpdatedAt != nil || len(p.AllowedToolIDs) != 0 {
		t.Fatal(p)
	}
	put := func(key string, n int64, tools []string, want int) agentPurpose {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"allowed_tool_ids": tools})
		rec := b.serve(surface, admin, "putAgentPurpose", http.MethodPut, path, params, string(body), map[string]string{"Idempotency-Key": key, "If-Match": quoteVersion(n)})
		if rec.Code != want {
			t.Fatalf("put %d wanted %d %s", rec.Code, want, rec.Body)
		}
		var p agentPurpose
		if want == 200 && json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatal(rec.Body.String())
		}
		return p
	}
	key := b.id()
	tools := []string{tool2, tool1}
	p := put(key, 0, tools, 200)
	sort.Strings(tools)
	if p.Revision != 1 || p.AllowedToolIDs[0] != tools[0] || p.UpdatedAt == nil {
		t.Fatal(p)
	}
	if get().Revision != 1 {
		t.Fatal("purpose unavailable after save")
	}
	put(key, 0, []string{tool1}, 409)
	put(b.id(), 0, []string{tool1}, 409)
	put(b.id(), 1, []string{tool1, tool1}, 400)
	put(b.id(), 1, []string{}, 200)
	if replay := put(key, 0, tools, 200); replay.Revision != 1 {
		t.Fatal("retry observed a different revision", replay)
	}
	if get().Revision != 2 {
		t.Fatal("retry overwrote latest declaration")
	}
	if e := b.text(`SELECT count(*)::text FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=($1,$2,$3,$4)`, b.o, b.w, b.e, agent); e != "2" {
		t.Fatal(e)
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getAgentPurpose", PathParameters: params}, purposeGetSQL, b.o, b.w, b.id(), agent); installedSQLState(err) != "42501" {
		t.Fatalf("cross-Environment read %v", err)
	}
}

func TestAgentSuggestionsOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	agent, allowed, tool, other, session := b.id(), b.id(), b.id(), b.id(), b.id()
	from := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	end := from.Add(time.Hour)
	events := []platformpolicy.ActionContext{}
	b.seed(func() {
		for _, id := range []string{agent, allowed, tool, other} {
			kind := "tool"
			if id == agent {
				kind = "agent"
			}
			b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,$5,'registered',jsonb_build_object('name','registered'),now(),now(),$5)`, b.o, b.w, b.e, id, kind)
		}
		for _, x := range []struct{ tool, confidence string }{{tool, "exact"}, {allowed, "exact"}, {other, "strong"}} {
			event := b.id()
			b.exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,$7,'otlp','tool','invoke','Tool invocation',$8,$9)`, b.o, b.w, b.e, event, session, agent, x.confidence, b.id(), from.Add(10*time.Minute))
			events = append(events, platformpolicy.ActionContext{AgentID: agent, SessionID: session, EnvironmentID: b.e, Action: "tool", EventID: event, ToolID: x.tool, Resource: x.tool})
		}
	})
	events = append(events, events[0], platformpolicy.ActionContext{AgentID: agent, SessionID: session, EnvironmentID: b.e, Action: "tool", EventID: b.id(), Resource: other})
	allow := fmt.Sprintf(`{"allowed_tool_ids":[%q]}`, allowed)
	purpose := &discoveryWorkflowSurface{evidenceDB: b.product}
	params := map[string]string{"id": agent}
	url := "/api/v1/agents/" + agent
	if rec := b.serve(purpose, admin, "putAgentPurpose", "PUT", url+"/purpose", params, allow, map[string]string{"If-Match": quoteVersion(0), "Idempotency-Key": b.id()}); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	history := &replayHistoryStub{policyActionHistoryStub: policyActionHistoryStub{events: events}, truncated: true}
	handler := &PolicyPublicHTTPHandler{config: PolicyPublicHTTPConfig{History: history, EvidenceDB: b.product}}
	type page struct {
		Revision int `json:"purpose_revision"`
		Items    []struct {
			ID       string   `json:"tool_id"`
			Policy   string   `json:"policy_id"`
			Audit    string   `json:"draft_audit_id"`
			State    string   `json:"state"`
			Evidence []string `json:"evidence_ids"`
		} `json:"items"`
		Scan *struct {
			Examined, Eligible int
			Truncated          bool
		} `json:"last_scan"`
	}
	call := func(op, method, path, body string, want int) page {
		t.Helper()
		rec := b.serve(handler, admin, op, method, url+"/suggestions"+path, params, body, nil)
		if rec.Code != want {
			t.Fatalf("%s wanted %d got %d %s", op, want, rec.Code, rec.Body.String())
		}
		var p page
		if want == 200 && json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatal(rec.Body)
		}
		return p
	}
	list := func() page { return call("listAgentSuggestions", "GET", "", "", 200) }
	if p := list(); p.Revision != 1 || p.Scan != nil || len(p.Items) != 0 {
		t.Fatal(p)
	}
	scan := fmt.Sprintf(`{"purpose_revision":1,"from":%q,"to":%q}`, from.Format(time.RFC3339), end.Format(time.RFC3339))
	p := call("refreshAgentSuggestions", "POST", "/refresh", scan, 200)
	if p.Scan == nil || p.Scan.Eligible != 2 || p.Scan.Examined != 5 || !p.Scan.Truncated || len(p.Items) != 1 || p.Items[0].ID != tool || len(p.Items[0].Evidence) != 1 || p.Items[0].State != "suggested" {
		t.Fatalf("unexpected review %#v", p)
	}
	params["toolId"] = tool
	decision := `{"purpose_revision":1,"decision":"request_draft"}`
	path := "/" + tool + "/decision"
	call("reviewAgentSuggestion", "PUT", path, decision, 200)
	call("reviewAgentSuggestion", "PUT", path, decision, 200)
	if p := list(); p.Items[0].State != "draft_requested" {
		t.Fatal("review not retained", p)
	}
	call("reviewAgentSuggestion", "PUT", path, `{"purpose_revision":1,"decision":"dismiss"}`, 409)
	// A real current product mutation creates the inactive policy and audit receipt.
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := newWorkflowHTTPHandler(repo, bytes.Repeat([]byte{1}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// The application middleware issues a distinct correlation ID for every request.
	workflowWithCorrelation := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workflow.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), correlationContextKey{}, b.id())))
	})
	policyBody, _ := json.Marshal(map[string]any{"id": p.Items[0].Policy, "name": "Restrict tool", "scope": "environment", "trigger": "tool", "conditions": []map[string]string{{"field": "agent_id", "operator": "equals", "value": agent}, {"field": "resource", "operator": "equals", "value": tool}}, "action": "block", "rollout": "draft", "failure_mode": "open"})
	out := b.serve(workflowWithCorrelation, admin, "createPolicy", "POST", "/api/v1/policies", nil, string(policyBody), map[string]string{"Idempotency-Key": b.id()})
	if out.Code != 201 && out.Code != 200 {
		t.Fatal("create draft", out.Code, out.Body.String())
	}
	if p := list(); p.Items[0].State != "draft_linked" || p.Items[0].Audit != out.Header().Get("X-Audit-ID") || !validProductID(p.Items[0].Audit) {
		t.Fatal("receipt link not recognized", p)
	}
	// Promote and reverse the same reviewed draft through the current workflow writer.
	policyID := p.Items[0].Policy
	policyParams := map[string]string{"id": policyID}
	roll := func(state string, version int64, key string, want int) {
		t.Helper()
		receipt := b.serve(workflowWithCorrelation, admin, "rolloutPolicy", "POST", "/api/v1/policies/"+policyID+"/rollout", policyParams, fmt.Sprintf(`{"state":%q,"target_id":%q}`, state, b.e), map[string]string{"Idempotency-Key": key, "If-Match": quoteVersion(version)})
		if receipt.Code != want {
			t.Fatalf("rollout %s r%d: %d %s", state, version, receipt.Code, receipt.Body.String())
		}
		if want == 200 && receipt.Header().Get("ETag") != quoteVersion(version+1) {
			t.Fatal("unexpected rollout version", receipt.Header(), receipt.Body.String())
		}
	}
	roll("enforced", 1, b.id(), 409)
	roll("monitor", 1, b.id(), 200)
	roll("enforced", 2, b.id(), 200)
	roll("monitor", 2, b.id(), 409)
	rollbackKey := b.id()
	roll("monitor", 3, rollbackKey, 200)
	roll("monitor", 3, rollbackKey, 200)
	if state := b.text(`SELECT body->>'rollout' FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id,version)=($1,$2,$3,'policy',$4,4)`, b.o, b.w, b.e, policyID); state != "monitor" {
		t.Fatal("actual persisted rollout", state)
	}
	if count := b.text(`SELECT count(*)::text FROM public.zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,resource_kind,resource_id,operation)=($1,$2,$3,'policy',$4,'rolloutPolicy') AND resource_version IN(2,3,4)`, b.o, b.w, b.e, policyID); count != "3" {
		t.Fatal("audited transitions", count)
	}
	roll("enforced", 4, b.id(), 200)
	// An edit while enforced has a different history. A mode rollback must never
	// present that new definition as the previously monitored configuration.
	var edited map[string]any
	if err := json.Unmarshal(policyBody, &edited); err != nil {
		t.Fatal(err)
	}
	edited["name"] = "Updated after enforcement"
	edited["rollout"] = "enforced"
	newBody, _ := json.Marshal(edited)
	updated := b.serve(workflowWithCorrelation, admin, "updatePolicy", "PATCH", "/api/v1/policies/"+policyID, policyParams, string(newBody), map[string]string{"Idempotency-Key": b.id(), "If-Match": quoteVersion(5)})
	if updated.Code != 200 {
		t.Fatal("policy edit", updated.Code, updated.Body.String())
	}
	roll("monitor", 6, b.id(), 409)
	call("refreshAgentSuggestions", "POST", "/refresh", scan, 200)
	if p := list(); p.Items[0].State != "draft_linked" {
		t.Fatal("refresh erased review", p)
	}
	if rec := b.serve(purpose, admin, "putAgentPurpose", "PUT", url+"/purpose", map[string]string{"id": agent}, allow, map[string]string{"If-Match": quoteVersion(1), "Idempotency-Key": b.id()}); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	p = list()
	if p.Revision != 2 || p.Scan != nil || len(p.Items) != 0 {
		t.Fatal(p)
	}
	call("reviewAgentSuggestion", "PUT", path, decision, 409)
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "listAgentSuggestions", PathParameters: params}, suggestionListSQL, b.o, b.w, b.id(), agent, ""); installedSQLState(err) != "42501" {
		t.Fatal("cross-Environment list", err)
	}
}
