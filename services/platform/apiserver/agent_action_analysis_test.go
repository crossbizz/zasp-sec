package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentActionAnalysisOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := installedWorkloadTokenIssuer(t, b, repo, admin)
	work := issue("Analysis workload", `["decide_actions"]`)
	neighbour := issue("Unbound workload", `["decide_actions"]`)
	a := b.id()
	b.seed(func() {
		b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind) VALUES($1,$2,$3,$4,'agent','analysis',jsonb_build_object('name','analysis'),now(),now(),'agent')`, b.o, b.w, b.e, a)
	})
	h := &workloadActionHandler{database: b.product, newProductID: newWorkflowProductID}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		switch op.OperationID {
		case "bindWorkloadCredential":
			h.binding(w, r, op)
		case "createWorkloadActionDecision":
			h.serve(w, r, op)
		default:
			serveActionAnalysis(b.product, w, r, op)
		}
	})
	path := "/api/v1/agents/" + a + "/action-analysis"
	params := map[string]string{"id": a}
	const settings = `{"allowed_operations":["ticket.read"],"allowed_classifications":["internal"],"allowed_destinations":["internal"],"blocked_transitions":[{"from":"ticket.read","to":"ticket.post"}]}`
	change := func(key, match string) *httptest.ResponseRecorder {
		return b.serve(surface, admin, "putAgentActionAnalysis", "PUT", path, params, settings, map[string]string{"Idempotency-Key": key, "If-Match": match})
	}
	read := func() *httptest.ResponseRecorder {
		return b.serve(surface, admin, "getAgentActionAnalysis", "GET", path, params, "", nil)
	}
	if r := change("analysis-fixture-0001", `"0"`); r.Code != 200 {
		t.Fatal("declare purpose", r.Code, r.Body)
	}
	if r := change("analysis-fixture-0001", `"0"`); r.Code != 200 {
		t.Fatal("replay purpose", r.Code, r.Body)
	}
	if r := change("analysis-fixture-0002", `"0"`); r.Code != 409 {
		t.Fatal("stale purpose", r.Code, r.Body)
	}
	bind := b.serve(surface, admin, "bindWorkloadCredential", "PUT", "/api/v1/runtime/workload-bindings/"+work.binding.ID, map[string]string{"id": work.binding.ID}, `{"agent_id":"`+a+`"}`, nil)
	if bind.Code != 200 {
		t.Fatal("bind", bind.Code, bind.Body)
	}
	submit := func(principal installedPrincipal, operation, classification, destination string) string {
		id := b.id()
		resource := map[string]string{"kind": "ticket", "classification": classification}
		if destination != "" {
			resource["destination_class"] = destination
		}
		raw, _ := json.Marshal(map[string]any{"schema_version": "action.v1", "action_id": id, "action_kind": "tool_call", "operation": operation, "resource": resource})
		resp := b.serve(surface, principal, "createWorkloadActionDecision", "POST", "/api/v1/runtime/action-decisions", nil, string(raw), map[string]string{"Idempotency-Key": id})
		var receipt workloadReceipt
		if resp.Code != 200 || json.Unmarshal(resp.Body.Bytes(), &receipt) != nil {
			t.Fatal("action", resp.Code, resp.Body)
		}
		if receipt.Verdict != "allow" {
			t.Fatal("advisory changed admission", receipt)
		}
		return receipt.DecisionID
	}
	submit(work, "ticket.read", "internal", "")
	want := submit(work, "ticket.post", "restricted", "external")
	submit(neighbour, "ticket.post", "restricted", "public")
	type view struct {
		Revision int `json:"revision"`
		Pending  int `json:"pending"`
		Analyzed int `json:"analyzed"`
		Unknown  int `json:"unknown_destination"`
		Findings []struct {
			Decision string   `json:"decision_id"`
			Issues   []string `json:"issues"`
			Previous string   `json:"previous_operation"`
		} `json:"findings"`
	}
	get := func() view {
		t.Helper()
		var v view
		r := read()
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil {
			t.Fatal("read", r.Code, r.Body)
		}
		return v
	}
	if v := get(); v.Pending != 2 || v.Analyzed != 0 {
		t.Fatal("asynchronous admission", v)
	}
	scheduler := b.login("zasp_svc_scheduler")
	run := func() int {
		t.Helper()
		var n int
		if err := scheduler.QueryRow(b.ctx, `SELECT zasp_analyze_bound_actions(10)`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := run(); n != 2 {
		t.Fatal("worker", n)
	}
	if n := run(); n != 0 {
		t.Fatal("replayed worker", n)
	}
	if v := get(); v.Unknown != 1 || v.Pending != 0 || len(v.Findings) != 1 || v.Findings[0].Decision != want || v.Findings[0].Previous != "ticket.read" || len(v.Findings[0].Issues) != 4 {
		t.Fatal("incorrect findings", v)
	}
	if r := change("analysis-fixture-0002", `"1"`); r.Code != 200 {
		t.Fatal("revise", r.Code, r.Body)
	}
	submit(work, "ticket.post", "internal", "internal")
	run()
	if v := get(); v.Revision != 2 || v.Analyzed != 1 || len(v.Findings) != 1 || v.Findings[0].Previous != "" || len(v.Findings[0].Issues) != 1 {
		t.Fatal("revision isolation", v)
	}
}
