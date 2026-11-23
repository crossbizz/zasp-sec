package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	claim := func() []byte {
		t.Helper()
		var raw []byte
		if err := scheduler.QueryRow(b.ctx, `SELECT public.zasp_claim_qualified_intent('mistralai/Shieldstral-1.0-3B','eu',1,('sha256:'||repeat('3',64)))`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if raw := claim(); string(raw) != "null" {
		t.Fatalf("unconsented activity reached classifier: %s", raw)
	}
	optIn := strings.Replace(settings, "{", `{"classifier_opt_in":true,`, 1)
	write := func(key, rev, value string) {
		t.Helper()
		r := b.serve(surface, admin, "putAgentActionAnalysis", "PUT", path, params, value, map[string]string{"Idempotency-Key": key, "If-Match": rev})
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
	}
	write("intent-declaration-0001", `"2"`, optIn)
	id := submit(work, "private.operation", "tenant.confidential", "external")
	run()
	if raw := claim(); string(raw) != "null" {
		t.Fatal("per-agent consent exceeded environment policy")
	}
	b.seed(func() {
		b.exec(`INSERT INTO public.zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,false) ON CONFLICT DO NOTHING`, b.o, b.w, b.e)
		b.exec(`INSERT INTO public.zasp_organization_ai_controls(organization_id,ai_enabled,allowed_modes,allowed_residency) VALUES($1,true,ARRAY['deterministic_only','zasp_vpc_slm'],'eu_only')`, b.o)
		b.exec(`INSERT INTO public.zasp_environment_ai_controls(organization_id,workspace_id,environment_id,environment_class,mode,tier2_profile,tier2_purpose_drift_enabled,allow_redacted_summaries,monthly_budget_nano_credits)
SELECT organization_id,workspace_id,environment_id,environment_class,'zasp_vpc_slm','mistralai/Shieldstral-1.0-3B',true,true,2 FROM public.zasp_data_controls WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, b.o, b.w, b.e)
	})
	if raw := claim(); string(raw) != "null" {
		t.Fatal("unqualified model admitted")
	}
	b.seed(func() {
		b.exec(`INSERT INTO public.model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose,qualified,evidence_digest,deployment_digest,expires_at) VALUES($1,$2,$3,'zasp_vpc_slm','mistralai/Shieldstral-1.0-3B','purpose_alignment_check',true,'sha256:'||repeat('2',64),'sha256:'||repeat('3',64),now()+interval '1 day')`, b.o, b.w, b.e)
	})
	var retired string
	if err := scheduler.QueryRow(b.ctx, `SELECT public.zasp_claim_intent_draft()::text`).Scan(&retired); err != nil || retired != "null" {
		t.Fatal("legacy public router received a claim", retired, err)
	}
	raw := claim()
	var job struct {
		Lease    string
		Features map[string]any
	}
	if json.Unmarshal(raw, &job) != nil || job.Lease == "" || len(job.Features) != 6 || job.Features["destination"] != "external" || job.Features["operation_mismatch"] != true || strings.Contains(string(raw), "private.operation") || strings.Contains(string(raw), "tenant.confidential") || strings.Contains(string(raw), b.o) || strings.Contains(string(raw), id) {
		t.Fatalf("unexpected classifier features %s", raw)
	}
	if next := claim(); string(next) != "null" {
		t.Fatalf("leased work delivered twice %s", next)
	}
	finish := func(lease, code string) bool {
		t.Helper()
		var saved bool
		if err := scheduler.QueryRow(b.ctx, `SELECT public.zasp_finish_intent_draft($1::text::uuid,$2)`, lease, code).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		return saved
	}
	if !finish(job.Lease, "review_destination") || finish(job.Lease, "review_purpose") {
		t.Fatal("lease allowed duplicate settlement")
	}
	r := read()
	if !strings.Contains(r.Body.String(), `"intent_drafts"`) || !strings.Contains(r.Body.String(), `"review_destination"`) || !strings.Contains(r.Body.String(), id) {
		t.Fatal("draft not visible", r.Body)
	}
	t.Setenv("ZASP_INTENT_CLASSIFIER_ENABLED", "true")
	flowHandler := &identityHTTPHandler{administration: repo}
	flow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := flowHandler.externalIntentFlow(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(v)
	})
	flowGet := func() string {
		t.Helper()
		out := b.serve(flow, admin, "getExternalDataFlows", "GET", "/api/v1/settings/external-data-flows", nil, "", nil)
		if out.Code != 200 {
			t.Fatal(out.Code, out.Body)
		}
		return out.Body.String()
	}
	if value := flowGet(); !strings.Contains(value, `"health": "healthy"`) && !strings.Contains(value, `"health":"healthy"`) {
		t.Fatal(value)
	}
	submit(work, "private.operation", "tenant.confidential", "external")
	run()
	if err := json.Unmarshal(claim(), &job); err != nil || job.Lease == "" {
		t.Fatal(err)
	}
	write("intent-declaration-0002", `"3"`, settings)
	if finish(job.Lease, "review_purpose") || !strings.Contains(read().Body.String(), `"intent_drafts": []`) && !strings.Contains(read().Body.String(), `"intent_drafts":[]`) {
		t.Fatal("obsolete draft crossed consent revision")
	}
	if value := flowGet(); !strings.Contains(value, "disabled") {
		t.Fatal(value)
	}
	if _, err := b.fenced("zasp_svc_api", admin, RoutedOperation{OperationID: "getExternalDataFlows"}, intentFlowSQL, b.o, b.w, b.id()); installedSQLState(err) != "42501" {
		t.Fatalf("cross-environment classifier flow: %v", err)
	}

}

func TestClassifierOptInIsExplicit(t *testing.T) {
	for _, value := range []string{"null", "0", `"true"`} {
		var cfg analysisSettings
		if json.Unmarshal([]byte(`{"classifier_opt_in":`+value+`}`), &cfg) == nil {
			t.Fatal("accepted invalid consent", value)
		}
	}
	var cfg analysisSettings
	if err := json.Unmarshal([]byte(`{"classifier_opt_in":true}`), &cfg); err != nil || !cfg.ClassifierOptIn {
		t.Fatal(cfg, err)
	}
}
