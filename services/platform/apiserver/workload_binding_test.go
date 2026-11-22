package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/hostedgateway"
)

func TestWorkloadBindingAndHostedEvidenceOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, _ := installedWorkloadTokenIssuer(t, b, repository, admin)
	first := issue("Scoped workload", "[\"use_gateway\",\"decide_actions\"]")
	unbound := issue("Legacy gateway", "[\"use_gateway\"]")
	reader := issue("Reader token", "[\"view\"]")
	agent := b.id()
	secondAgent := b.id()
	b.seed(func() {
		for _, id := range []string{agent, secondAgent} {
			b.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind)
VALUES($1,$2,$3,$4,'agent','scoped-agent',jsonb_build_object('name','scoped-agent'),now(),now(),'agent')`, b.o, b.w, b.e, id)
		}
	})
	handler := &workloadActionHandler{database: b.product, newProductID: newWorkflowProductID}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		handler.binding(w, r, op)
	})
	bind := func(token installedPrincipal, id string) *httptest.ResponseRecorder {
		return b.serve(surface, admin, "bindWorkloadCredential", http.MethodPut, "/api/v1/runtime/workload-bindings/"+token.binding.ID, map[string]string{"id": token.binding.ID}, `{"agent_id":"`+id+`"}`, nil)
	}
	if r := bind(reader, agent); r.Code != 404 {
		t.Fatalf("human token bound: %d %s", r.Code, r.Body)
	}
	if r := bind(first, b.id()); r.Code != 404 {
		t.Fatalf("unknown agent bound: %d %s", r.Code, r.Body)
	}
	bound := bind(first, agent)
	var binding workloadBinding
	if bound.Code != 200 || json.Unmarshal(bound.Body.Bytes(), &binding) != nil || binding.Agent != agent || binding.Credential != first.binding.ID || binding.Session == "" {
		t.Fatalf("binding: %d %s", bound.Code, bound.Body)
	}
	if again := bind(first, agent); again.Body.String() != bound.Body.String() {
		t.Fatalf("binding replay: %s", again.Body)
	}
	if incompatible := bind(first, secondAgent); incompatible.Code != 409 {
		t.Fatalf("rebound: %d %s", incompatible.Code, incompatible.Body)
	}
	read := b.serve(surface, admin, "getWorkloadCredentialBinding", http.MethodGet, "/api/v1/runtime/workload-bindings/"+first.binding.ID, map[string]string{"id": first.binding.ID}, "", nil)
	if read.Body.String() != bound.Body.String() {
		t.Fatalf("binding read %d %s", read.Code, read.Body)
	}
	if _, err := b.checked(first, RoutedOperation{OperationID: "getWorkloadCredentialBinding", PathParameters: map[string]string{"id": first.binding.ID}}); err == nil {
		t.Fatal("workload token read admin binding")
	}
	writeGateway := func(workload installedPrincipal, claimed string) {
		route := RoutedOperation{OperationID: "createGatewayChatCompletion", PathParameters: map[string]string{}}
		ctx, err := b.checked(workload, route)
		if err != nil {
			t.Fatal(err)
		}
		store := gatewayRequestStore{handler: &hostedGatewayHandler{database: b.product, newProductID: newWorkflowProductID}, identity: workload.identity, route: route, issued: time.Now()}
		record := hostedgateway.Record{Surface: "llm", Operation: "chat.completions", Direction: "request", Decision: "allow", Reason: "none", Bytes: 1, Digest: "sha256:" + strings.Repeat("a", 64), AgentID: claimed, Provider: "openai", Model: "fixture"}
		if err := store.Record(ctx, "", []hostedgateway.Record{record}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// An untrusted header may name a different valid inventory agent.
	installedWorkloadContainment(t, b, handler, admin, first, binding, issue)
	writeGateway(first, secondAgent)
	writeGateway(unbound, secondAgent)
	scheduler := b.login("zasp_svc_scheduler")
	var maintained json.RawMessage
	if err := scheduler.QueryRow(b.ctx, `SELECT zasp_gateway_maintain(90,100)`).Scan(&maintained); err != nil {
		t.Fatal(err)
	}
	sql := `SELECT count(*)::text FROM zasp_runtime_session_events WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND agent_id=$4 AND confidence=$5 AND source='gateway'`
	if exact := b.text(sql+` AND session_id=$6`, b.o, b.w, b.e, agent, "exact", binding.Session); exact != "1" {
		t.Fatal("missing exact agent/session event", exact, string(maintained))
	}
	if legacy := b.text(sql, b.o, b.w, b.e, secondAgent, "strong"); legacy != "1" {
		t.Fatal("legacy attribution changed", legacy)
	}

	p := sampleToolPolicy("enforced", "session_id", binding.Session)
	body, _ := json.Marshal(p)
	b.seed(func() {
		b.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, b.o, b.w, b.e, p.ID, body)
	})
	action := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		handler.serve(w, r, op)
	})
	response := b.serve(action, first, "createWorkloadActionDecision", http.MethodPost, "/api/v1/runtime/action-decisions", nil, `{"schema_version":"action.v1","action_id":"bound-attempt","action_kind":"tool_call","source_session_ref":"different","operation":"ticket.update","resource":{"kind":"ticket","classification":"internal"}}`, map[string]string{"Idempotency-Key": "bound-attempt"})
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"verdict":"block"`) {
		t.Fatal("untrusted session overrode bound scope", response.Code, response.Body)
	}
}
