package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func sampleToolPolicy(rollout, field, value string) policy.Policy {
	return policy.Policy{ID: "policy-support", Name: "Support tool scope", Scope: "environment", Trigger: "tool",
		Conditions: []policy.Condition{{Field: field, Operator: "equals", Value: value}}, Action: policy.ActionBlock, Rollout: rollout, FailureMode: "closed"}
}

func TestWorkloadActionUsesActivePolicyEvaluator(t *testing.T) {
	identity := newGuardrailFixture(t, CredentialBearerToken).secondary.identity
	h := workloadActionHandler{newProductID: func() (string, error) { return guardrailTestDecisionID, nil }}
	for _, tc := range []struct {
		rollout, field, value, verdict string
		would, unsupported             bool
	}{
		{"enforced", "resource", "restricted", "block", false, false}, {"monitor", "resource", "restricted", "allow", true, false},
		{"enforced", "action", "ticket.read", "allow", false, false}, {"enforced", "agent_id", "unbound", "", false, true},
	} {
		t.Run(tc.rollout+"-"+tc.field, func(t *testing.T) {
			p := sampleToolPolicy(tc.rollout, tc.field, tc.value)
			body, _ := json.Marshal(p)
			action := workloadActionRequest{ActionID: "attempt", ActionKind: "tool_call", Operation: "ticket.update"}
			action.Resource.Kind = "ticket"
			action.Resource.Classification = "restricted"
			receipt, err := h.evaluate(context.Background(), identity, action, workloadAdmission{Revision: "sha256:" + strings.Repeat("a", 64), Policies: []workloadPolicy{{p.ID, 1, body}}})
			if tc.unsupported {
				if !errors.Is(err, errUnsupportedWorkloadContext) {
					t.Fatalf("unknown identity: %v", err)
				}
				return
			}
			if err != nil || receipt.Verdict != tc.verdict || receipt.WouldBlock != tc.would {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

// Exercise the actual Python dispatch path over HTTP, using issued PATs,
// request-bound SQL and a disposable installed PostgreSQL deployment.
func TestWorkloadActionOnInstalledBaselinePostgres(t *testing.T) {
	b := startInstalledV2Baseline(t)
	admin := b.member("security_admin", "investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance")
	if err := b.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(b.product)
	if err != nil {
		t.Fatal(err)
	}
	issue, tokens := installedWorkloadTokenIssuer(t, b, repository, admin)
	first := issue("First workload", `["decide_actions"]`)
	other := issue("Second workload", `["decide_actions"]`)
	readOnly := issue("Reader", `["view"]`)
	p := sampleToolPolicy("enforced", "resource", "restricted")
	body, _ := json.Marshal(p)
	b.seed(func() {
		b.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, b.o, b.w, b.e, p.ID, body)
	})
	handler := &workloadActionHandler{database: b.product, newProductID: newWorkflowProductID}
	surface := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, _ := RoutedOperationFromRequest(r)
		handler.serve(w, r, op)
	})
	route := RoutedOperation{OperationID: "createWorkloadActionDecision", PathParameters: map[string]string{}}
	if _, err := b.checked(readOnly, route); err == nil {
		t.Fatal("view credential obtained workload access")
	}
	request := `{"schema_version":"action.v1","action_id":"attempt-1","action_kind":"tool_call","operation":"ticket.update","resource":{"kind":"ticket","classification":"restricted"}}`
	decide := func(actor installedPrincipal, body string) *httptest.ResponseRecorder {
		return b.serve(surface, actor, route.OperationID, http.MethodPost, "/api/v1/runtime/action-decisions", nil, body, map[string]string{"Idempotency-Key": "attempt-1"})
	}
	one := decide(first, request)
	var receipt workloadReceipt
	if one.Code != 200 || json.Unmarshal(one.Body.Bytes(), &receipt) != nil || receipt.Verdict != "block" {
		t.Fatalf("decision %d %s", one.Code, one.Body)
	}
	replay := decide(first, request)
	if replay.Body.String() != one.Body.String() {
		t.Fatalf("replayed %s first %s", replay.Body, one.Body)
	}
	conflict := decide(first, strings.Replace(request, "restricted", "public", 1))
	if conflict.Code != 409 || !strings.Contains(conflict.Body.String(), "action_id_conflict") {
		t.Fatal(conflict.Code, conflict.Body)
	}
	out := workloadOutcome{SchemaVersion: "action-outcome.v1", ActionID: "attempt-1", DecisionID: receipt.DecisionID, Status: "not_dispatched"}
	outcome := func(actor installedPrincipal, value workloadOutcome) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		return b.serve(surface, actor, "recordWorkloadActionOutcome", http.MethodPost, "/api/v1/runtime/actions/attempt-1/outcomes", map[string]string{"actionId": "attempt-1"}, string(body), map[string]string{"Idempotency-Key": "attempt-1-outcome"})
	}
	if result := outcome(other, out); result.Code != 404 {
		t.Fatalf("other binding: %d %s", result.Code, result.Body)
	}
	if result := outcome(first, out); result.Code != 200 {
		t.Fatalf("outcome %d %s", result.Code, result.Body)
	}
	if result := outcome(first, out); result.Code != 200 {
		t.Fatalf("replay outcome %d %s", result.Code, result.Body)
	}
	out.Status = "returned"
	if result := outcome(first, out); result.Code != 409 {
		t.Fatalf("outcome conflict %d %s", result.Code, result.Body)
	}
	if result := decide(other, request); result.Code != 200 || result.Body.String() == one.Body.String() {
		t.Fatalf("second binding %d %s", result.Code, result.Body)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, authErr := repository.Authenticate(r.Context(), Credential{Kind: CredentialBearerToken, Value: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
		if authErr != nil {
			http.Error(w, "unauthenticated", 401)
			return
		}
		op := route
		if r.URL.Path != "/api/v1/runtime/action-decisions" {
			path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(path) != 6 || path[2] != "runtime" || path[3] != "actions" || path[5] != "outcomes" {
				http.NotFound(w, r)
				return
			}
			op = RoutedOperation{OperationID: "recordWorkloadActionOutcome", PathParameters: map[string]string{"actionId": path[4]}}
		}
		checked, authErr := b.checked(installedPrincipal{identity: authenticated, binding: authenticated.credentialBinding}, op)
		if authErr != nil {
			http.Error(w, "denied", 403)
			return
		}
		surface.ServeHTTP(w, r.WithContext(checked))
	}))
	defer server.Close()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 required for installed workload SDK test")
	}
	src, err := filepath.Abs("../../../sdks/python-guardrails/src")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(b.ctx, python, "-c", `
import os
from zasp_guardrails import ToolGuard, PolicyDenied
g=ToolGuard(os.environ["ACTION_TEST_ORIGIN"],os.environ["ACTION_TEST_TOKEN"],timeout=30)
writes=[]
def attempt(target):
    a=g.action("ticket.update",resource_kind="ticket",classification=target)
    try:
        a.run(writes.append, target)
    except PolicyDenied:
        assert target=="restricted"
    assert a.outcome_delivered
attempt("internal")
attempt("restricted")
assert writes==["internal"], writes

import hashlib, sqlite3, tempfile
from pathlib import Path
from zasp_guardrails.context import SQLiteContext, RecordApproval, ContextDenied
with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp)/"context.db"
    key=os.urandom(32)
    def adapter(tenant):
        return SQLiteContext(path,g,tenant=tenant,principal="reader",session="sqlite-demo",approval_key=key)
    record=RecordApproval("one","collection","doc","reader",("reader",),1,4102444800,
                          "document",hashlib.sha256(b"known value").hexdigest())
    adapter("one").put(record,record.sign(key),b"known value")
    assert adapter("one").grounded_value("collection","doc",b"known value")==b"known value"
    try:
        adapter("two").retrieve("collection","doc")
        raise AssertionError("unexpected cross-tenant retrieval")
    except ContextDenied:
        pass
    with sqlite3.connect(path) as inspector:
        print(",".join(x[0] for x in inspector.execute("SELECT action FROM context_receipts ORDER BY rowid")))
`)
	command.Env = append(os.Environ(), "PYTHONPATH="+src, "ACTION_TEST_ORIGIN="+server.URL, "ACTION_TEST_TOKEN="+tokens["First workload"])
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Python guard E2E: %v %s", err, result)
	}
	ids := strings.Split(strings.TrimSpace(string(result)), ",")
	if len(ids) != 3 {
		t.Fatalf("context adapter receipts: %s", result)
	}
	for index, actionID := range ids {
		var contextResult string
		err := b.admin.QueryRow(b.ctx, "SELECT outcome#>>'{context_evidence,result}' FROM public.zasp_workload_actions WHERE action_id=$1", actionID).Scan(&contextResult)
		expected := []string{"allowed", "allowed", "rejected"}[index]
		if err != nil || contextResult != expected {
			t.Fatalf("local receipt %d versus authenticated outcome: %v %q", index, err, contextResult)
		}
	}
}
