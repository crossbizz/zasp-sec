package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestPolicyPublicHandlerSimulatesBoundedScopedHistoryAndListsDecisions(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	policyID := "policy-runtime-history"
	workflow := &workflowRepositoryStub{value: WorkflowValue{Version: 3, Body: json.RawMessage(`{"id":"policy-runtime-history","name":"Runtime history","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"invoke"}],"action":"block","rollout":"monitor","failure_mode":"closed"}`)}}
	history := &policyActionHistoryStub{events: []platformpolicy.ActionContext{{PrincipalID: "pid_70000001-0000-4000-8000-000000000001", AgentID: "pid_70000001-0000-4000-8000-000000000001", SessionID: "pid_70000002-0000-4000-8000-000000000002", Action: "tool", Resource: "shell", EnvironmentID: identity.Scope.EnvironmentID().String(), Metadata: map[string]string{"action": "invoke", "resource": "shell", "principal_id": "pid_70000001-0000-4000-8000-000000000001", "agent_id": "pid_70000001-0000-4000-8000-000000000001", "session_id": "pid_70000002-0000-4000-8000-000000000002", "environment_id": identity.Scope.EnvironmentID().String()}}}}
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	decisions := &policyDecisionHistoryStub{values: []platformpolicy.RuntimeDecision{{ID: "pid_70000003-0000-4000-8000-000000000003", PolicyID: policyID, EnvironmentID: identity.Scope.EnvironmentID().String(), Result: "block", CorrelationID: "pid_70000004-0000-4000-8000-000000000004", At: at}}}
	handler, err := NewPolicyPublicHTTPHandler(PolicyPublicHTTPConfig{Workflows: workflow, History: history, Decisions: decisions})
	if err != nil {
		t.Fatal(err)
	}

	request := workflowRequest(t, identity, testCorrelationID, "simulatePolicy", map[string]string{"id": policyID}, http.MethodPost, "/api/v1/policies/"+policyID+"/simulate", `{}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Body.String() != "{\"example_session_ids\":[\"pid_70000002-0000-4000-8000-000000000002\"],\"matches\":1,\"would_block\":1}\n" {
		t.Fatalf("simulation status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if history.scope != identity.Scope || history.trigger != "tool" || history.limit != 100 || workflow.getCalls != 1 {
		t.Fatalf("history scope=%v trigger=%q limit=%d reads=%d", history.scope, history.trigger, history.limit, workflow.getCalls)
	}

	request = workflowRequest(t, identity, testCorrelationID, "listPolicyDecisions", map[string]string{"id": policyID}, http.MethodGet, "/api/v1/policies/"+policyID+"/decisions?limit=25", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("decisions status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var page struct {
		Items []platformpolicy.RuntimeDecision `json:"items"`
	}
	if json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0] != decisions.values[0] || decisions.scope != identity.Scope || decisions.policyID != policyID || decisions.limit != 25 || workflow.getCalls != 2 {
		t.Fatalf("page=%#v decision request=%#v reads=%d", page, decisions, workflow.getCalls)
	}
}

func TestPolicyPublicHandlerFailsClosedBeforeProviderIO(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	validPolicy := json.RawMessage(`{"id":"policy-runtime-history","name":"Runtime history","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"invoke"}],"action":"monitor","rollout":"monitor","failure_mode":"closed"}`)
	tests := []struct {
		name       string
		operation  string
		method     string
		path       string
		body       string
		workflow   *workflowRepositoryStub
		historyErr error
		want       int
	}{
		{name: "nonempty simulation input", operation: "simulatePolicy", method: http.MethodPost, path: "/api/v1/policies/policy-runtime-history/simulate", body: `{"events":[]}`, workflow: &workflowRepositoryStub{value: WorkflowValue{Body: validPolicy}}, want: http.StatusBadRequest},
		{name: "foreign environment event", operation: "simulatePolicy", method: http.MethodPost, path: "/api/v1/policies/policy-runtime-history/simulate", body: `{}`, workflow: &workflowRepositoryStub{value: WorkflowValue{Body: validPolicy}}, want: http.StatusServiceUnavailable},
		{name: "provider unavailable", operation: "simulatePolicy", method: http.MethodPost, path: "/api/v1/policies/policy-runtime-history/simulate", body: `{}`, workflow: &workflowRepositoryStub{value: WorkflowValue{Body: validPolicy}}, historyErr: errors.New("secret provider response"), want: http.StatusServiceUnavailable},
		{name: "unknown query", operation: "listPolicyDecisions", method: http.MethodGet, path: "/api/v1/policies/policy-runtime-history/decisions?cursor=secret", workflow: &workflowRepositoryStub{value: WorkflowValue{Body: validPolicy}}, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			history := &policyActionHistoryStub{err: test.historyErr}
			if test.name == "foreign environment event" {
				history.events = []platformpolicy.ActionContext{{PrincipalID: "principal", AgentID: "agent", SessionID: "session", Action: "tool", Resource: "shell", EnvironmentID: "foreign", Metadata: map[string]string{"action": "invoke"}}}
			}
			decisions := &policyDecisionHistoryStub{}
			handler, err := NewPolicyPublicHTTPHandler(PolicyPublicHTTPConfig{Workflows: test.workflow, History: history, Decisions: decisions})
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, test.operation, map[string]string{"id": "policy-runtime-history"}, test.method, test.path, test.body)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || len(response.Body.String()) > 256 || test.historyErr != nil && containsText(response.Body.String(), "secret") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.name == "nonempty simulation input" && (test.workflow.getCalls != 0 || history.calls != 0) {
				t.Fatalf("invalid input performed IO reads=%d history=%d", test.workflow.getCalls, history.calls)
			}
		})
	}
}

func TestPolicyWorkflowSurfaceRoutesOnlyPolicyProviderOperations(t *testing.T) {
	workflow := handlerResponse("workflow")
	policyHandler := handlerResponse("policy")
	surface, err := NewPolicyWorkflowSurface(workflow, policyHandler)
	if err != nil {
		t.Fatal(err)
	}
	for operation, expected := range map[string]string{"simulatePolicy": "policy", "listPolicyDecisions": "policy", "getPolicy": "workflow"} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		surface.ServeHTTP(response, request)
		if response.Body.String() != expected {
			t.Fatalf("operation %s body=%q", operation, response.Body.String())
		}
	}
}

type policyActionHistoryStub struct {
	events  []platformpolicy.ActionContext
	err     error
	scope   domain.Scope
	trigger string
	limit   int
	calls   int
}

func (stub *policyActionHistoryStub) SearchPolicyActions(_ context.Context, scope domain.Scope, trigger string, limit int) ([]platformpolicy.ActionContext, error) {
	stub.calls++
	stub.scope, stub.trigger, stub.limit = scope, trigger, limit
	return append([]platformpolicy.ActionContext(nil), stub.events...), stub.err
}

func (*policyActionHistoryStub) Ready(context.Context) error { return nil }

type policyDecisionHistoryStub struct {
	values   []platformpolicy.RuntimeDecision
	err      error
	scope    domain.Scope
	policyID string
	limit    int
}

func (stub *policyDecisionHistoryStub) ListPolicyDecisions(_ context.Context, scope domain.Scope, policyID string, limit int) ([]platformpolicy.RuntimeDecision, error) {
	stub.scope, stub.policyID, stub.limit = scope, policyID, limit
	return append([]platformpolicy.RuntimeDecision(nil), stub.values...), stub.err
}

func (*policyDecisionHistoryStub) Ready(context.Context) error { return nil }

func containsText(value, target string) bool {
	for index := 0; index+len(target) <= len(value); index++ {
		if value[index:index+len(target)] == target {
			return true
		}
	}
	return false
}
