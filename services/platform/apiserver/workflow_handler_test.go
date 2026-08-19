package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type workflowRepositoryStub struct {
	page                json.RawMessage
	value               WorkflowValue
	result              WorkflowMutationResult
	err                 error
	listScope           domain.Scope
	getScope            domain.Scope
	mutation            WorkflowMutation
	identity            RequestIdentity
	replay              WorkflowMutationResult
	replayed            bool
	replayErr           error
	getCalls            int
	cursorPage          WorkflowListPage
	cursorCalls         int
	receipts            []WorkflowMutationReceipt
	receiptListCalls    int
	receiptID           string
	receiptListIdentity RequestIdentity
	receiptAckIdentity  RequestIdentity
}

func (repository *workflowRepositoryStub) ListWorkflows(_ context.Context, scope domain.Scope, _, _, _ string) (json.RawMessage, error) {
	repository.listScope = scope
	return repository.page, repository.err
}
func (repository *workflowRepositoryStub) ListWorkflowPage(_ context.Context, scope domain.Scope, _, _ string, _ int) (WorkflowListPage, error) {
	repository.listScope = scope
	repository.cursorCalls++
	return repository.cursorPage, repository.err
}
func (repository *workflowRepositoryStub) GetWorkflow(_ context.Context, scope domain.Scope, _, _ string) (WorkflowValue, error) {
	repository.getCalls++
	repository.getScope = scope
	return repository.value, repository.err
}
func (repository *workflowRepositoryStub) ReplayWorkflow(_ context.Context, _ RequestIdentity, _ string, _ string, _ json.RawMessage) (WorkflowMutationResult, bool, error) {
	return repository.replay, repository.replayed, repository.replayErr
}
func (repository *workflowRepositoryStub) MutateWorkflow(_ context.Context, identity RequestIdentity, mutation WorkflowMutation) (WorkflowMutationResult, error) {
	repository.identity, repository.mutation = identity, mutation
	return repository.result, repository.err
}
func (repository *workflowRepositoryStub) ListWorkflowMutationReceipts(_ context.Context, identity RequestIdentity, _ int) ([]WorkflowMutationReceipt, error) {
	repository.receiptListCalls++
	repository.receiptListIdentity = identity
	return repository.receipts, repository.err
}
func (repository *workflowRepositoryStub) AcknowledgeWorkflowMutationReceipt(_ context.Context, identity RequestIdentity, receiptID string) error {
	repository.receiptAckIdentity, repository.receiptID = identity, receiptID
	return repository.err
}

func TestWorkflowHandlerReplaysLostRolloutResponseBeforeMutablePolicyRead(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{replayed: true, replay: WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"policy-bounded","rollout":"enforced"}`), Version: 3}, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation, ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc", Replayed: true}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, correlation, "rolloutPolicy", map[string]string{"id": "policy-bounded"}, http.MethodPost, "/api/v1/policies/policy-bounded/rollout", `{"state":"enforced","target_id":"pid_10000003-0000-4000-8000-000000000003"}`)
	request.Header.Set("Idempotency-Key", "idem-rollout-policy-001")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || repository.getCalls != 0 || response.Header().Get("X-Audit-ID") != repository.replay.AuditID {
		t.Fatalf("lost-response replay = status %d reads %d headers %v body %s", response.Code, repository.getCalls, response.Header(), response.Body.String())
	}
	var receipt map[string]any
	if json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt["state"] != "enforced" || receipt["target_id"] != identity.Scope.EnvironmentID().String() {
		t.Fatalf("replayed rollout receipt = %s", response.Body.String())
	}
}

func TestWorkflowHandlerUsesOpaqueScopeBoundSecurityAgentCursor(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{cursorPage: WorkflowListPage{Items: []json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001"}`)}, NextID: "pid_40000001-0000-4000-8000-000000000001"}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?limit=1", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var page struct {
		Items    []json.RawMessage `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.PageInfo.NextCursor == nil || !page.PageInfo.HasMore {
		t.Fatalf("first page = %d %s", response.Code, response.Body.String())
	}
	cursor := *page.PageInfo.NextCursor
	request = workflowRequest(t, identity, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?cursor=%%%", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repository.cursorCalls != 1 {
		t.Fatalf("invalid cursor = %d calls=%d body=%s", response.Code, repository.cursorCalls, response.Body.String())
	}
	foreign := fixtureRequestIdentity(t)
	organization, _ := domain.ParseProductID("pid_20000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_20000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_20000003-0000-4000-8000-000000000003")
	foreign.Scope, _ = domain.NewScope(organization, workspace, environment)
	request = workflowRequest(t, foreign, testCorrelationID, "listSecurityAgents", nil, http.MethodGet, "/api/v1/security-agents?cursor="+cursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repository.cursorCalls != 1 || strings.Contains(response.Body.String(), identity.Scope.OrganizationID().String()) {
		t.Fatalf("foreign cursor = %d calls=%d body=%s", response.Code, repository.cursorCalls, response.Body.String())
	}
}

func TestWorkflowHandlerCreatesPolicyWithExactIdempotencyAuditAndVersion(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "manage_workflows"}
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{result: WorkflowMutationResult{
		WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`), Version: 1},
		AuditID:       "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation, ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}}
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, correlation, "createPolicy", nil, http.MethodPost, "/api/v1/policies", `{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	request.Header.Set("Idempotency-Key", "idem-create-policy-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != repository.result.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != repository.result.ReceiptID {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if repository.identity.Scope != identity.Scope || repository.mutation.Action != "create" || repository.mutation.Kind != "policy" || repository.mutation.ID != "policy-bounded" || repository.mutation.IdempotencyKey != "idem-create-policy-0001" || repository.mutation.CorrelationID != correlation || repository.mutation.ReceiptID == "" {
		t.Fatalf("mutation = %#v identity=%#v", repository.mutation, repository.identity)
	}
}

func TestWorkflowHandlerListsAndAcknowledgesExactAuthenticatedReceipts(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	receiptID := "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	repository := &workflowRepositoryStub{receipts: []WorkflowMutationReceipt{{ID: receiptID, Operation: "createPolicy", IdempotencyKey: "idem-create-policy-0001", Intent: json.RawMessage(`{"body":{}}`), Result: json.RawMessage(`{"id":"policy-bounded"}`), ResourceKind: "policy", ResourceID: "policy-bounded", ResourceVersion: 1, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", CreatedAt: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)

	request := workflowRequest(t, identity, testCorrelationID, "listWorkflowMutationReceipts", nil, http.MethodGet, "/api/v1/workflow-mutation-receipts?limit=20", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), receiptID) || repository.receiptListIdentity.Scope != identity.Scope || repository.receiptListIdentity.PrincipalID != identity.PrincipalID {
		t.Fatalf("receipt list = %d %s identity=%#v", response.Code, response.Body.String(), repository.receiptListIdentity)
	}
	for _, target := range []string{
		"/api/v1/workflow-mutation-receipts?unexpected=true",
		"/api/v1/workflow-mutation-receipts?limit=20&unexpected=true",
	} {
		request = workflowRequest(t, identity, testCorrelationID, "listWorkflowMutationReceipts", nil, http.MethodGet, target, "")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || repository.receiptListCalls != 1 {
			t.Fatalf("unexpected receipt query %q = %d calls=%d body=%s", target, response.Code, repository.receiptListCalls, response.Body.String())
		}
	}

	request = workflowRequest(t, identity, testCorrelationID, "acknowledgeWorkflowMutationReceipt", map[string]string{"id": receiptID}, http.MethodPost, "/api/v1/workflow-mutation-receipts/"+receiptID+"/acknowledge", `{}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || repository.receiptID != receiptID || repository.receiptAckIdentity.Scope != identity.Scope || repository.receiptAckIdentity.PrincipalID != identity.PrincipalID {
		t.Fatalf("receipt acknowledgement = %d %s id=%q identity=%#v", response.Code, response.Body.String(), repository.receiptID, repository.receiptAckIdentity)
	}
}

func TestWorkflowHandlerReceiptAcknowledgementIsNondisclosing(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{err: ErrRepositoryNotFound}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, testCorrelationID, "acknowledgeWorkflowMutationReceipt", map[string]string{"id": "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}, http.MethodPost, "/api/v1/workflow-mutation-receipts/pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc/acknowledge", `{}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "receipt") {
		t.Fatalf("foreign receipt response = %d %s", response.Code, response.Body.String())
	}
}

func TestWorkflowHandlerRequiresVersionAndMapsConflictWithoutMutationSuccess(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{err: ErrRepositoryConflict}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, correlation, "updatePolicy", map[string]string{"id": "policy-bounded"}, http.MethodPatch, "/api/v1/policies/policy-bounded", `{"id":"policy-bounded","name":"Changed","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	request.Header.Set("Idempotency-Key", "idem-update-policy-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status = %d", response.Code)
	}

	request = workflowRequest(t, identity, correlation, "updatePolicy", map[string]string{"id": "policy-bounded"}, http.MethodPatch, "/api/v1/policies/policy-bounded", `{"id":"policy-bounded","name":"Changed","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	request.Header.Set("Idempotency-Key", "idem-update-policy-0001")
	request.Header.Set("If-Match", `"2"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestWorkflowHandlerRolloutPersistsUpdatedPolicyButReturnsRolloutReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	policyBody := json.RawMessage(`{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"monitor","failure_mode":"open"}`)
	repository := &workflowRepositoryStub{value: WorkflowValue{Body: policyBody, Version: 2}, result: WorkflowMutationResult{WorkflowValue: WorkflowValue{Version: 3}, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, correlation, "rolloutPolicy", map[string]string{"id": "policy-bounded"}, http.MethodPost, "/api/v1/policies/policy-bounded/rollout", `{"state":"enforced","target_id":"pid_10000003-0000-4000-8000-000000000003"}`)
	request.Header.Set("Idempotency-Key", "idem-rollout-policy-001")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	var stored map[string]any
	if json.Unmarshal(repository.mutation.Body, &stored) != nil || stored["id"] != "policy-bounded" || stored["name"] != "Bounded policy" || stored["rollout"] != "enforced" {
		t.Fatalf("stored rollout mutation replaced policy: %s", repository.mutation.Body)
	}
	var receipt map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt["policy_id"] != "policy-bounded" || receipt["state"] != "enforced" {
		t.Fatalf("rollout response = %d %s", response.Code, response.Body.String())
	}
}

func TestWorkflowHandlerRejectsInvalidPolicyTransitionBeforeMutation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{value: WorkflowValue{Body: json.RawMessage(`{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`), Version: 2}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, testCorrelationID, "rolloutPolicy", map[string]string{"id": "policy-bounded"}, http.MethodPost, "/api/v1/policies/policy-bounded/rollout", `{"state":"enforced","target_id":"pid_10000003-0000-4000-8000-000000000003"}`)
	request.Header.Set("Idempotency-Key", "idem-invalid-transition-01")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || repository.mutation.Operation != "" {
		t.Fatalf("invalid transition = %d %s mutation=%#v", response.Code, response.Body.String(), repository.mutation)
	}
}

func TestWorkflowHandlerRejectsUnmountedPolicySimulationWithoutPersistence(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	request := workflowRequest(t, identity, correlation, "simulatePolicy", map[string]string{"id": "policy-bounded"}, http.MethodPost, "/api/v1/policies/policy-bounded/simulate", `{"events":[{"principal_id":"principal-1","agent_id":"agent-1","session_id":"session-1","action":"write","resource":"scoped-resource","environment_id":"`+identity.Scope.EnvironmentID().String()+`","metadata":{}}]}`)
	request.Header.Set("Idempotency-Key", "idem-simulate-policy-001")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound || repository.getCalls != 0 || repository.mutation.Operation != "" {
		t.Fatalf("unmounted simulation = response %d reads=%d mutation=%#v body=%s", response.Code, repository.getCalls, repository.mutation, response.Body.String())
	}
}

func TestWorkflowHandlerUpdatesPreserveServerOwnedIntegrationState(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{value: WorkflowValue{Version: 4, Body: json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","connector_key":"generic-webhook","name":"old","configuration":{"destination_url":"https://example.test/hooks","signing_secret_reference":"secret_ref_old"},"status":"authorized","created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-02T00:00:00Z"}`)}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	request := workflowRequest(t, identity, correlation, "updateIntegration", map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}, http.MethodPatch, "/api/v1/integrations/pid_90000001-0000-4000-8000-000000000001", `{"name":"new","configuration":{"destination_url":"https://example.test/new","signing_secret_reference":"secret_ref_new"}}`)
	request.Header.Set("If-Match", `"4"`)
	mutation, _, _, err := handler.buildMutation(request, identity, RoutedOperation{OperationID: "updateIntegration", PathParameters: map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}}, "idem-update-integration-01", "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", correlation)
	var integrationValue map[string]any
	if err != nil || json.Unmarshal(mutation.Body, &integrationValue) != nil || integrationValue["created_at"] != "2026-08-01T00:00:00Z" || integrationValue["status"] != "authorized" {
		t.Fatalf("integration update = %v %s", err, mutation.Body)
	}

}

func TestWorkflowHandlerUsesServerScopeAndNondisclosingFixedErrors(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{err: ErrRepositoryNotFound}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "getIntegration", map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}, http.MethodGet, "/api/v1/integrations/pid_90000001-0000-4000-8000-000000000001", "")
	request.Header.Set("X-Zasp-Organization-ID", "pid_20000001-0000-4000-8000-000000000001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repository.getScope != identity.Scope || bytes.Contains(response.Body.Bytes(), []byte("90000001")) {
		t.Fatalf("response = %d %s scope=%v", response.Code, response.Body.String(), repository.getScope)
	}
}

func TestWorkflowHandlerDecodesSecurityAgentContractAndBuildsDurableDefinition(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	resultBody := json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","name":"Bounded response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`)
	repository := &workflowRepositoryStub{result: WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: resultBody, Version: 1}, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	body := `{"name":"Bounded response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`
	request := workflowRequest(t, identity, correlation, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", body)
	request.Header.Set("Idempotency-Key", "idem-create-agent-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || repository.mutation.Kind != "security_agent" {
		t.Fatalf("response = %d %s mutation=%#v", response.Code, response.Body.String(), repository.mutation)
	}
	repository.mutation = WorkflowMutation{}
	request = workflowRequest(t, identity, correlation, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", `{"id":"pid_90000001-0000-4000-8000-000000000001","name":"Client assigned","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`)
	request.Header.Set("Idempotency-Key", "idem-reject-client-agent-id")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.mutation.Operation != "" {
		t.Fatalf("client-assigned id response = %d mutation=%#v", response.Code, repository.mutation)
	}
}

func TestWorkflowHandlerRejectsUnservedSecurityAction(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	body := `{"name":"Unsafe response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["provider_magic_success"],"verification_kind":"test_run","definition_version":1,"enabled":true}`
	request := workflowRequest(t, identity, correlation, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", body)
	request.Header.Set("Idempotency-Key", "idem-reject-agent-action")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.mutation.Operation != "" {
		t.Fatalf("unknown action response = %d mutation=%#v", response.Code, repository.mutation)
	}
}

func TestWorkflowHandlerPublishesOnlyLocallyCompleteCatalogAndTemplates(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{}
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	request := workflowRequest(t, identity, testCorrelationID, "listIntegrationCatalog", nil, http.MethodGet, "/api/v1/integration-catalog", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var catalog struct {
		Items []struct {
			Key           string   `json:"key"`
			Description   string   `json:"description"`
			Actions       []string `json:"actions"`
			AuthMode      string   `json:"auth_mode"`
			TestSemantics string   `json:"test_semantics"`
		} `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &catalog) != nil || len(catalog.Items) != 1 || catalog.Items[0].Key != "generic-webhook" ||
		!slices.Equal(catalog.Items[0].Actions, []string{"store_configuration"}) || catalog.Items[0].AuthMode != "secret_reference" ||
		!strings.Contains(catalog.Items[0].Description, "future delivery adapter") || !strings.Contains(catalog.Items[0].TestSemantics, "without contacting") {
		t.Fatalf("local catalog = %d %s", response.Code, response.Body.String())
	}

	request = workflowRequest(t, identity, testCorrelationID, "listSecurityAgentTemplates", nil, http.MethodGet, "/api/v1/security-agent-templates", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var templates struct {
		Items []struct {
			DefaultActions []string `json:"default_actions"`
		} `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &templates) != nil || len(templates.Items) != 1 {
		t.Fatalf("local templates = %d %s", response.Code, response.Body.String())
	}
	for _, action := range templates.Items[0].DefaultActions {
		if !servedWorkflowActions([]string{action}) {
			t.Fatalf("template publishes unsupported action %q", action)
		}
	}
}

func workflowRequest(t *testing.T, identity RequestIdentity, correlation, operation string, params map[string]string, method, path, body string) *http.Request {
	t.Helper()
	var source *bytes.Reader
	if body == "" {
		source = bytes.NewReader(nil)
	} else {
		source = bytes.NewReader([]byte(body))
	}
	request := httptest.NewRequest(method, path, source)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, correlation))
	if params == nil {
		params = map[string]string{}
	}
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: params}))
	return request
}

var _ workflowRepository = (*workflowRepositoryStub)(nil)
var _ = errors.Is
