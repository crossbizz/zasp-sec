package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type workflowRepositoryStub struct {
	page      json.RawMessage
	value     WorkflowValue
	result    WorkflowMutationResult
	err       error
	listScope domain.Scope
	getScope  domain.Scope
	mutation  WorkflowMutation
	identity  RequestIdentity
}

func (repository *workflowRepositoryStub) ListWorkflows(_ context.Context, scope domain.Scope, _, _, _ string) (json.RawMessage, error) {
	repository.listScope = scope
	return repository.page, repository.err
}
func (repository *workflowRepositoryStub) GetWorkflow(_ context.Context, scope domain.Scope, _, _ string) (WorkflowValue, error) {
	repository.getScope = scope
	return repository.value, repository.err
}
func (repository *workflowRepositoryStub) MutateWorkflow(_ context.Context, identity RequestIdentity, mutation WorkflowMutation) (WorkflowMutationResult, error) {
	repository.identity, repository.mutation = identity, mutation
	return repository.result, repository.err
}

func TestWorkflowHandlerCreatesPolicyWithExactIdempotencyAuditAndVersion(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "manage_workflows"}
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{result: WorkflowMutationResult{
		WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`), Version: 1},
		AuditID:       "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation,
	}}
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, correlation, "createPolicy", nil, http.MethodPost, "/api/v1/policies", `{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	request.Header.Set("Idempotency-Key", "idem-create-policy-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != repository.result.AuditID {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if repository.identity.Scope != identity.Scope || repository.mutation.Action != "create" || repository.mutation.Kind != "policy" || repository.mutation.ID != "policy-bounded" || repository.mutation.IdempotencyKey != "idem-create-policy-0001" || repository.mutation.CorrelationID != correlation {
		t.Fatalf("mutation = %#v identity=%#v", repository.mutation, repository.identity)
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
	policyBody := json.RawMessage(`{"id":"policy-bounded","name":"Bounded policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
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

func TestWorkflowHandlerSensorSecretIsDeterministicForReplayAndNeverStoredInBody(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	sensorID := "pid_90000001-0000-4000-8000-000000000001"
	stored := json.RawMessage(`{"id":"` + sensorID + `","name":"prod sensor","mode":"metadata_only","capabilities":[],"created_at":"2026-08-18T12:00:00Z","updated_at":"2026-08-18T12:00:00Z"}`)
	repository := &workflowRepositoryStub{result: WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: stored, Version: 1, SecretGeneration: 0}, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: correlation}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	request := workflowRequest(t, identity, correlation, "createSensorEnrollment", nil, http.MethodPost, "/api/v1/sensors", `{"name":"prod sensor","mode":"metadata_only"}`)
	request.Header.Set("Idempotency-Key", "idem-create-sensor-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var first map[string]any
	if json.Unmarshal(response.Body.Bytes(), &first) != nil || len(first["token"].(string)) < 44 {
		t.Fatalf("enrollment = %s", response.Body.String())
	}
	if bytes.Contains(repository.mutation.Body, []byte("token")) {
		t.Fatalf("stored body contains secret: %s", repository.mutation.Body)
	}

	repository.result.Replayed = true
	request = workflowRequest(t, identity, correlation, "createSensorEnrollment", nil, http.MethodPost, "/api/v1/sensors", `{"name":"prod sensor","mode":"metadata_only"}`)
	request.Header.Set("Idempotency-Key", "idem-create-sensor-0001")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var second map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &second)
	if second["token"] != first["token"] {
		t.Fatalf("replayed token changed: %q != %q", second["token"], first["token"])
	}
}

func TestWorkflowHandlerUpdatesPreserveServerOwnedIntegrationAndSensorState(t *testing.T) {
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

	repository.value = WorkflowValue{Version: 2, SecretGeneration: 1, Body: json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","name":"old sensor","mode":"metadata_only","capabilities":["events"],"last_heartbeat":"2026-08-17T12:00:00Z","created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-02T00:00:00Z"}`)}
	request = workflowRequest(t, identity, correlation, "updateSensor", map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}, http.MethodPatch, "/api/v1/sensors/pid_90000001-0000-4000-8000-000000000001", `{"name":"new sensor","mode":"full"}`)
	request.Header.Set("If-Match", `"2"`)
	mutation, _, _, err = handler.buildMutation(request, identity, RoutedOperation{OperationID: "updateSensor", PathParameters: map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}}, "idem-update-sensor-000001", "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", correlation)
	var sensorValue map[string]any
	if err != nil || json.Unmarshal(mutation.Body, &sensorValue) != nil || sensorValue["created_at"] != "2026-08-01T00:00:00Z" || sensorValue["last_heartbeat"] != "2026-08-17T12:00:00Z" || len(sensorValue["capabilities"].([]any)) != 1 {
		t.Fatalf("sensor update = %v %s", err, mutation.Body)
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
	body := `{"id":"","name":"Bounded response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["run_test"],"verification_kind":"test_run","definition_version":1,"enabled":true}`
	request := workflowRequest(t, identity, correlation, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", body)
	request.Header.Set("Idempotency-Key", "idem-create-agent-0001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || repository.mutation.Kind != "security_agent" {
		t.Fatalf("response = %d %s mutation=%#v", response.Code, response.Body.String(), repository.mutation)
	}
}

func TestWorkflowHandlerRejectsUnservedSecurityActionAndMalformedRunEvidence(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	correlation := "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	repository := &workflowRepositoryStub{value: WorkflowValue{Version: 1, Body: json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","allowed_actions":["run_test"]}`)}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	body := `{"id":"","name":"Unsafe response","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_10000003-0000-4000-8000-000000000003"],"autonomy":"supervised","max_steps":10,"max_duration_seconds":900,"temporary_policy_seconds":3600,"ai_token_budget":4000,"concurrency_limit":2,"allowed_actions":["provider_magic_success"],"verification_kind":"test_run","definition_version":1,"enabled":true}`
	request := workflowRequest(t, identity, correlation, "createSecurityAgent", nil, http.MethodPost, "/api/v1/security-agents", body)
	request.Header.Set("Idempotency-Key", "idem-reject-agent-action")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.mutation.Operation != "" {
		t.Fatalf("unknown action response = %d mutation=%#v", response.Code, repository.mutation)
	}

	request = workflowRequest(t, identity, correlation, "runSecurityAgent", map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}, http.MethodPost, "/api/v1/security-agents/pid_90000001-0000-4000-8000-000000000001/runs", `{"environment_id":"pid_10000003-0000-4000-8000-000000000003","trigger_kind":"finding","trigger_id":"not-an-evidence-id"}`)
	request.Header.Set("Idempotency-Key", "idem-reject-run-evidence")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed evidence response = %d %s", response.Code, response.Body.String())
	}
}

func TestWorkflowHandlerBuildsAtomicRunApprovalEnvelope(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &workflowRepositoryStub{value: WorkflowValue{Version: 3, Body: json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","allowed_actions":["run_test"]}`)}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "runSecurityAgent", map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}, http.MethodPost, "/api/v1/security-agents/pid_90000001-0000-4000-8000-000000000001/runs", `{"environment_id":"pid_10000003-0000-4000-8000-000000000003","trigger_kind":"finding","trigger_id":"pid_90000002-0000-4000-8000-000000000002"}`)
	request.Header.Set("Idempotency-Key", "idem-run-agent-approval-1")
	mutation, _, _, err := handler.buildMutation(request, identity, RoutedOperation{OperationID: "runSecurityAgent", PathParameters: map[string]string{"id": "pid_90000001-0000-4000-8000-000000000001"}}, "idem-run-agent-approval-1", "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	var value struct {
		Approval map[string]any `json:"_approval"`
	}
	if err != nil || json.Unmarshal(mutation.Body, &value) != nil || value.Approval["state"] != "pending" || value.Approval["run_id"] != mutation.ID || value.Approval["expires_at"] != nil {
		t.Fatalf("atomic run mutation = (%v, %s)", err, mutation.Body)
	}
}

func TestWorkflowHandlerRunDetailIncludesDurableScopedApprovals(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	runID := "pid_90000001-0000-4000-8000-000000000001"
	repository := &workflowRepositoryStub{value: WorkflowValue{Version: 1, Body: json.RawMessage(`{"id":"` + runID + `","agent_id":"pid_90000002-0000-4000-8000-000000000002","state":"waiting_approval","evidence_ids":["pid_90000003-0000-4000-8000-000000000003"],"definition_version":1,"version":1}`)}, page: json.RawMessage(`{"items":[{"id":"pid_90000004-0000-4000-8000-000000000004","run_id":"` + runID + `","step_id":"pid_90000005-0000-4000-8000-000000000005","state":"pending","expires_at":"2026-08-18T12:15:00Z","version":1}]}`)}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "getSecurityAgentRun", map[string]string{"id": runID}, http.MethodGet, "/api/v1/security-agent-runs/"+runID, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var detail struct {
		Approvals []map[string]any `json:"approvals"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &detail) != nil || len(detail.Approvals) != 1 || detail.Approvals[0]["run_id"] != runID {
		t.Fatalf("run detail = %d %s", response.Code, response.Body.String())
	}
}

func TestWorkflowHandlerRejectsExpiredOrNonpendingApproval(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	approvalID := "pid_90000001-0000-4000-8000-000000000001"
	repository := &workflowRepositoryStub{value: WorkflowValue{Version: 1, Body: json.RawMessage(`{"id":"` + approvalID + `","run_id":"pid_90000002-0000-4000-8000-000000000002","step_id":"pid_90000003-0000-4000-8000-000000000003","state":"pending","expires_at":"2026-08-18T11:59:59Z","version":1}`)}}
	handler, _ := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) })
	request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "decideSecurityAgentApproval", map[string]string{"id": approvalID}, http.MethodPost, "/api/v1/security-agent-approvals/"+approvalID+"/decision", `{"decision":"approved"}`)
	request.Header.Set("Idempotency-Key", "idem-expired-approval-01")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || repository.mutation.Operation != "" {
		t.Fatalf("expired approval = %d %s mutation=%#v", response.Code, response.Body.String(), repository.mutation)
	}
}

func TestSensorCoverageOmitsUnknownTimestampInsteadOfEmittingInvalidDate(t *testing.T) {
	coverage, err := sensorCoverage(json.RawMessage(`{"id":"pid_90000001-0000-4000-8000-000000000001","capabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := coverage["last_heartbeat"]; exists {
		t.Fatalf("unknown last heartbeat must be omitted: %#v", coverage)
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
