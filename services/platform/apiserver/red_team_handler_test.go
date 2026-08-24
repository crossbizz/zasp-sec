package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type redTeamAuthorityStub struct {
	definitionResult RedTeamDefinitionMutationResult
	runResult        RedTeamRunMutationResult
	cancelInput      RedTeamCancelRequest
	calls            int
}

func (stub *redTeamAuthorityStub) ListRedTeamDefinitions(context.Context, RequestIdentity, RedTeamDefinitionPageRequest) (RedTeamDefinitionPage, error) {
	return RedTeamDefinitionPage{}, nil
}
func (stub *redTeamAuthorityStub) GetRedTeamDefinition(context.Context, RequestIdentity, string) (RedTeamDefinition, error) {
	return stub.definitionResult.Body, nil
}
func (stub *redTeamAuthorityStub) CreateRedTeamDefinition(context.Context, RequestIdentity, RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error) {
	stub.calls++
	return stub.definitionResult, nil
}
func (stub *redTeamAuthorityStub) UpdateRedTeamDefinition(context.Context, RequestIdentity, RedTeamDefinitionMutation) (RedTeamDefinitionMutationResult, error) {
	stub.calls++
	return stub.definitionResult, nil
}
func (stub *redTeamAuthorityStub) RunRedTeamTest(context.Context, RequestIdentity, RedTeamRunRequest) (RedTeamRunMutationResult, error) {
	stub.calls++
	return stub.runResult, nil
}
func (stub *redTeamAuthorityStub) ListRedTeamRuns(context.Context, RequestIdentity, RedTeamRunPageRequest) (RedTeamRunPage, error) {
	return RedTeamRunPage{}, nil
}
func (stub *redTeamAuthorityStub) GetRedTeamRun(context.Context, RequestIdentity, string) (RedTeamRunDetail, error) {
	return RedTeamRunDetail{RedTeamRun: stub.runResult.Body, Attempts: []RedTeamAttempt{}}, nil
}
func (stub *redTeamAuthorityStub) CancelRedTeamRun(_ context.Context, _ RequestIdentity, input RedTeamCancelRequest) (RedTeamRunMutationResult, error) {
	stub.calls++
	stub.cancelInput = input
	return stub.runResult, nil
}

func TestRedTeamHandlerCreatesAuditedDefinitionAndSuppressesPATReceiptHeader(t *testing.T) {
	definitionID := "pid_79000101-0000-4000-8000-000000000001"
	targetID := "pid_79000102-0000-4000-8000-000000000002"
	auditID := "pid_79000103-0000-4000-8000-000000000003"
	receiptID := "pid_79000104-0000-4000-8000-000000000004"
	createdAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	stub := &redTeamAuthorityStub{definitionResult: RedTeamDefinitionMutationResult{
		Body:    RedTeamDefinition{ID: definitionID, Version: 1, Name: "Prompt safety", TargetID: targetID, TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: RedTeamSafety{Environment: "staging", CredentialClass: "read_only", ExpectedSideEffects: []string{"audit event"}}, Enabled: true, CreatedAt: createdAt, UpdatedAt: createdAt},
		AuditID: auditID, CorrelationID: testCorrelationID, ReceiptID: receiptID,
	}}
	handler, err := NewRedTeamPublicHTTPHandler(stub, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
		identity := fixtureRequestIdentity(t)
		identity.CredentialKind = credential
		request := workflowRequest(t, identity, testCorrelationID, "createTest", nil, http.MethodPost, "/api/v1/tests", `{"id":"`+definitionID+`","name":"Prompt safety","target_id":"`+targetID+`","target_kind":"agent_endpoint","categories":["prompt_injection"],"safety":{"environment":"staging","credential_class":"read_only","expected_side_effects":["audit event"]}}`)
		request.Header.Set("Idempotency-Key", "red-team-create-0001")
		request.Header.Set("If-Match", `"0"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != auditID || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("credential=%v response=%d headers=%v body=%s", credential, response.Code, response.Header(), response.Body.String())
		}
		if (credential == CredentialBrowserSession) != (response.Header().Get("X-Mutation-Receipt-ID") == receiptID) {
			t.Fatalf("credential=%v receipt header=%q", credential, response.Header().Get("X-Mutation-Receipt-ID"))
		}
	}
}

func TestRedTeamHandlerVersionFencesCancellation(t *testing.T) {
	runID := "pid_79000201-0000-4000-8000-000000000001"
	definitionID := "pid_79000202-0000-4000-8000-000000000002"
	queuedAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	stub := &redTeamAuthorityStub{runResult: RedTeamRunMutationResult{
		Body:    RedTeamRun{ID: runID, Version: 4, DefinitionID: definitionID, DefinitionVersion: 1, Status: "cancelled", Attempt: 0, CancelRequested: true, QueuedAt: queuedAt, CompletedAt: &queuedAt, ErrorCode: "cancelled"},
		AuditID: "pid_79000203-0000-4000-8000-000000000003", CorrelationID: testCorrelationID, ReceiptID: "pid_79000204-0000-4000-8000-000000000004",
	}}
	handler, err := NewRedTeamPublicHTTPHandler(stub, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := workflowRequest(t, identity, testCorrelationID, "cancelTestRun", map[string]string{"id": runID}, http.MethodPost, "/api/v1/test-runs/"+runID+"/cancel", "")
	request.Header.Set("Idempotency-Key", "red-team-cancel-0001")
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, request)
	if missing.Code != http.StatusBadRequest || stub.calls != 0 {
		t.Fatalf("missing version response=%d calls=%d body=%s", missing.Code, stub.calls, missing.Body.String())
	}
	request.Header.Set("If-Match", `"3"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || stub.cancelInput.ExpectedVersion != 3 || stub.cancelInput.RunID != runID {
		t.Fatalf("response=%d headers=%v input=%#v body=%s", response.Code, response.Header(), stub.cancelInput, response.Body.String())
	}
}
