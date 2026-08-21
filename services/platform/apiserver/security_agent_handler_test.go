package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type securityAgentPublicAuthorityStub struct {
	activation SecurityAgentActivation
	result     SecurityAgentActivationResult
	calls      int
}

func (stub *securityAgentPublicAuthorityStub) ActivateSecurityAgent(_ context.Context, _ RequestIdentity, input SecurityAgentActivation) (SecurityAgentActivationResult, error) {
	stub.calls++
	stub.activation = input
	return stub.result, nil
}

func TestSecurityAgentPublicHandlerActivatesWithFreshBrowserAuthorityAndDurableReceipt(t *testing.T) {
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	receiptID := "pid_78000003-0000-4000-8000-000000000003"
	correlationID := "pid_78000004-0000-4000-8000-000000000004"
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	stub := &securityAgentPublicAuthorityStub{result: SecurityAgentActivationResult{ID: definitionID, Activation: "validated", Enabled: false, Version: 2, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}}
	ids := []string{auditID, receiptID}
	index := 0
	definitionCalls := 0
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { definitionCalls++ }), SecurityAgentPublicHandlerConfig{
		Clock: func() time.Time { return now },
		NewProductID: func() (string, error) {
			value := ids[index]
			index++
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = now.Add(4 * time.Minute)
	request := workflowRequest(t, identity, correlationID, "activateSecurityAgent", map[string]string{"id": definitionID}, http.MethodPost, "/api/v1/security-agents/"+definitionID+"/activation", `{"activation":"validated"}`)
	request.Header.Set("Idempotency-Key", "activate-agent-idem-0001")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` || response.Header().Get("X-Audit-ID") != auditID || response.Header().Get("X-Mutation-Receipt-ID") != receiptID || definitionCalls != 0 || stub.calls != 1 {
		t.Fatalf("activation status=%d headers=%#v body=%s definitionCalls=%d calls=%d", response.Code, response.Header(), response.Body.String(), definitionCalls, stub.calls)
	}
	var body map[string]any
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["id"] != definitionID || body["activation"] != "validated" || body["enabled"] != false || stub.activation.ExpectedVersion != 1 || stub.activation.IdempotencyKey != "activate-agent-idem-0001" || stub.activation.FreshAuthExpiresAt != identity.FreshAuthExpiresAt || stub.activation.AuditID != auditID || stub.activation.ReceiptID != receiptID {
		t.Fatalf("activation body=%#v input=%#v", body, stub.activation)
	}
}

func TestSecurityAgentPublicHandlerRejectsStaleActivationBeforeRepository(t *testing.T) {
	stub := &securityAgentPublicAuthorityStub{}
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = false
	request := workflowRequest(t, identity, testCorrelationID, "activateSecurityAgent", map[string]string{"id": "pid_78000001-0000-4000-8000-000000000001"}, http.MethodPost, "/api/v1/security-agents/pid_78000001-0000-4000-8000-000000000001/activation", `{"activation":"validated"}`)
	request.Header.Set("Idempotency-Key", "activate-agent-idem-0001")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || stub.calls != 0 {
		t.Fatalf("stale activation status=%d body=%s calls=%d", response.Code, response.Body.String(), stub.calls)
	}
}
