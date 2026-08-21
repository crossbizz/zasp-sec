package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type securityAgentPublicAuthorityStub struct {
	activation SecurityAgentActivation
	result     SecurityAgentActivationResult
	simulation SecurityAgentSimulationRequest
	simulated  SecurityAgentSimulationResult
	calls      int
}

func (stub *securityAgentPublicAuthorityStub) ActivateSecurityAgent(_ context.Context, _ RequestIdentity, input SecurityAgentActivation) (SecurityAgentActivationResult, error) {
	stub.calls++
	stub.activation = input
	return stub.result, nil
}

func (stub *securityAgentPublicAuthorityStub) SimulateSecurityAgent(_ context.Context, _ RequestIdentity, input SecurityAgentSimulationRequest) (SecurityAgentSimulationResult, error) {
	stub.calls++
	stub.simulation = input
	return stub.simulated, nil
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

func TestSecurityAgentPublicHandlerPersistsAZeroEffectSimulation(t *testing.T) {
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	receiptID := "pid_78000003-0000-4000-8000-000000000003"
	correlationID := "pid_78000004-0000-4000-8000-000000000004"
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(15 * time.Minute)
	stub := &securityAgentPublicAuthorityStub{simulated: SecurityAgentSimulationResult{
		RunID: runID, DefinitionID: definitionID, DefinitionVersion: 2, PlanHash: "sha256:" + strings.Repeat("a", 64), CatalogVersion: "security-agent-actions-v1", ExpiresAt: expiresAt,
		MatchedEvidenceIDs: []string{evidenceID}, Summary: "Review exposed credential", Steps: []SecurityAgentSimulationStep{{Index: 0, Action: "create_temporary_policy", Authorization: "approval_required", ApprovalRequired: true}}, SideEffects: 0, Version: 1,
		AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID,
	}}
	ids := []string{runID, auditID, receiptID}
	index := 0
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: func() (string, error) { value := ids[index]; index++; return value, nil }})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := workflowRequest(t, identity, correlationID, "simulateSecurityAgent", map[string]string{"id": definitionID}, http.MethodPost, "/api/v1/security-agents/"+definitionID+"/simulate", `{"goal":"Review exposed credential","environment_id":"`+identity.Scope.EnvironmentID().String()+`","evidence_ids":["`+evidenceID+`"]}`)
	request.Header.Set("Idempotency-Key", "simulate-agent-idem-0001")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != auditID || response.Header().Get("X-Mutation-Receipt-ID") != receiptID || stub.calls != 1 {
		t.Fatalf("simulation status=%d headers=%#v body=%s calls=%d", response.Code, response.Header(), response.Body.String(), stub.calls)
	}
	if stub.simulation.RunID != runID || stub.simulation.ExpectedVersion != 2 || stub.simulation.ExpiresAt != expiresAt || len(stub.simulation.EvidenceIDs) != 1 || stub.simulation.EvidenceIDs[0] != evidenceID {
		t.Fatalf("simulation input=%#v", stub.simulation)
	}
	var body SecurityAgentSimulationResult
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || body.RunID != runID || body.PlanHash != stub.simulated.PlanHash || body.SideEffects != 0 || body.AuditID != "" || body.ReceiptID != "" {
		t.Fatalf("simulation body=%s decoded=%#v", response.Body.String(), body)
	}
}
