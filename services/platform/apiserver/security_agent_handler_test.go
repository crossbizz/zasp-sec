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

var securityAgentTestSigningKey = []byte("0123456789abcdef0123456789abcdef")

type securityAgentPublicAuthorityStub struct {
	activation   SecurityAgentActivation
	result       SecurityAgentActivationResult
	simulation   SecurityAgentSimulationRequest
	simulated    SecurityAgentSimulationResult
	run          SecurityAgentRunRequest
	runResult    SecurityAgentRunResult
	decision     SecurityAgentApprovalDecisionRequest
	decided      SecurityAgentApprovalResult
	runPage      SecurityAgentRunPageRequest
	runs         SecurityAgentRunPage
	runID        string
	runDetail    SecurityAgentRunDetail
	cancel       SecurityAgentCancelRequest
	cancelled    SecurityAgentRunResult
	approvalPage SecurityAgentApprovalPageRequest
	approvals    SecurityAgentApprovalPage
	approvalID   string
	approval     SecurityAgentApproval
	calls        int
}

func (stub *securityAgentPublicAuthorityStub) ListSecurityAgentRuns(_ context.Context, _ RequestIdentity, input SecurityAgentRunPageRequest) (SecurityAgentRunPage, error) {
	stub.calls++
	stub.runPage = input
	return stub.runs, nil
}

func (stub *securityAgentPublicAuthorityStub) GetSecurityAgentRun(_ context.Context, _ RequestIdentity, runID string) (SecurityAgentRunDetail, error) {
	stub.calls++
	stub.runID = runID
	return stub.runDetail, nil
}

func (stub *securityAgentPublicAuthorityStub) CancelSecurityAgentRun(_ context.Context, _ RequestIdentity, input SecurityAgentCancelRequest) (SecurityAgentRunResult, error) {
	stub.calls++
	stub.cancel = input
	return stub.cancelled, nil
}

func (stub *securityAgentPublicAuthorityStub) ListSecurityAgentApprovals(_ context.Context, _ RequestIdentity, input SecurityAgentApprovalPageRequest) (SecurityAgentApprovalPage, error) {
	stub.calls++
	stub.approvalPage = input
	return stub.approvals, nil
}

func (stub *securityAgentPublicAuthorityStub) GetSecurityAgentApproval(_ context.Context, _ RequestIdentity, approvalID string) (SecurityAgentApproval, error) {
	stub.calls++
	stub.approvalID = approvalID
	return stub.approval, nil
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

func (stub *securityAgentPublicAuthorityStub) RunSecurityAgent(_ context.Context, _ RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	stub.calls++
	stub.run = input
	return stub.runResult, nil
}

func (stub *securityAgentPublicAuthorityStub) DecideSecurityAgentApproval(_ context.Context, _ RequestIdentity, input SecurityAgentApprovalDecisionRequest) (SecurityAgentApprovalResult, error) {
	stub.calls++
	stub.decision = input
	return stub.decided, nil
}

func TestSecurityAgentPublicHandlerQueuesExactTenantFindingRun(t *testing.T) {
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	receiptID := "pid_78000003-0000-4000-8000-000000000003"
	correlationID := "pid_78000004-0000-4000-8000-000000000004"
	stub := &securityAgentPublicAuthorityStub{runResult: SecurityAgentRunResult{ID: runID, AgentID: definitionID, State: "queued", EvidenceIDs: []string{evidenceID}, DefinitionVersion: 3, Version: 1, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}}
	ids := []string{runID, auditID, receiptID}
	index := 0
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: func() (string, error) { value := ids[index]; index++; return value, nil }, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	request := workflowRequest(t, identity, correlationID, "runSecurityAgent", map[string]string{"id": definitionID}, http.MethodPost, "/api/v1/security-agents/"+definitionID+"/runs", `{"environment_id":"`+identity.Scope.EnvironmentID().String()+`","trigger_kind":"finding","trigger_id":"`+evidenceID+`"}`)
	request.Header.Set("Idempotency-Key", "run-security-agent-0001")
	request.Header.Set("If-Match", `"3"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != auditID || response.Header().Get("X-Mutation-Receipt-ID") != "" || stub.calls != 1 {
		t.Fatalf("run status=%d headers=%#v body=%s calls=%d", response.Code, response.Header(), response.Body.String(), stub.calls)
	}
	if stub.run.DefinitionID != definitionID || stub.run.ExpectedVersion != 3 || stub.run.RunID != runID || stub.run.TriggerKind != "finding" || stub.run.TriggerID != evidenceID || stub.run.ReceiptID != receiptID {
		t.Fatalf("run input=%#v", stub.run)
	}
}

func TestSecurityAgentPublicHandlerListsReadsAndCancelsTenantRuns(t *testing.T) {
	definitionID := "pid_78000001-0000-4000-8000-000000000001"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	approvalID := "pid_78000007-0000-4000-8000-000000000007"
	stepID := "pid_78000008-0000-4000-8000-000000000008"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	receiptID := "pid_78000003-0000-4000-8000-000000000003"
	correlationID := "pid_78000004-0000-4000-8000-000000000004"
	createdAt := time.Date(2026, 8, 21, 11, 59, 0, 123000, time.UTC)
	expiresAt := time.Date(2026, 8, 21, 12, 15, 0, 0, time.UTC)
	run := SecurityAgentRun{ID: runID, AgentID: definitionID, State: "waiting_approval", EvidenceIDs: []string{evidenceID}, DefinitionVersion: 3, Version: 4}
	approval := SecurityAgentApproval{ID: approvalID, RunID: runID, StepID: stepID, State: "pending", ExpiresAt: expiresAt, Version: 1, ExpectedEffect: "Move finding to under review", Reversible: true, EvidenceSummary: []string{evidenceID}}
	stub := &securityAgentPublicAuthorityStub{
		runs:      SecurityAgentRunPage{Items: []SecurityAgentRun{run}, NextCreatedAt: &createdAt, NextID: runID},
		runDetail: SecurityAgentRunDetail{Run: run, EvidenceIDs: []string{evidenceID}, Authorization: "not_planned", Approvals: []SecurityAgentApproval{}, Execution: []SecurityAgentExecutionStep{}, Verification: "not_started"},
		approvals: SecurityAgentApprovalPage{Items: []SecurityAgentApproval{approval}},
		approval:  approval,
		cancelled: SecurityAgentRunResult{ID: runID, AgentID: definitionID, State: "cancelled", EvidenceIDs: []string{evidenceID}, DefinitionVersion: 3, Version: 5, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID},
	}
	ids := []string{auditID, receiptID}
	index := 0
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: func() (string, error) { value := ids[index]; index++; return value, nil }, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := workflowRequest(t, identity, correlationID, "listSecurityAgentRuns", nil, http.MethodGet, "/api/v1/security-agent-runs?agent_id="+definitionID+"&status=waiting_approval&environment_id="+identity.Scope.EnvironmentID().String()+"&limit=25", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var page struct {
		Items      []SecurityAgentRun `json:"items"`
		NextCursor string             `json:"next_cursor"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != runID || page.NextCursor == "" || stub.runPage.DefinitionID != definitionID || stub.runPage.State != "waiting_approval" || stub.runPage.Limit != 25 {
		t.Fatalf("list status=%d body=%s input=%#v", response.Code, response.Body.String(), stub.runPage)
	}
	request = workflowRequest(t, identity, correlationID, "listSecurityAgentRuns", nil, http.MethodGet, "/api/v1/security-agent-runs?agent_id="+definitionID+"&status=waiting_approval&environment_id="+identity.Scope.EnvironmentID().String()+"&limit=25&cursor="+page.NextCursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.runPage.BeforeCreatedAt != createdAt || stub.runPage.BeforeID != runID {
		t.Fatalf("second page status=%d body=%s input=%#v", response.Code, response.Body.String(), stub.runPage)
	}
	request = workflowRequest(t, identity, correlationID, "getSecurityAgentRun", map[string]string{"id": runID}, http.MethodGet, "/api/v1/security-agent-runs/"+runID, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.runID != runID || !strings.Contains(response.Body.String(), `"authorization":"not_planned"`) {
		t.Fatalf("detail status=%d body=%s run=%s", response.Code, response.Body.String(), stub.runID)
	}
	request = workflowRequest(t, identity, correlationID, "listSecurityAgentApprovals", nil, http.MethodGet, "/api/v1/security-agent-approvals?state=pending&run_id="+runID+"&limit=25", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.approvalPage.State != "pending" || stub.approvalPage.RunID != runID || !strings.Contains(response.Body.String(), approvalID) {
		t.Fatalf("approvals status=%d body=%s input=%#v", response.Code, response.Body.String(), stub.approvalPage)
	}
	request = workflowRequest(t, identity, correlationID, "getSecurityAgentApproval", map[string]string{"id": approvalID}, http.MethodGet, "/api/v1/security-agent-approvals/"+approvalID, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.approvalID != approvalID || !strings.Contains(response.Body.String(), "Move finding to under review") {
		t.Fatalf("approval status=%d body=%s id=%s", response.Code, response.Body.String(), stub.approvalID)
	}
	request = workflowRequest(t, identity, correlationID, "cancelSecurityAgentRun", map[string]string{"id": runID}, http.MethodPost, "/api/v1/security-agent-runs/"+runID+"/cancel", "")
	request.Header.Set("Idempotency-Key", "cancel-agent-run-0001")
	request.Header.Set("If-Match", `"4"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"5"` || response.Header().Get("X-Mutation-Receipt-ID") != receiptID || stub.cancel.RunID != runID || stub.cancel.ExpectedVersion != 4 {
		t.Fatalf("cancel status=%d headers=%#v body=%s input=%#v", response.Code, response.Header(), response.Body.String(), stub.cancel)
	}
}

func TestSecurityAgentPublicHandlerApprovesWithFreshSeparateBrowserAuthority(t *testing.T) {
	approvalID := "pid_78000010-0000-4000-8000-000000000010"
	runID := "pid_78000006-0000-4000-8000-000000000006"
	stepID := "pid_78000007-0000-4000-8000-000000000007"
	auditID := "pid_78000002-0000-4000-8000-000000000002"
	receiptID := "pid_78000003-0000-4000-8000-000000000003"
	correlationID := "pid_78000004-0000-4000-8000-000000000004"
	evidenceID := "pid_78000005-0000-4000-8000-000000000005"
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	stub := &securityAgentPublicAuthorityStub{decided: SecurityAgentApprovalResult{ID: approvalID, RunID: runID, StepID: stepID, State: "approved", ExpiresAt: now.Add(10 * time.Minute), Version: 2, ExpectedEffect: "Move finding to under review", Reversible: true, EvidenceSummary: []string{evidenceID}, AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID}}
	ids := []string{auditID, receiptID}
	index := 0
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: func() (string, error) { value := ids[index]; index++; return value, nil }, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = now.Add(4 * time.Minute)
	request := workflowRequest(t, identity, correlationID, "decideSecurityAgentApproval", map[string]string{"id": approvalID}, http.MethodPost, "/api/v1/security-agent-approvals/"+approvalID+"/decision", `{"decision":"approved"}`)
	request.Header.Set("Idempotency-Key", "approve-security-agent-0001")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` || response.Header().Get("X-Mutation-Receipt-ID") != receiptID || stub.calls != 1 {
		t.Fatalf("approval status=%d headers=%#v body=%s calls=%d", response.Code, response.Header(), response.Body.String(), stub.calls)
	}
	if stub.decision.ApprovalID != approvalID || stub.decision.ExpectedVersion != 1 || stub.decision.Decision != "approved" || stub.decision.FreshAuthAt != now || stub.decision.ReceiptID != receiptID {
		t.Fatalf("approval input=%#v", stub.decision)
	}
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
		Clock:      func() time.Time { return now },
		SigningKey: securityAgentTestSigningKey,
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
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
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
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: func() (string, error) { value := ids[index]; index++; return value, nil }, SigningKey: securityAgentTestSigningKey})
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
