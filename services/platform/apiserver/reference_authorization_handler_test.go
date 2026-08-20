package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type referenceAuthorizationAuthorityStub struct {
	replayed      bool
	replayResult  WorkflowMutationResult
	replayInput   ReferenceAuthorizationReplay
	completion    ReferenceAuthorizationCompletion
	completeCalls int
}

func (stub *referenceAuthorizationAuthorityStub) Replay(_ context.Context, _ RequestIdentity, input ReferenceAuthorizationReplay) (WorkflowMutationResult, bool, error) {
	stub.replayInput = input
	return stub.replayResult, stub.replayed, nil
}

func (stub *referenceAuthorizationAuthorityStub) Complete(_ context.Context, _ RequestIdentity, input ReferenceAuthorizationCompletion) (WorkflowMutationResult, error) {
	stub.completion = input
	stub.completeCalls++
	return WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"` + input.IntegrationID + `","connector_key":"` + input.Provider + `","status":"active"}`), Version: input.ExpectedVersion + 1}, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}, nil
}

type referenceProbeStub struct{ calls int }

func (stub *referenceProbeStub) ProbeReferenceAuthorization(context.Context, ReferenceAuthorizationTarget) error {
	stub.calls++
	return nil
}

func referenceWorkflowValue(id, provider, status string, version int64) WorkflowValue {
	configuration := `{"connection_reference":"ref:kubernetes/connection/customer-0001"}`
	if provider == "aws" {
		configuration = `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`
	}
	return WorkflowValue{Version: version, Body: json.RawMessage(`{"id":"` + id + `","connector_key":"` + provider + `","name":"Reference","configuration":` + configuration + `,"status":"` + status + `","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)}
}

func referenceAuthorizationRequest(t *testing.T, identity RequestIdentity, integrationID string, version int64, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/reference-authorization", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "reference-authorize-0001")
	request.Header.Set("If-Match", quoteVersion(version))
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	return request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "authorizeIntegrationReference", PathParameters: map[string]string{"id": integrationID}}))
}

func TestReferenceAuthorizationHandlerReplaysBeforeProbeAfterLostResponse(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	replay := WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"aws","status":"active"}`), Version: 2}, AuditID: "pid_74000006-0000-4000-8000-000000000006", CorrelationID: "pid_74000007-0000-4000-8000-000000000007", ReceiptID: "pid_74000008-0000-4000-8000-000000000008", Replayed: true}
	authority := &referenceAuthorizationAuthorityStub{replayed: true, replayResult: replay}
	probe := &referenceProbeStub{}
	registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": probe}, map[string]ConnectorCapabilityCheck{"aws": func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: authority, Workflows: connectorWorkflowStub{err: ErrRepositoryNotFound}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, referenceAuthorizationRequest(t, identity, integrationID, 1, `{}`))
	if response.Code != http.StatusOK || probe.calls != 0 || authority.completeCalls != 0 || response.Header().Get("ETag") != `"2"` || response.Header().Get("X-Mutation-Receipt-ID") != replay.ReceiptID {
		t.Fatalf("replay status=%d probe=%d complete=%d headers=%#v body=%s", response.Code, probe.calls, authority.completeCalls, response.Header(), response.Body.String())
	}
}

func TestReferenceAuthorizationHandlerProbesThenAtomicallyCompletes(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	authority := &referenceAuthorizationAuthorityStub{}
	probe := &referenceProbeStub{}
	registry, err := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"kubernetes": probe}, map[string]ConnectorCapabilityCheck{"kubernetes": func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: authority, Workflows: connectorWorkflowStub{value: referenceWorkflowValue(integrationID, "kubernetes", "pending_authorization", 3)}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, referenceAuthorizationRequest(t, identity, integrationID, 3, `{}`))
	if response.Code != http.StatusOK || probe.calls != 1 || authority.completeCalls != 1 || authority.completion.ConnectionReference != "ref:kubernetes/connection/customer-0001" || authority.completion.ExpectedVersion != 3 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("complete status=%d probe=%d completion=%#v headers=%#v body=%s", response.Code, probe.calls, authority.completion, response.Header(), response.Body.String())
	}
}

func TestReferenceAuthorizationHandlerRejectsHostileInputsWithoutProbe(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_74000001-0000-4000-8000-000000000001"
	for _, test := range []struct {
		name string
		edit func(*http.Request)
	}{
		{name: "non-empty body", edit: func(request *http.Request) { request.Body = http.NoBody }},
		{name: "missing if-match", edit: func(request *http.Request) { request.Header.Del("If-Match") }},
		{name: "bare if-match", edit: func(request *http.Request) { request.Header.Set("If-Match", "1") }},
		{name: "leading-zero if-match", edit: func(request *http.Request) { request.Header.Set("If-Match", `"01"`) }},
		{name: "signed if-match", edit: func(request *http.Request) { request.Header.Set("If-Match", `"+1"`) }},
		{name: "missing idempotency", edit: func(request *http.Request) { request.Header.Del("Idempotency-Key") }},
		{name: "missing fresh assertion", edit: func(request *http.Request) { request.Header.Del("X-Zasp-Fresh-Auth") }},
		{name: "duplicate fresh assertion", edit: func(request *http.Request) { request.Header.Add("X-Zasp-Fresh-Auth", "confirmed") }},
		{name: "wrong fresh assertion", edit: func(request *http.Request) { request.Header.Set("X-Zasp-Fresh-Auth", "true") }},
		{name: "null body", edit: func(request *http.Request) { request.Body = io.NopCloser(strings.NewReader("null")) }},
		{name: "not fresh", edit: func(request *http.Request) {
			stale := identity
			stale.FreshAuthenticated = false
			*request = *request.WithContext(context.WithValue(request.Context(), identityContextKey{}, stale))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &referenceAuthorizationAuthorityStub{}
			probe := &referenceProbeStub{}
			registry, _ := NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": probe}, map[string]ConnectorCapabilityCheck{"aws": func(context.Context) error { return nil }})
			handler, _ := NewReferenceAuthorizationHTTPHandler(ReferenceAuthorizationHTTPConfig{Repository: authority, Workflows: connectorWorkflowStub{value: referenceWorkflowValue(integrationID, "aws", "pending_authorization", 1)}, Registry: registry})
			request := referenceAuthorizationRequest(t, identity, integrationID, 1, `{}`)
			test.edit(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || probe.calls != 0 || authority.completeCalls != 0 {
				t.Fatalf("hostile status=%d probe=%d complete=%d body=%s", response.Code, probe.calls, authority.completeCalls, response.Body.String())
			}
		})
	}
}
