package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectorRejectionClassification(t *testing.T) {
	for _, tc := range []struct {
		name, body, operation string
		want                  bool
	}{
		{"override", `{"connector_key":"github","name":"x","configuration":{"provider_url":"https://private.invalid"}}`, "createIntegration", true},
		{"webhook", `{"connector_key":"generic_webhook","name":"x","configuration":{"destination_url":"https://example.test"}}`, "createIntegration", false},
		{"malformed", `{"name":`, "createIntegration", false},
		{"wrong_type", `{"connector_key":"github","name":"x","configuration":{"provider_url":42}}`, "createIntegration", false},
		{"missing_name", `{"connector_key":"github","configuration":{"provider_url":"x"}}`, "createIntegration", false},
		{"other_operation", `{"connector_key":"github","name":"x","configuration":{"provider_url":"x"}}`, "createPolicy", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := json.RawMessage(`{"body":` + tc.body + `}`)
			if got := integrationAuthorityOverride(intent, tc.operation); got != tc.want {
				t.Fatalf("classification=%t want=%t", got, tc.want)
			}
		})
	}
}

type connectorRejectionAuditorStub struct {
	*workflowRepositoryStub
	err     error
	calls   int
	command IntegrationRejection
}

func (s *connectorRejectionAuditorStub) AuditIntegrationRejection(_ context.Context, _ RequestIdentity, c IntegrationRejection) error {
	s.calls++
	s.command = c
	return s.err
}

func TestConnectorRejectionHTTPBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		status  int
	}{
		{"commit", nil, 400}, {"authentication", ErrRepositoryAuthentication, 401}, {"authorization", ErrRepositoryAuthorization, 403}, {"target", ErrRepositoryNotFound, 404}, {"raw_database_error", errors.New("secret sql private.invalid"), 503}, {"other_typed_error", ErrRepositoryOperation, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			identity.Permissions = []string{"view", "manage_workflows"}
			repository := &connectorRejectionAuditorStub{workflowRepositoryStub: &workflowRepositoryStub{}, err: tc.failure}
			handler, _ := newWorkflowHTTPHandler(repository, []byte(strings.Repeat("k", 32)), nil)
			r := workflowRequest(t, identity, testCorrelationID, "createIntegration", nil, "POST", "/api/v1/integrations", "")
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-cookie"})
			w := httptest.NewRecorder()
			handler.writeIntegrationRejection(w, r, identity, RoutedOperation{OperationID: "createIntegration"}, json.RawMessage(`{"body":{"connector_key":"github","name":"secret name","configuration":{"provider_url":"https://private.invalid"}}}`), ErrRepositoryOperation)
			if w.Code != tc.status || repository.calls != 1 || strings.Contains(w.Body.String(), "private.invalid") || !validIntegrationRejection(identity, repository.command) {
				t.Fatalf("status=%d calls=%d body=%s command valid=%t", w.Code, repository.calls, w.Body, validIntegrationRejection(identity, repository.command))
			}
		})
	}
	t.Run("missing_auditor", func(t *testing.T) {
		identity := fixtureRequestIdentity(t)
		identity.CredentialKind = CredentialBrowserSession
		handler, _ := newWorkflowHTTPHandler(&workflowRepositoryStub{}, []byte(strings.Repeat("k", 32)), nil)
		r := httptest.NewRequest("POST", "/api/v1/integrations", nil)
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-cookie"})
		w := httptest.NewRecorder()
		handler.writeIntegrationRejection(w, r, identity, RoutedOperation{OperationID: "createIntegration"}, json.RawMessage(`{"body":{"connector_key":"github","name":"x","configuration":{"provider_url":"x"}}}`), ErrRepositoryOperation)
		if w.Code != 503 {
			t.Fatalf("missing capability status=%d", w.Code)
		}
	})
}
