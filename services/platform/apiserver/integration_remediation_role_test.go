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

func TestIntegrationRemediationRoleRoutes(t *testing.T) {
	f := newSecondaryFixture(t)
	const integration, audit = "pid_80000001-0000-4000-8000-000000000001", "pid_80000002-0000-4000-8000-000000000002"
	const role = "arn:aws:iam::123456789012:role/zasp-remediation"
	serve := func(operation, method, body, payload string, headers map[string]string) (*httptest.ResponseRecorder, *completionTxFixture) {
		t.Helper()
		database, tx, _ := f.database(t, payload)
		repository := &DiscoveryRepository{database: database}
		handler := &discoveryPublicHTTPHandler{repository: repository, config: DiscoveryPublicHandlerConfig{NewProductID: func() (string, error) { return audit, nil }}}
		route := RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": integration}}
		ctx := context.WithValue(context.WithValue(f.request(t, route), identityContextKey{}, f.identity), routedOperationContextKey{}, route)
		request := httptest.NewRequest(method, "/api/v1/integrations/"+integration+"/remediation-role", strings.NewReader(body)).WithContext(ctx)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder, tx
	}
	configured := `{"integration_id":"` + integration + `","supported":true,"configured":true,"role_arn":"` + role + `","version":1,"updated_at":"2026-11-14T10:00:00.000000Z"}`
	unset := `{"integration_id":"` + integration + `","supported":true,"configured":false,"role_arn":null,"version":0,"updated_at":null}`

	response, tx := serve("getIntegrationRemediationRole", http.MethodGet, "", unset, nil)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"0"` || !strings.Contains(response.Body.String(), `"configured":false`) || len(tx.statements) != 1 || tx.statements[0] != currentIntegrationRemediationRoleSQL {
		t.Fatalf("get: status=%d body=%s statements=%v", response.Code, response.Body.String(), tx.statements)
	}
	headers := map[string]string{"Idempotency-Key": "remediation-role-0001", "If-Match": `"0"`}
	written := strings.TrimSuffix(configured, "}") + `,"audit_id":"` + audit + `","correlation_id":"` + fallbackCorrelationID + `"}`
	response, tx = serve("putIntegrationRemediationRole", http.MethodPut, `{"role_arn":"`+role+`"}`, written, headers)
	var value IntegrationRemediationRole
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != audit || json.Unmarshal(response.Body.Bytes(), &value) != nil || !value.Configured || *value.RoleARN != role || strings.Contains(response.Body.String(), "audit_id") {
		t.Fatalf("put: status=%d body=%s", response.Code, response.Body.String())
	}
	if len(tx.statements) != 1 || tx.statements[0] != currentIntegrationSetRemediationRoleSQL || tx.arguments[0][3] != f.identity.PrincipalID.String() || tx.arguments[0][4] != integration || tx.arguments[0][5] != role || tx.arguments[0][6] != int64(0) {
		t.Fatalf("statements=%v arguments=%v", tx.statements, tx.arguments)
	}
	for name, body := range map[string]string{
		"a role that is not an IAM role ARN": `{"role_arn":"zasp-remediation"}`,
		"a user ARN":                         `{"role_arn":"arn:aws:iam::123456789012:user/admin"}`,
		"no role member":                     `{}`,
		"a credential member":                `{"role_arn":"` + role + `","external_id":"secret"}`,
	} {
		if response, tx := serve("putIntegrationRemediationRole", http.MethodPut, body, written, headers); response.Code != http.StatusBadRequest || len(tx.statements) != 0 {
			t.Fatalf("%s: status=%d statements=%d", name, response.Code, len(tx.statements))
		}
	}
	// An answer for another role, or one that claims a role where none was asked for, is not served.
	for name, payload := range map[string]string{
		"another role":        strings.Replace(written, "zasp-remediation", "zasp-other", 1),
		"another integration": strings.Replace(written, integration, "pid_80000009-0000-4000-8000-000000000009", 1),
		"a stale version":     strings.Replace(written, `"version":1`, `"version":7`, 1),
	} {
		if response, _ := serve("putIntegrationRemediationRole", http.MethodPut, `{"role_arn":"`+role+`"}`, payload, headers); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status=%d", name, response.Code)
		}
	}
	// The statements are admitted only for their own operation and integration.
	grant, _ := requestAuthorizationFromContext(f.request(t, RoutedOperation{OperationID: "getIntegrationRemediationRole", PathParameters: map[string]string{"id": integration}}))
	scope := []any{f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String()}
	if handled, allowed := integrationRemediationRoleStatementAllowed(grant, currentIntegrationRemediationRoleSQL, append(append([]any(nil), scope...), integration)); !handled || !allowed {
		t.Fatalf("read: handled=%t allowed=%t", handled, allowed)
	}
	if handled, allowed := integrationRemediationRoleStatementAllowed(grant, currentIntegrationRemediationRoleSQL, append(append([]any(nil), scope...), "pid_80000009-0000-4000-8000-000000000009")); !handled || allowed {
		t.Fatalf("read of another integration: handled=%t allowed=%t", handled, allowed)
	}
	if handled, allowed := integrationRemediationRoleStatementAllowed(grant, currentIntegrationSetRemediationRoleSQL, append(append([]any(nil), scope...), f.identity.PrincipalID.String(), integration, role, int64(0), audit, fallbackCorrelationID)); !handled || allowed {
		t.Fatalf("a write under a read request: handled=%t allowed=%t", handled, allowed)
	}
}

func TestGuardrailDecisionNeedsATokenWhoseCeilingHasView(t *testing.T) {
	f := newSecondaryFixture(t)
	f.identity.CredentialKind, f.credential.Kind = CredentialBearerToken, CredentialBearerToken
	f.credential.PATCeiling = []string{"run_tests"}
	f.identity.credentialBinding = f.credential
	if _, err := f.authorizer.Authorize(context.Background(), f.identity, f.credential, RoutedOperation{OperationID: "createGuardrailDecision"}); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("a token without view was authorized for a decision: %v", err)
	}
	f.credential.PATCeiling = []string{"view"}
	f.identity.credentialBinding = f.credential
	if _, err := f.authorizer.Authorize(context.Background(), f.identity, f.credential, RoutedOperation{OperationID: "createGuardrailDecision"}); err != nil {
		t.Fatalf("a token with view was refused: %v", err)
	}
}
