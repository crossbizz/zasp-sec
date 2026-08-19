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

type administrationRecorder struct {
	reads     int
	mutations int
	last      administrationMutation
}

func (repository *administrationRecorder) ReadAdministration(_ context.Context, _ RequestIdentity, _ string, _ map[string]string) (json.RawMessage, error) {
	repository.reads++
	return json.RawMessage(`{"id":"pid_10000003-0000-4000-8000-000000000003","organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","name":"Production","environment_class":"production","version":1}`), nil
}

func (repository *administrationRecorder) MutateAdministration(_ context.Context, _ RequestIdentity, mutation administrationMutation) (json.RawMessage, error) {
	repository.mutations++
	repository.last = mutation
	return json.RawMessage(`{"id":"pid_11000005-0000-4000-8000-000000000005","name":"Automation","principal_id":"pid_10000004-0000-4000-8000-000000000004","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","permissions":["view"],"created_at":"2026-08-19T00:00:00Z","expires_at":"2026-08-20T00:00:00Z","last_used_at":null,"revoked_at":null,"version":1,"audit_correlation_id":"pid_31000003-0000-4000-8000-000000000003"}`), nil
}

func TestEnvironmentTargetsMustMatchTheActiveExactScopeBeforeRepositoryAccess(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	foreignWorkspace := "pid_20000002-0000-4000-8000-000000000002"
	foreignEnvironment := "pid_20000003-0000-4000-8000-000000000003"
	for _, test := range []struct {
		name, operation, method, target, body string
		parameters                            map[string]string
	}{
		{name: "create under sibling workspace", operation: "createEnvironment", method: http.MethodPost, target: "/api/v1/environments", body: `{"workspace_id":"` + foreignWorkspace + `","name":"Sibling"}`},
		{name: "get sibling environment", operation: "getEnvironment", method: http.MethodGet, target: "/api/v1/environments/" + foreignEnvironment, parameters: map[string]string{"id": foreignEnvironment}},
		{name: "update sibling environment", operation: "updateEnvironment", method: http.MethodPatch, target: "/api/v1/environments/" + foreignEnvironment, body: `{"name":"Sibling"}`, parameters: map[string]string{"id": foreignEnvironment}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &administrationRecorder{}
			handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if test.method == http.MethodPatch {
				request.Header.Set("If-Match", `"1"`)
			}
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			parameters := test.parameters
			if parameters == nil {
				parameters = map[string]string{}
			}
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: test.operation, PathParameters: parameters}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || repository.reads != 0 || repository.mutations != 0 {
				t.Fatalf("cross-scope target = %d reads=%d mutations=%d body=%s", response.Code, repository.reads, repository.mutations, response.Body.String())
			}
		})
	}
}

func TestCreateAPITokenReturnsOnlyDurableRevealGrantMetadata(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &administrationRecorder{}
	handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), tokenRevealKey: []byte("0123456789abcdef0123456789abcdef"), now: func() time.Time { return time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC) }}
	body := `{"name":"Automation","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","permissions":["view"],"expires_at":"2026-08-20T00:00:00Z"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/api-tokens", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-admin-token-0001")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "createAPIToken", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var value map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &value)
	if response.Code != http.StatusCreated || value["grant_id"] == nil || value["token"] == nil || value["raw_token"] != nil || strings.Contains(response.Body.String(), "zasp_pat_") {
		t.Fatalf("token create response = %d %s", response.Code, response.Body.String())
	}
}

func TestBootstrapPublishesExactFreshAuthenticationExpiry(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.FreshAuthExpiresAt = time.Date(2026, 8, 19, 0, 5, 0, 0, time.UTC)
	payload, err := authorizedBootstrap(json.RawMessage(`{"principal":{}}`), identity)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		FreshAuthExpiresAt string `json:"fresh_auth_expires_at"`
	}
	if json.Unmarshal(payload, &value) != nil || value.FreshAuthExpiresAt != "2026-08-19T00:05:00Z" {
		t.Fatalf("fresh-auth bootstrap = %s", payload)
	}
}

func TestConfiguredButUnverifiedIdentityProviderCannotMakeSystemHealthy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, fixtureRequestIdentity(t)))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "getSystemStatus", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	(&identityHTTPHandler{provider: CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return SessionGrant{}, nil }), now: func() time.Time { return time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC) }}).ServeHTTP(response, request)
	var value struct {
		Healthy  bool `json:"security_plane_healthy"`
		Degraded bool `json:"optional_degraded"`
	}
	if json.Unmarshal(response.Body.Bytes(), &value) != nil || response.Code != http.StatusOK || value.Healthy || !value.Degraded {
		t.Fatalf("configured-only provider health = %d %s", response.Code, response.Body.String())
	}
}
