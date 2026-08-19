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

func TestRouterDispatchesOnlyExactOperations(t *testing.T) {
	called := ""
	router, err := NewRouter([]Operation{
		{Method: http.MethodGet, Pattern: "/api/v1/agents", Handler: namedHandler("agents", &called)},
		{Method: http.MethodGet, Pattern: "/api/v1/agents/{id}", Handler: namedHandler("agent", &called)},
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || called != "agent" {
		t.Fatalf("dispatch = (%d, %q), want (%d, agent)", response.Code, called, http.StatusNoContent)
	}
}

func TestRouterRejectsDuplicateAndMalformedOperations(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	tests := []struct {
		name       string
		operations []Operation
		want       error
	}{
		{name: "duplicate", operations: []Operation{{Method: "GET", Pattern: "/api/v1/agents", Handler: handler}, {Method: "GET", Pattern: "/api/v1/agents", Handler: handler}}, want: ErrDuplicateOperation},
		{name: "nil handler", operations: []Operation{{Method: "GET", Pattern: "/api/v1/agents"}}, want: ErrInvalidOperation},
		{name: "relative path", operations: []Operation{{Method: "GET", Pattern: "api/v1/agents", Handler: handler}}, want: ErrInvalidOperation},
		{name: "trailing slash", operations: []Operation{{Method: "GET", Pattern: "/api/v1/agents/", Handler: handler}}, want: ErrInvalidOperation},
		{name: "duplicate parameter", operations: []Operation{{Method: "GET", Pattern: "/api/v1/{id}/{id}", Handler: handler}}, want: ErrInvalidOperation},
		{name: "lowercase method", operations: []Operation{{Method: "get", Pattern: "/api/v1/agents", Handler: handler}}, want: ErrInvalidOperation},
		{name: "parameter name collision", operations: []Operation{{Method: "GET", Pattern: "/api/v1/agents/{id}", Handler: handler}, {Method: "GET", Pattern: "/api/v1/agents/{name}", Handler: handler}}, want: ErrDuplicateOperation},
		{name: "literal parameter ambiguity", operations: []Operation{{Method: "GET", Pattern: "/api/v1/agents/current", Handler: handler}, {Method: "GET", Pattern: "/api/v1/agents/{id}", Handler: handler}}, want: ErrDuplicateOperation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRouter(test.operations)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRouter() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRouterProvidesValidatedProductIDPathParametersAndOperation(t *testing.T) {
	var route RoutedOperation
	router, err := NewRouter([]Operation{{
		Method: "GET", Pattern: "/api/v1/agents/{id}", OperationID: "getAgent", Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			route, _ = RoutedOperationFromRequest(request)
			writer.WriteHeader(http.StatusNoContent)
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	validID := "pid_20000001-0000-4000-8000-000000000001"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+validID, nil))
	if response.Code != http.StatusNoContent || route.OperationID != "getAgent" || route.PathParameters["id"] != validID {
		t.Fatalf("route = (%d, %#v)", response.Code, route)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/agents/not-a-product-id", nil))
	if response.Code != http.StatusNotFound || decodeErrorCode(t, response) != "not_found" {
		t.Fatalf("invalid ProductID response = (%d, %s)", response.Code, response.Body.String())
	}
}

func TestRouterEnforcesExactOperationPermission(t *testing.T) {
	router, err := NewRouter([]Operation{{Method: "GET", Pattern: "/api/v1/agents", OperationID: "listAgents", Permission: "view", Handler: handlerResponse("agents")}})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		name        string
		permissions []string
		status      int
	}{
		{name: "authenticated without grant", status: http.StatusForbidden},
		{name: "exact grant", permissions: []string{"view"}, status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity.Permissions = test.permissions
			request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			if test.status == http.StatusForbidden && decodeErrorCode(t, response) != "request_forbidden" {
				t.Fatalf("forbidden body = %s", response.Body.String())
			}
		})
	}
}

func TestRouterRejectsWrongCredentialSchemeBeforeCSRFAndPermission(t *testing.T) {
	called := false
	router, err := NewRouter([]Operation{{Method: "POST", Pattern: "/api/v1/session/sign-out", OperationID: "signOutSession", Permission: "view", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })}})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.Permissions = nil
	identity.CredentialKind = CredentialBearerToken
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/sign-out", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || decodeErrorCode(t, response) != "authentication_required" || called {
		t.Fatalf("wrong scheme = (%d, %s, called=%v)", response.Code, response.Body.String(), called)
	}
}

func TestRouterAppliesBrowserCSRFOnlyAfterSchemeMatch(t *testing.T) {
	router, err := NewRouter([]Operation{{Method: "POST", Pattern: "/api/v1/session/sign-out", OperationID: "signOutSession", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, Handler: handlerResponse("ok")}})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/sign-out", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/sign-out", nil)
	request.Header.Set("Origin", "https://app.zasp.test")
	request.Header.Set("X-CSRF-Token", identity.CSRFToken)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid csrf status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestRouterRejectsStaleBrowserScopeBeforeScopedHandlerAccess(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	called := 0
	router, err := NewRouter([]Operation{{
		Method: http.MethodGet, Pattern: "/api/v1/policies", OperationID: "listPolicies",
		Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken},
		Handler:  http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { called++; writer.WriteHeader(http.StatusNoContent) }),
	}})
	if err != nil {
		t.Fatal(err)
	}
	expected := identity.Scope.OrganizationID().String() + "/" + identity.Scope.WorkspaceID().String() + "/" + identity.Scope.EnvironmentID().String()
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "duplicate", values: []string{expected, expected}},
		{name: "malformed", values: []string{"not/a/scope"}},
		{name: "noncanonical", values: []string{strings.ToUpper(expected)}},
		{name: "forged", values: []string{"pid_20000001-0000-4000-8000-000000000001/pid_20000002-0000-4000-8000-000000000002/pid_20000003-0000-4000-8000-000000000003"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			for _, value := range test.values {
				request.Header.Add("X-Zasp-Expected-Scope", value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			var envelope struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				Retryable bool   `json:"retryable"`
			}
			if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || response.Code != http.StatusConflict || envelope.Code != "scope_stale" || envelope.Message != "Session scope changed; rebootstrap required" || !envelope.Retryable || called != 0 {
				t.Fatalf("scope rejection = status %d envelope=%#v called=%d body=%s", response.Code, envelope, called, response.Body.String())
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	request.Header.Set("X-Zasp-Expected-Scope", expected)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("matching scope = status %d called=%d body=%s", response.Code, called, response.Body.String())
	}
}

func TestRouterScopeAssertionCoversSwitchAndIgnoresPATHeader(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	expected := identity.Scope.OrganizationID().String() + "/" + identity.Scope.WorkspaceID().String() + "/" + identity.Scope.EnvironmentID().String()
	called := 0
	router, err := NewRouter([]Operation{
		{Method: http.MethodPut, Pattern: "/api/v1/session/scope", OperationID: "switchSessionScope", Security: []CredentialKind{CredentialBrowserSession}, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { called++; writer.WriteHeader(http.StatusNoContent) })},
		{Method: http.MethodGet, Pattern: "/api/v1/session/bootstrap", OperationID: "bootstrapSession", Security: []CredentialKind{CredentialBrowserSession}, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { called++; writer.WriteHeader(http.StatusNoContent) })},
		{Method: http.MethodGet, Pattern: "/api/v1/policies", OperationID: "listPolicies", Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { called++; writer.WriteHeader(http.StatusNoContent) })},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPut, "/api/v1/session/scope", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || called != 0 {
		t.Fatalf("scope switch without assertion = %d called=%d", response.Code, called)
	}
	request = httptest.NewRequest(http.MethodPut, "/api/v1/session/scope", nil)
	request.Header.Set("X-Zasp-Expected-Scope", expected)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("scope switch with assertion = %d called=%d", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/session/bootstrap", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || called != 2 {
		t.Fatalf("bootstrap exemption = %d called=%d", response.Code, called)
	}

	identity.CredentialKind = CredentialBearerToken
	for _, value := range []string{"", "forged/browser/scope"} {
		request = httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
		if value != "" {
			request.Header.Set("X-Zasp-Expected-Scope", value)
		}
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		response = httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("PAT header %q = %d body=%s", value, response.Code, response.Body.String())
		}
	}
}

func TestRouterRequiresFreshBrowserAuthenticationForPrivilegedMutation(t *testing.T) {
	router, err := NewRouter([]Operation{{
		Method: http.MethodPatch, Pattern: "/api/v1/admin/members/{id}", OperationID: "updateMemberRole",
		Permission: "manage_identity", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true,
		RequireFreshAuth: true, Handler: handlerResponse("updated"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		fresh bool
		want  int
	}{
		{name: "stale", fresh: false, want: http.StatusForbidden},
		{name: "fresh", fresh: true, want: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			identity.Permissions = []string{"manage_identity"}
			identity.CredentialKind = CredentialBrowserSession
			identity.FreshAuthenticated = test.fresh
			request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/members/pid_20000001-0000-4000-8000-000000000001", strings.NewReader(`{"role":"read_only_viewer","expected_version":1}`))
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
			request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
			request.Header.Set("Origin", "https://app.zasp.test")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestRouterUsesFixedErrorsForUnknownRequests(t *testing.T) {
	router, err := NewRouter([]Operation{{Method: http.MethodGet, Pattern: "/api/v1/agents/{id}", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected handler call")
	})}})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}

	tests := []struct {
		name   string
		method string
		target string
		status int
		code   string
	}{
		{name: "unknown path", method: "GET", target: "/api/v1/tools", status: http.StatusNotFound, code: "not_found"},
		{name: "unsupported method", method: "POST", target: "/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
		{name: "trailing slash", method: "GET", target: "/api/v1/agents/one/", status: http.StatusNotFound, code: "not_found"},
		{name: "encoded slash", method: "GET", target: "/api/v1/agents/one%2Ftwo", status: http.StatusNotFound, code: "not_found"},
		{name: "encoded segment", method: "GET", target: "/api/v1/agents/%6fne", status: http.StatusNotFound, code: "not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(test.method, test.target, nil))
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
			}
			var envelope struct {
				Code          string `json:"code"`
				Message       string `json:"message"`
				CorrelationID string `json:"correlation_id"`
				Retryable     bool   `json:"retryable"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode error = %v", err)
			}
			if envelope.Code != test.code || envelope.Message == "" || envelope.CorrelationID == "" || envelope.Retryable {
				t.Fatalf("envelope = %#v", envelope)
			}
		})
	}
}

func namedHandler(name string, called *string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		*called = name
		writer.WriteHeader(http.StatusNoContent)
	})
}
