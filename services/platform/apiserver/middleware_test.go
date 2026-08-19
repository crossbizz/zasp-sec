package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductMiddlewareAuthenticatesCookieAndOwnsRequestIdentity(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	var observed RequestIdentity
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed, _ = IdentityFromRequest(request)
		if request.Header.Get("X-Zasp-Organization-ID") != "" || request.Header.Get("X-Zasp-Principal-ID") != "" {
			t.Fatal("forged browser identity headers reached product handler")
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := newTestMiddleware(t, next, func(_ context.Context, credential Credential) (RequestIdentity, error) {
		if credential.Kind != CredentialBrowserSession || credential.Value != "session-secret" {
			return RequestIdentity{}, errors.New("unexpected credential")
		}
		return identity, nil
	})

	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/agents", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: "session-secret"})
	request.Header.Set("X-Zasp-Organization-ID", "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	request.Header.Set("X-Zasp-Principal-ID", "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || observed.PrincipalID != identity.PrincipalID || observed.Scope != identity.Scope {
		t.Fatalf("response/identity = (%d, %#v), want (204, %#v)", response.Code, observed, identity)
	}
	if response.Header().Get("X-Correlation-ID") != testCorrelationID {
		t.Fatalf("correlation header = %q", response.Header().Get("X-Correlation-ID"))
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
}

func TestProductMiddlewareSeparatesAuthenticationAndBrowserMutationRejection(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	next, err := NewRouter([]Operation{{Method: http.MethodPost, Pattern: "/api/v1/session/sign-out", Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })}})
	if err != nil {
		t.Fatal(err)
	}
	authenticate := func(_ context.Context, credential Credential) (RequestIdentity, error) {
		if credential.Value == "expired" {
			return RequestIdentity{}, ErrAuthenticationRequired
		}
		return identity, nil
	}
	handler := newTestMiddleware(t, next, authenticate)

	tests := []struct {
		name   string
		cookie string
		origin string
		csrf   string
		status int
		code   string
	}{
		{name: "missing session", status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "expired session", cookie: "expired", status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "missing origin", cookie: "valid", csrf: identity.CSRFToken, status: http.StatusForbidden, code: "request_forbidden"},
		{name: "foreign origin", cookie: "valid", origin: "https://evil.example", csrf: identity.CSRFToken, status: http.StatusForbidden, code: "request_forbidden"},
		{name: "missing csrf", cookie: "valid", origin: "https://app.zasp.test", status: http.StatusForbidden, code: "request_forbidden"},
		{name: "wrong csrf", cookie: "valid", origin: "https://app.zasp.test", csrf: strings.Repeat("x", 32), status: http.StatusForbidden, code: "request_forbidden"},
		{name: "valid mutation", cookie: "valid", origin: "https://app.zasp.test", csrf: identity.CSRFToken, status: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/sign-out", nil)
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: test.cookie})
			}
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-CSRF-Token", test.csrf)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			if test.code != "" && decodeErrorCode(t, response) != test.code {
				t.Fatalf("code = %q, want %q", decodeErrorCode(t, response), test.code)
			}
		})
	}
}

func TestProductMiddlewareAcceptsBearerAutomationWithoutBrowserCSRF(t *testing.T) {
	handler := newTestMiddleware(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }), func(_ context.Context, credential Credential) (RequestIdentity, error) {
		if credential.Kind != CredentialBearerToken || credential.Value != "product-token" {
			return RequestIdentity{}, ErrAuthenticationRequired
		}
		return fixtureRequestIdentity(t), nil
	})
	request := httptest.NewRequest(http.MethodPatch, "https://app.zasp.test/api/v1/findings/id", strings.NewReader(`{"status":"resolved"}`))
	request.Header.Set("Authorization", "Bearer product-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
}

func TestProductMiddlewareEnforcesBodyAndPanicBoundaries(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	authenticate := func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }
	panicHandler := newTestMiddleware(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret") }), authenticate)

	tests := []struct {
		name        string
		contentType string
		body        string
		handler     http.Handler
		status      int
		code        string
	}{
		{name: "wrong content type", contentType: "text/plain", body: `{}`, handler: panicHandler, status: http.StatusUnsupportedMediaType, code: "unsupported_media_type"},
		{name: "oversized", contentType: "application/json", body: strings.Repeat("x", 65), handler: panicHandler, status: http.StatusRequestEntityTooLarge, code: "request_too_large"},
		{name: "panic contained", contentType: "application/json", body: `{}`, handler: panicHandler, status: http.StatusInternalServerError, code: "operation_rejected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPatch, "https://app.zasp.test/api/v1/findings/id", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer product-token")
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != test.status || decodeErrorCode(t, response) != test.code {
				t.Fatalf("response = (%d, %q), want (%d, %q)", response.Code, decodeErrorCode(t, response), test.status, test.code)
			}
		})
	}
}

func TestProductMiddlewareSuppliesCorrelationToRouterErrors(t *testing.T) {
	router, err := NewRouter([]Operation{{Method: "GET", Pattern: "/api/v1/agents", Handler: handlerResponse("ok")}})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestMiddleware(t, router, func(context.Context, Credential) (RequestIdentity, error) { return fixtureRequestIdentity(t), nil })
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/unknown", nil)
	request.Header.Set("Authorization", "Bearer product-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var envelope struct {
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.CorrelationID != testCorrelationID {
		t.Fatalf("correlation ID = %q, want %q", envelope.CorrelationID, testCorrelationID)
	}
}

const testCorrelationID = "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

func newTestMiddleware(t *testing.T, next http.Handler, authenticate Authenticator) http.Handler {
	t.Helper()
	handler, err := NewProductMiddleware(ProductSecurity{
		PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 64, Authenticate: authenticate,
		GenerateCorrelationID: func() string { return testCorrelationID },
	}, next)
	if err != nil {
		t.Fatalf("NewProductMiddleware() error = %v", err)
	}
	return handler
}

func fixtureRequestIdentity(t *testing.T) RequestIdentity {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_10000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_10000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000003")
	principal, _ := domain.ParseProductID("pid_10000004-0000-4000-8000-000000000004")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: []string{"view", "manage_findings"}, CSRFToken: strings.Repeat("c", 32), CredentialKind: CredentialBrowserSession, FreshAuthenticated: true}
}

func decodeErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (%q)", err, response.Body.String())
	}
	return envelope.Code
}
