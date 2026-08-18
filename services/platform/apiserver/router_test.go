package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
		{name: "unsupported method", method: "POST", target: "/api/v1/agents/one", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
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
