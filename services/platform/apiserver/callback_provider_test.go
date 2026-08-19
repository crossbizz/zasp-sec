package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPCallbackProviderExchangesBoundedCodeWithoutRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer provider-secret" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request = %s %#v", request.Method, request.Header)
		}
		var input map[string]string
		if json.NewDecoder(request.Body).Decode(&input) != nil || input["authorization_code"] != "code" || input["state"] != "state" {
			t.Fatalf("input = %#v", input)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"principal_id": "pid_10000004-0000-4000-8000-000000000004", "organization_id": "pid_10000001-0000-4000-8000-000000000001",
			"workspace_id": "pid_10000002-0000-4000-8000-000000000002", "environment_id": "pid_10000003-0000-4000-8000-000000000003",
			"permissions": []string{"view"}, "expires_at": time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339),
		})
	}))
	defer server.Close()
	provider, err := NewHTTPCallbackProvider(server.URL, "provider-secret", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := provider.Complete(context.Background(), "code", "state")
	if err != nil || grant.PrincipalID.String() != "pid_10000004-0000-4000-8000-000000000004" || grant.Scope.OrganizationID().String() != "pid_10000001-0000-4000-8000-000000000001" || len(grant.Permissions) != 1 || grant.Permissions[0] != "view" {
		t.Fatalf("Complete() = (%#v, %v)", grant, err)
	}
}

func TestNewHTTPCallbackProviderRejectsMalformedURLWithoutPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("NewHTTPCallbackProvider panicked: %v", recovered)
		}
	}()
	if provider, err := NewHTTPCallbackProvider("%", "provider-secret", time.Second); provider != nil || err == nil {
		t.Fatalf("provider/error = (%#v, %v)", provider, err)
	}
}

func TestHTTPCallbackProviderFailsClosedOnProviderHTML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte("<html>secret</html>"))
	}))
	defer server.Close()
	provider, err := NewHTTPCallbackProvider(server.URL, "provider-secret", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Complete(context.Background(), "code", "state"); err == nil {
		t.Fatal("Complete() accepted HTML provider error")
	}
}

func TestHTTPCallbackProviderReadinessRequiresHealthyExactEndpoint(t *testing.T) {
	healthy := true
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead || request.Header.Get("Authorization") != "Bearer provider-secret" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if !healthy {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	provider, err := NewHTTPCallbackProvider(server.URL, "provider-secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Ready(context.Background()); err != nil {
		t.Fatalf("healthy readiness = %v", err)
	}
	healthy = false
	if err := provider.Ready(context.Background()); err == nil {
		t.Fatal("unhealthy provider remained ready")
	}
}
