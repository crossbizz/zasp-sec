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
		_, _ = writer.Write([]byte(`{"session_token":"durable-session-token"}`))
	}))
	defer server.Close()
	provider, err := NewHTTPCallbackProvider(server.URL, "provider-secret", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.Complete(context.Background(), "code", "state")
	if err != nil || token != "durable-session-token" {
		t.Fatalf("Complete() = (%q, %v)", token, err)
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
