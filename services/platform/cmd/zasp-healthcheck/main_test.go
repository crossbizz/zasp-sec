package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckAcceptsOnlyLoopbackHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "localhost", "127.0.0.1", 1) + "/healthz"
	if err := check(target); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{server.URL + "/readyz", "https://127.0.0.1:8081/healthz", "http://example.com:8081/healthz", "http://127.0.0.1:8081/healthz?secret=x"} {
		if err := check(hostile); err == nil {
			t.Fatalf("accepted %q", hostile)
		}
	}
}
