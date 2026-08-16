package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteMainContainsConfigurationAtFixedOutputBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		arguments []string
		lookup    func(string) (string, bool)
	}{
		{arguments: []string{"proof", "unexpected"}, lookup: func(string) (string, bool) { return "", false }},
		{arguments: []string{"proof"}, lookup: func(string) (string, bool) { return "", false }},
		{arguments: []string{"proof"}, lookup: func(string) (string, bool) { return "http://127.0.0.1:9200/", true }},
	}
	for _, test := range tests {
		code, line := executeMain(test.arguments, test.lookup)
		if code != 1 || line != "OpenSearch event projection proof failed: configuration rejected." {
			t.Fatalf("executeMain returned code=%d unexpected fixed line", code)
		}
		if strings.Contains(line, "127.0.0.1") {
			t.Fatal("fixed failure output included configuration material")
		}
	}
}

func TestExecuteMainContainsProviderFailureAtFixedOutputBoundary(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("content-type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()
	code, line := executeMain([]string{"proof"}, func(name string) (string, bool) {
		if name == "OPENSEARCH_ENDPOINT" {
			return server.URL, true
		}
		return "", false
	})
	if code != 1 || line != "OpenSearch event projection proof failed: operation rejected." {
		t.Fatalf("executeMain returned code=%d unexpected fixed line", code)
	}
	if strings.Contains(line, server.URL) {
		t.Fatal("fixed failure output included provider configuration")
	}
}

func TestExecuteMainContainsEventStoreModeAtDistinctFixedOutputBoundary(t *testing.T) {
	t.Parallel()
	t.Run("configuration", func(t *testing.T) {
		code, line := executeMain([]string{"proof", "event-store"}, func(string) (string, bool) { return "", false })
		if code != 1 || line != "OpenSearch event store failed: configuration rejected." {
			t.Fatalf("executeMain returned code=%d line=%q", code, line)
		}
	})
	t.Run("provider", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("content-type", "application/json")
			_, _ = writer.Write([]byte(`{}`))
		}))
		defer server.Close()
		code, line := executeMain([]string{"proof", "event-store"}, func(name string) (string, bool) {
			if name == "OPENSEARCH_ENDPOINT" {
				return server.URL, true
			}
			return "", false
		})
		if code != 1 || line != "OpenSearch event store failed: operation rejected." {
			t.Fatalf("executeMain returned code=%d line=%q", code, line)
		}
		if strings.Contains(line, server.URL) {
			t.Fatal("event-store failure disclosed provider configuration")
		}
	})
	for _, arguments := range [][]string{{"proof", "Event-store"}, {"proof", "event-store", "extra"}} {
		if code, line := executeMain(arguments, func(string) (string, bool) { return "", false }); code != 1 || line != "OpenSearch event projection proof failed: configuration rejected." {
			t.Fatalf("invalid arguments %#v crossed the legacy fixed boundary: code=%d line=%q", arguments, code, line)
		}
	}
}
