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
