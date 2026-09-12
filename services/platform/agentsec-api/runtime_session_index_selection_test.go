package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPISessionIndexSelectionReachesSelectedProvider(t *testing.T) {
	for _, name := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", "zasp-runtime-sessions-v3", "*"} {
		t.Run(name, func(t *testing.T) {
			paths := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths <- r.URL.Path
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"error":"missing"}`))
			}))
			defer server.Close()
			config := fixtureRuntimeConfig()
			config.Environment = "test"
			config.PolicyHistoryEndpoint = server.URL
			config.RuntimeSessionIndex = name
			history, err := newProductionPolicyHistory(config)
			valid := name == "" || name == "zasp-runtime-sessions-v1" || name == "zasp-runtime-sessions-v2"
			if !valid {
				if err == nil || history != nil {
					t.Fatal("unknown index selection accepted", name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer history.Close()
			if history.sessionSearch.Ready(context.Background()) == nil {
				t.Fatal("missing selected index ready")
			}
			want := name
			if want == "" {
				want = "zasp-runtime-sessions-v1"
			}
			select {
			case path := <-paths:
				if path != "/"+want+"/_mapping" {
					t.Fatal("API selected wrong index", path, want)
				}
			default:
				t.Fatal("API did not query provider")
			}
		})
	}
}

func TestAPISessionIndexConfigurationRejectsUnknownGeneration(t *testing.T) {
	config := fixtureRuntimeConfig()
	config.RuntimeSessionIndex = "zasp-runtime-sessions-v3"
	if validRuntimeConfig(config) {
		t.Fatal("invalid session index configuration accepted")
	}
}
