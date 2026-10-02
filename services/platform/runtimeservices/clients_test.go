package runtimeservices

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercises our credential/pinned-model request and deadline, not FGA decisions.
func TestFGAReadinessUsesPinnedAuthority(t *testing.T) {
	values := localEnvironment()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("fixture-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	values["ZASP_OPENFGA_TOKEN_FILE"] = token
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer fixture-secret" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" {
			t.Error("wrong authority on model readiness request")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer server.Close()
	values["ZASP_OPENFGA_URL"] = server.URL
	c, err := Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	fga, transport, err := newFGA(c)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	clients := &Clients{config: c, FGA: fga, transport: transport}
	if err := clients.fgaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	status = http.StatusUnauthorized
	if err := clients.fgaReady(context.Background()); err == nil {
		t.Fatal("unauthenticated readiness accepted")
	}
}

func TestConnectUnavailableHasBoundedDeadline(t *testing.T) {
	values := localEnvironment()
	values["ZASP_RUNTIME_SERVICES_TIMEOUT"] = "100ms"
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("fixture-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	values["ZASP_OPENFGA_TOKEN_FILE"] = token
	c, err := Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalAddress = "127.0.0.1:1"
	start := time.Now()
	if clients, err := Connect(context.Background(), c); err == nil {
		clients.Close()
		t.Fatal("unavailable Temporal accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("connect exceeded application deadline")
	}
}
