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

func TestAuthorizationOnlyConnectHasNoTemporalDependency(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" || r.Header.Get("Authorization") != "Bearer owned-fga-token" {
			t.Error("wrong pinned authorization request")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	if os.WriteFile(token, []byte("owned-fga-token"), 0400) != nil {
		t.Fatal("token")
	}
	c := Config{Enabled: true, Environment: "test", FGAURL: server.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: token, Timeout: time.Second}
	if c.Validate() == nil {
		t.Fatal("legacy full config was widened")
	}
	client, err := ConnectAuthorizationOnly(context.Background(), c)
	if err != nil {
		t.Fatal("FGA-only connect", err)
	}
	defer client.Close()
	if client.FGA == nil || client.Ready(context.Background()) != nil || calls != 2 {
		t.Fatal("actual pinned model readiness", calls)
	}
	for _, change := range []func(*Config){func(c *Config) { c.TemporalAddress = "localhost:7233" }, func(c *Config) { c.ModelID = "latest" }, func(c *Config) { c.Environment = "production" }, func(c *Config) { c.FGAURL = "https://public.example" }, func(c *Config) { c.FGATokenFile = "relative" }, func(c *Config) { c.Enabled = false }} {
		bad := c
		change(&bad)
		if _, err := ConnectAuthorizationOnly(context.Background(), bad); err == nil {
			t.Fatal("unsafe FGA-only config accepted")
		}
	}
	if calls != 2 {
		t.Fatal("invalid configuration performed IO", calls)
	}
}
