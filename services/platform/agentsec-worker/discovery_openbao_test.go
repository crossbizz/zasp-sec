package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaokv"
)

func TestDiscoveryOpenBaoReadsOnlyTheConfiguredWorkloadPrefix(t *testing.T) {
	c := validProductionDiscoveryDependencyConfig(time.Now().UTC())
	dir := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("worker attempted write")
			w.WriteHeader(405)
			return
		}
		switch r.URL.Path {
		case "/v1/zasp-kv/config":
			fmt.Fprint(w, `{"data":{"max_versions":1}}`)
		case "/v1/zasp-kv/data/tenant-a/github/app-private-key-0001":
			fmt.Fprint(w, `{"data":{"data":{"value":"c2VjcmV0"},"metadata":{"version":2}}}`)
		default:
			t.Errorf("unscoped lookup %s", r.URL.Path)
			w.WriteHeader(403)
		}
	}))
	defer server.Close()
	cfg := openbaoclient.Config{Address: server.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca")}
	if err := os.WriteFile(cfg.TokenFile, []byte("worker-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c.Cloud.SecretRoot = "tenant-a"
	c.ConnectorSecrets = openbaokv.Config{Provider: openbaokv.Provider, Client: cfg, Mount: "zasp-kv"}
	reader, closeStore, err := newDiscoveryConnectorSecrets(nil, c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore()
	got, err := reader.ResolveDiscoverySecret(context.Background(), "ref:github/app-private-key-0001")
	if err != nil || string(got) != "secret" {
		t.Fatal("credential lookup failed", err)
	}
	for _, ref := range []string{"ref:github/../../tenant-b/other", "ref:%2e%2e/secret", "/tenant-b/secret"} {
		if _, err = reader.ResolveDiscoverySecret(context.Background(), ref); err == nil {
			t.Errorf("accepted reference %q", ref)
		}
	}
}
