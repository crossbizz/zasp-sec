package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaokv"
)

func TestRuntimeConnectorSecretsKeepAWSDefaultAndReadExpiredOAuthThroughKV(t *testing.T) {
	config := fixtureRuntimeConfig()
	if !validConnectorSecretAuthority(config) {
		t.Fatal("default KMS authority rejected")
	}
	dir := t.TempDir()
	state := strings.Repeat("s", 43)
	expired, err := json.Marshal(map[string]any{"state": state, "verifier": strings.Repeat("v", 43), "expires_at": time.Now().UTC().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const denied = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/connectors/config":
			fmt.Fprint(w, `{"data":{"max_versions":1}}`)
		case "/v1/connectors/data/zasp/oauth/" + denied:
			if r.Method != http.MethodPost {
				t.Error("retried refused create with read")
			}
			w.WriteHeader(http.StatusForbidden)
		case "/v1/connectors/data/zasp/oauth/" + id:
			if r.Method != http.MethodGet {
				t.Errorf("expired grant mutated with %s", r.Method)
				http.Error(w, "invalid", 400)
				return
			}
			fmt.Fprintf(w, `{"data":{"metadata":{"version":1},"data":{"value":%q}}}`, base64.StdEncoding.EncodeToString(expired))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	config.ConnectorSecrets = openbaokv.Config{Provider: openbaokv.Provider, Mount: "connectors", Client: openbaoclient.Config{Address: server.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca")}}
	if validConnectorSecretAuthority(config) {
		t.Fatal("accepted both KMS and KV authority")
	}
	config.ConnectorKMSKeyARN = ""
	for path, value := range map[string][]byte{config.ConnectorSecrets.Client.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), config.ConnectorSecrets.Client.TokenFile: []byte("scoped-token")} {
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	driver, closer, err := newRuntimeConnectorSecrets(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	store, err := driver.oauthStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if verifier, err := store.Consume(ctx, "ref:oauth/pkce/"+id); err != apiserver.ErrRepositoryUnavailable || len(verifier) != 0 {
		t.Fatalf("expired grant returned %d bytes, %v", len(verifier), err)
	}
	candidate := apiserver.OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43)), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if _, err := store.Acquire(ctx, "ref:oauth/pkce/"+denied, candidate, candidate.ExpiresAt); err != apiserver.ErrRepositoryUnavailable {
		t.Fatal("refused create did not fail closed", err)
	}

}

func TestConnectorAWSRollbackUsesOnlyTheSelectedDriver(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	values["ZASP_CONNECTOR_SECRETS_PROVIDER"] = "aws-secrets-manager"
	values["ZASP_OPENBAO_KV_MOUNT"] = "stale-mount"
	// A recovery signer on the same deployment may retain its own OpenBao configuration.
	values["ZASP_OPENBAO_ADDR"] = "https://localhost:1"
	values["ZASP_OPENBAO_TOKEN_FILE"] = "/absent/bao-token"
	get := func(k string) string { return values[k] }
	if _, err := loadRuntimeConfig(get); err == nil {
		t.Fatal("ambiguous rollback with stale connector mount accepted")
	}
	delete(values, "ZASP_OPENBAO_KV_MOUNT")
	config, err := loadRuntimeConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	driver, closer, err := newRuntimeConnectorSecrets(context.Background(), config)
	if err != nil {
		t.Fatal("AWS rollback depended on unavailable OpenBao", err)
	}
	defer closer.Close()
	if resource, ok := closer.(transportCloser); !ok || resource.transport == nil {
		t.Fatal("AWS transport is not owned by the runtime")
	}
	if _, ok := driver.(*connectorSecretsDriver); !ok {
		t.Fatal("AWS rollback selected another provider")
	}
}

func TestCheckConfigReadsExplicitStartupProjectionWithoutDisclosure(t *testing.T) {
	values := fixtureRuntimeEnvironment()
	path := filepath.Join(t.TempDir(), "stytch-secret")
	value := values["ZASP_STYTCH_SECRET"]
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	delete(values, "ZASP_STYTCH_SECRET")
	values["ZASP_STYTCH_SECRET_FILE"] = path
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	var output strings.Builder
	_, err := runConfigurationCommand([]string{"--check-config"}, lookup, &output)
	if err != nil || output.String() != configurationCheckAccepted {
		t.Fatal("private projection not accepted", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	_, err = runConfigurationCommand([]string{"--check-config"}, lookup, &output)
	if err == nil || output.String() != configurationCheckRefused || strings.Contains(output.String(), value) {
		t.Fatal("unsafe projection accepted or leaked")
	}
}
