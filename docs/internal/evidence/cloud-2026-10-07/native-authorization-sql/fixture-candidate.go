package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func newAuthorizationProjectionFGA(t *testing.T, wrappers ...func(http.RoundTripper) http.RoundTripper) (*fga.OpenFgaClient, runtimeservices.Config) {
	t.Helper()
	pins, err := resolveAuthorizationProjectionCredentials(os.Getenv, legacyAuthorizationProjectionCredentials)
	if err != nil {
		t.Fatal(err)
	}
	token := pins.token
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	var roundTripper http.RoundTripper = transport
	for _, wrap := range wrappers {
		roundTripper = wrap(roundTripper)
	}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.url, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: roundTripper, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	if err != nil {
		t.Fatal("SDK initialization rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := client.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-p6-owned-projection"}).Execute()
	if err != nil {
		t.Fatal("owned store creation failed")
	}
	if client.SetStoreId(store.Id) != nil {
		t.Fatal("store pin rejected")
	}
	modelData, err := os.ReadFile("../authorization/model.json")
	if err != nil {
		t.Fatal(err)
	}
	var model fga.ClientWriteAuthorizationModelRequest
	if json.Unmarshal(modelData, &model) != nil {
		t.Fatal("model invalid")
	}
	written, err := client.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		t.Fatal("owned model publication rejected")
	}
	config := runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-test", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGAURL: pins.url, StoreID: store.Id, ModelID: written.AuthorizationModelId, FGATokenFile: pins.tokenFile, Timeout: 5 * time.Second}
	t.Logf("owned OpenFGA store=%s model=%s; active configuration unchanged", config.StoreID, config.ModelID)
	return client, config
}

func legacyAuthorizationProjectionCredentials() (authorizationProjectionCredentials, error) {
	data, err := exec.Command("docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		return authorizationProjectionCredentials{}, errors.New("retained local service unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		return authorizationProjectionCredentials{}, errors.New("local service inspection unavailable")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		return authorizationProjectionCredentials{}, errors.New("local credential unavailable")
	}

	return authorizationProjectionCredentials{url: "http://127.0.0.1:8088", token: token, tokenFile: "/test/in-memory-only"}, nil
}
