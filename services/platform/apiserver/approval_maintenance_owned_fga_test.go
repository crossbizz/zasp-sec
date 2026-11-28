package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/testopenfga"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

func newApprovalMaintenanceOwnedFGA(t *testing.T, wrappers ...func(http.RoundTripper) http.RoundTripper) (*fga.OpenFgaClient, runtimeservices.Config) {
	t.Helper()
	pins, err := resolveApprovalMaintenanceCredentials(os.Getenv, func() (approvalMaintenanceCredentials, error) {
		return approvalMaintenanceCredentials{}, errors.New("explicit owned OpenFGA fixture required")
	})
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
	store, err := client.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-approval-maintenance-owned-projection"}).Execute()
	if err != nil {
		t.Fatal("owned store creation failed")
	}
	if client.SetStoreId(store.Id) != nil {
		t.Fatal("store pin rejected")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := client.DeleteStore(cleanup).Execute(); err != nil {
			t.Error("owned fixture store cleanup refused")
		}
	})

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
	t.Log("owned OpenFGA fixture initialized; active configuration unchanged")
	return client, config
}

type approvalMaintenanceCredentials struct{ url, token, tokenFile string }

// Native selection is explicit: partial or refused native inputs never fall
// back to retained Docker discovery. These credentials belong to the owned
// test lifetime; selection alone is not SQL/API or native-runtime acceptance.
func resolveApprovalMaintenanceCredentials(getenv func(string) string, legacy func() (approvalMaintenanceCredentials, error)) (approvalMaintenanceCredentials, error) {
	refused := errors.New("native projection fixture credentials refused")
	if getenv == nil || legacy == nil {
		return approvalMaintenanceCredentials{}, refused
	}
	endpoint, path := getenv("ZASP_P6_NATIVE_OPENFGA_URL"), getenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE")
	if endpoint == "" && path == "" {
		return legacy()
	}
	token, err := testopenfga.ReadOwnedToken(endpoint, path)
	if err != nil {
		return approvalMaintenanceCredentials{}, err
	}
	return approvalMaintenanceCredentials{url: endpoint, token: token, tokenFile: path}, nil
}
