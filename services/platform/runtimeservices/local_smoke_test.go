package runtimeservices

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/openfga/go-sdk"
	fga "github.com/openfga/go-sdk/client"
)

// Explicitly opt in against the disposable Compose stack. This provisions a
// connection fixture, not the product's authorization model (P5).
func TestLocalServiceConnectionSmoke(t *testing.T) {
	if os.Getenv("ZASP_LOCAL_RUNTIME_SMOKE") != "1" {
		t.Skip("requires disposable Temporal/OpenFGA Compose stack")
	}
	values := localEnvironment()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("local-openfga-smoke-only"), 0600); err != nil {
		t.Fatal(err)
	}
	values["ZASP_OPENFGA_TOKEN_FILE"] = token
	values["ZASP_RUNTIME_SERVICES_TIMEOUT"] = "5s"
	c, err := Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, transport, err := newFGA(c)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := bootstrap.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-p1-connection-smoke"}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.SetStoreId(store.Id); err != nil {
		t.Fatal(err)
	}
	model, err := bootstrap.WriteAuthorizationModel(ctx).Body(fga.ClientWriteAuthorizationModelRequest{SchemaVersion: "1.1", TypeDefinitions: []sdk.TypeDefinition{{Type: "connection_probe"}}}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	c.StoreID, c.ModelID = store.Id, model.AuthorizationModelId
	clients, err := Connect(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer clients.Close()
	t.Log("Temporal namespace and authenticated pinned OpenFGA model readiness passed")
}
