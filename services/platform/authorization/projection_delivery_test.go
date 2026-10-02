package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	fga "github.com/openfga/go-sdk/client"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Exercise our pinned, bounded delivery and recovery contract at the HTTP edge.
// A later batch failure must leave a staged inventory and no SQL acknowledgement.
func TestProjectionDelivery(t *testing.T) {
	calls := 0
	fail := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			ModelID string `json:"authorization_model_id"`
			Writes  struct {
				Tuples []json.RawMessage `json:"tuple_keys"`
			} `json:"writes"`
			Deletes struct {
				Tuples []json.RawMessage `json:"tuple_keys"`
			} `json:"deletes"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || r.URL.Path != "/stores/"+storeID+"/write" || body.ModelID != modelID || len(body.Writes.Tuples)+len(body.Deletes.Tuples) > 100 {
			t.Error("delivery escaped pin or batch bound")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if fail && calls > 1 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"code":"validation_error","message":"owned partial-batch fixture"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewOpenFGATupleWriter(client, testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := projectionFixture()
	for i := 0; i < 220; i++ {
		snapshot.Resources = append(snapshot.Resources, ProjectionResource{snapshot.Scopes[0], "finding", fmt.Sprintf("pid_79001000-0000-4000-8000-%012x", i)})
	}
	repository := &projectionStore{snapshot: snapshot}
	receipt, err := Reconcile(context.Background(), repository, writer, org, storeID, modelID)
	if err == nil || receipt.Applied || repository.acked || calls < 2 || len(repository.snapshot.Known) < 200 {
		t.Fatal("partial batch escaped durable pending state", receipt, err, calls)
	}
	fail = false
	receipt, err = Reconcile(context.Background(), repository, writer, org, storeID, modelID)
	if err != nil || !receipt.Applied || !repository.acked {
		t.Fatal("partial-batch current-state repair failed", receipt, err)
	}
	t.Logf("partial delivery failed closed then replayed staged inventory in bounded batches; HTTP calls=%d", calls)
}
