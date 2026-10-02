package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func TestProductDiscoveryCollectorBindingAndOwnedBuffers(t *testing.T) {
	scope := workerScope(t)
	legacy := workerExecutionInput(scope, "pid_10000003-0000-4000-8000-000000000003")
	legacy.ObservationTime = time.Now().UTC().Truncate(time.Second)
	raw, _ := json.Marshal(legacy)
	var input apiserver.DiscoveryCollectionInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	input.EffectID = strings.Repeat("a", 64)
	input.Deadline = time.Now().UTC().Add(time.Minute)
	provider := &recordingJobProviderClient{outcome: workerCompleteOutcome(t, legacy)}
	credentials := &recordingJobCredentialMaterialResolver{credential: []byte("product-scoped-credential-material")}
	factory, err := newProductionDiscoveryCollectorFactory(testFirstPartyCollectionFactory(t, provider), credentials)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	revoked := false
	guard := func(context.Context) error {
		checks++
		if revoked {
			return errors.New("revoked")
		}
		return nil
	}
	expected, err := input.CollectionRequest(scope)
	if err != nil {
		t.Fatal(err)
	}
	provider.outcome, err = collection.NewPartialResult(expected, expected.ExpectedSubject, collection.Cursor{Provider: expected.Provider, Version: "cursor_v1", Value: "next"}, workerManifest(t, expected), collection.FailurePartial)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := factory.BuildProductDiscoveryCollector(context.Background(), scope, input, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = collector.Collect(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	if checks < 2 || provider.callCount() != 1 || credentials.callCount() != 1 {
		t.Fatal("product boundaries not used", checks, provider.callCount(), credentials.callCount())
	}
	if credentials.request().Product == nil || credentials.request().Product.EffectID != input.EffectID || credentials.request().WorkerID != "" || len(credentials.request().LeaseToken) != 0 {
		t.Fatal("product fell back to lease authority")
	}
	if _, err = collector.Collect(context.Background(), expected); err == nil {
		t.Fatal("effect collector reused")
	}
	collector, err = factory.BuildProductDiscoveryCollector(context.Background(), scope, input, guard)
	if err != nil {
		t.Fatal(err)
	}
	revoked = true
	if _, err = collector.Collect(context.Background(), expected); err == nil {
		t.Fatal("revoked effect collected")
	}
	if provider.callCount() != 1 || credentials.callCount() != 1 {
		t.Fatal("revoked product reached provider")
	}
	// Ownership is private: destroying an adapter must not clear the source SQL
	// input or another attempt's cursor/configuration buffers.
	before := string(input.Configuration)
	cloned := cloneDiscoveryCredentialMaterialRequest(discoveryCredentialMaterialRequest{Product: &input})
	destroyDiscoveryCredentialMaterialRequest(&cloned)
	if before == "" || string(input.Configuration) != before {
		t.Fatal("product input buffers aliased")
	}
	if cloned.Product != nil {
		t.Fatal("product retained after destroy")
	}
}
