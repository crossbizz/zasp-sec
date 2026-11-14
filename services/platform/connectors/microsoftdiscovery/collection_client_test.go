package microsoftdiscovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type microsoftSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *microsoftSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *microsoftSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *microsoftSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*microsoftSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://microsoft-discovery-evidence/" + locator.Key, nil
}

// The whole collection, driven by the shared collection client exactly as
// the worker drives it, ends in a typed snapshot and stores no token.
func TestMicrosoftCollectionClientCompletesATypedSnapshot(t *testing.T) {
	t.Parallel()
	api, roundTripper := newMicrosoftTestAPI(t,
		microsoftOK(microsoftTestOrganization),
		microsoftHTTPResponse{status: 403, body: `{}`},
		microsoftOK(`{"@odata.nextLink":"https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next","value":[{"id":"cccccccc-0000-4000-8000-000000000001","displayName":"ChatGPT Enterprise","accountEnabled":true,"servicePrincipalType":"Application"}]}`),
		microsoftOK(`{"value":[{"id":"cccccccc-0000-4000-8000-000000000002","displayName":"Contoso HR","accountEnabled":true,"servicePrincipalType":"Application"}]}`),
		microsoftOK(`{"value":[{"botid":"eeeeeeee-0000-4000-8000-000000000001","name":"Help desk","statecode":0,"authenticationmode":1}]}`),
	)
	driver := &microsoftSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewMicrosoftCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 6)
	for index := range ids {
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderMicrosoft, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialMicrosoftClient, CredentialReference: "ref:microsoft/connection/customer-0001", ExpectedSubject: microsoftTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, bytes.Clone(microsoftTestDataverseCredential))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	snapshot := complete.Snapshot()
	if roundTripper.calls() != 5 || len(driver.objects) != 6 || !snapshot.TypedObservations() || snapshot.EntityCount() != 3 || snapshot.RelationshipCount() != 2 || snapshot.EvidenceCount() != 3 {
		t.Fatalf("collection: calls=%d artifacts=%d entities=%d relationships=%d evidence=%d", roundTripper.calls(), len(driver.objects), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount())
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(microsoftTestGraphToken)) || bytes.Contains(object.Body, []byte(microsoftTestDataverseToken)) {
			t.Fatalf("artifact %s stores a token", key)
		}
	}
}
