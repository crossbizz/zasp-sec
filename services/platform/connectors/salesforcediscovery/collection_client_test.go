package salesforcediscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type salesforceSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *salesforceSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *salesforceSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *salesforceSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*salesforceSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://salesforce-discovery-evidence/" + locator.Key, nil
}

// The whole collection, driven by the shared collection client exactly as
// the worker drives it, ends in a typed snapshot: every entity carries the
// identity rule's envelope and canonical stable fields and attributes.
func TestSalesforceCollectionClientCompletesATypedSnapshot(t *testing.T) {
	t.Parallel()
	api, roundTripper := newSalesforceTestAPI(t,
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceTestOrgBody},
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(false, "/services/data/v62.0/query/01g5g00000AbCdEAAV-2000",
			salesforceBotRecord(salesforceTestBotOne, "Support_Agent", "Support Agent", `,"Type":"Bot","AgentType":"EinsteinServiceAgent"`+salesforceActiveVersions),
			salesforceBotRecord(salesforceTestBotTwo, "Legacy_Bot", "", `,"Type":"Bot","AgentType":null,"BotVersions":null`))},
		salesforceHTTPResponse{status: http.StatusOK, body: salesforceQueryBody(true, "",
			salesforceBotRecord(salesforceTestBotThree, "Sales_Coach", "Sales Coach", `,"Type":null,"AgentType":null,"BotVersions":{"totalSize":0,"done":true,"records":[]}`))},
	)
	driver := &salesforceSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewSalesforceCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
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
	observed := time.Now().UTC().Truncate(time.Second)
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderSalesforce, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialSalesforceClient, CredentialReference: "ref:salesforce/connection/customer-0001", ExpectedSubject: salesforceTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: observed, Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, salesforceTestCredential(salesforceTestToken, salesforceTestHost))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	snapshot := complete.Snapshot()
	if roundTripper.calls() != 3 || len(driver.objects) != 4 || !snapshot.TypedObservations() || snapshot.EntityCount() != 4 || snapshot.RelationshipCount() != 3 || snapshot.EvidenceCount() != 4 {
		t.Fatalf("collection: calls=%d artifacts=%d entities=%d relationships=%d evidence=%d", roundTripper.calls(), len(driver.objects), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount())
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(salesforceTestToken)) {
			t.Fatalf("artifact %s stores a token", key)
		}
	}
	var entities []struct {
		ID                    string          `json:"id"`
		Kind                  string          `json:"kind"`
		StableFields          json.RawMessage `json:"stable_fields"`
		Attributes            json.RawMessage `json:"attributes"`
		IdentityNamespace     string          `json:"identity_namespace"`
		ProductKind           string          `json:"product_kind"`
		ConfidenceBasisPoints int             `json:"confidence_basis_points"`
		ObservedAt            string          `json:"observed_at"`
		EvidenceID            string          `json:"evidence_id"`
	}
	var relationships []struct {
		Kind         string `json:"kind"`
		FromEntityID string `json:"from_entity_id"`
		ToEntityID   string `json:"to_entity_id"`
	}
	if err := json.Unmarshal(snapshot.Entities(), &entities); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(snapshot.Relationships(), &relationships); err != nil {
		t.Fatal(err)
	}
	orgID := deterministicSalesforceInventoryID(salesforceTestSubject, "salesforce_org", salesforceTestOrgID)
	contained := map[string]bool{}
	for _, relationship := range relationships {
		if relationship.Kind != "contains" || relationship.FromEntityID != orgID {
			t.Fatalf("relationship = %+v", relationship)
		}
		contained[relationship.ToEntityID] = true
	}
	kinds := map[string]int{}
	for _, entity := range entities {
		kinds[entity.Kind]++
		wantProduct, wantConfidence := "asset", 9500
		if entity.Kind == "salesforce_agent" {
			wantProduct = "agent"
			if !contained[entity.ID] {
				t.Fatalf("agent %s has no org relationship", entity.ID)
			}
		}
		if entity.IdentityNamespace != entity.Kind || entity.ProductKind != wantProduct || entity.ConfidenceBasisPoints != wantConfidence || entity.ObservedAt != observed.Format(time.RFC3339) || entity.EvidenceID == "" {
			t.Fatalf("entity envelope = %+v", entity)
		}
		for name, raw := range map[string]json.RawMessage{"stable_fields": entity.StableFields, "attributes": entity.Attributes} {
			var decoded map[string]any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if canonical, err := json.Marshal(decoded); err != nil || !bytes.Equal(canonical, raw) {
				t.Fatalf("%s %s is not canonical: %s", entity.Kind, name, raw)
			}
		}
	}
	if kinds["salesforce_org"] != 1 || kinds["salesforce_agent"] != 3 || len(contained) != 3 {
		t.Fatalf("kinds = %v, contained = %v", kinds, contained)
	}
	if !bytes.Contains(snapshot.Entities(), []byte(`"attributes":{"agent_type":"EinsteinServiceAgent","discovery":{"method":"provider_api","platform":"agentforce","signals":[]},"posture":{`)) || !bytes.Contains(snapshot.Entities(), []byte(`"stable_fields":{"name":"Support Agent","object_type":"bot_definition","org":"`+salesforceTestOrgID+`"}`)) {
		t.Fatalf("agent attributes missing from snapshot: %s", snapshot.Entities())
	}
}
