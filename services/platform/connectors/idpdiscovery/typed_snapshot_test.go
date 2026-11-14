package idpdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// typedSnapshotArtifacts is an in-memory artifact driver for collections
// driven through the shared collection client.
type typedSnapshotArtifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *typedSnapshotArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *typedSnapshotArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *typedSnapshotArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*typedSnapshotArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://typed-snapshot-evidence/" + locator.Key, nil
}

func newTypedSnapshotArtifacts(t *testing.T) (*typedSnapshotArtifacts, artifactstore.ObjectReferencingArtifactStore) {
	t.Helper()
	driver := &typedSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return driver, artifacts
}

// typedSnapshotRequest is a typed collection request: its observation time is
// set, so a complete collection must end in a typed snapshot.
func typedSnapshotRequest(t *testing.T, provider collection.Provider, class collection.CredentialClass, reference string, subject collection.SubjectBinding) collection.Request {
	t.Helper()
	ids := make([]domain.ProductID, 6)
	for index := range ids {
		var err error
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: provider, CollectorVersion: "collector_v1", CredentialClass: class, CredentialReference: reference, ExpectedSubject: subject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 5 * time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	return request
}

type typedSnapshotEntity struct {
	ID                      string          `json:"id"`
	Kind                    string          `json:"kind"`
	SourceNativeID          string          `json:"source_native_id"`
	DisplayName             string          `json:"display_name"`
	StableFields            json.RawMessage `json:"stable_fields"`
	Attributes              json.RawMessage `json:"attributes"`
	IdentityNamespace       string          `json:"identity_namespace"`
	IdentityRuleVersion     int             `json:"identity_rule_version"`
	IdentityPriority        int             `json:"identity_priority"`
	ProductKind             string          `json:"product_kind"`
	ConfidenceBasisPoints   int             `json:"confidence_basis_points"`
	ObservedAt              string          `json:"observed_at"`
	FreshUntil              string          `json:"fresh_until"`
	EvidenceID              string          `json:"evidence_id"`
	SourceProjectionVersion int             `json:"source_projection_version"`
}

type typedSnapshotRelationship struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	SourceNativeID string          `json:"source_native_id"`
	FromEntityID   string          `json:"from_entity_id"`
	ToEntityID     string          `json:"to_entity_id"`
	Attributes     json.RawMessage `json:"attributes"`
}

// typedSnapshotEnvelope is the product kind and confidence the identity rule
// catalog assigns a source kind.
type typedSnapshotEnvelope struct {
	productKind string
	confidence  int
}

// requireTypedSnapshot decodes a complete outcome's snapshot and requires
// every entity to carry the typed envelope of its kind and canonical stable
// fields and attributes. It returns the entities by kind and the
// relationships.
func requireTypedSnapshot(t *testing.T, request collection.Request, outcome collection.Outcome, err error, want map[string]typedSnapshotEnvelope) (map[string][]typedSnapshotEntity, []typedSnapshotRelationship) {
	t.Helper()
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	snapshot := complete.Snapshot()
	var entities []typedSnapshotEntity
	var relationships []typedSnapshotRelationship
	if err := json.Unmarshal(snapshot.Entities(), &entities); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(snapshot.Relationships(), &relationships); err != nil {
		t.Fatal(err)
	}
	if request.ObservationTime.IsZero() || !snapshot.TypedObservations() || len(entities) == 0 || snapshot.EntityCount() != len(entities) || snapshot.RelationshipCount() != len(relationships) || snapshot.EvidenceCount() < len(entities) {
		t.Fatalf("snapshot typed=%t entities=%d relationships=%d evidence=%d", snapshot.TypedObservations(), snapshot.EntityCount(), snapshot.RelationshipCount(), snapshot.EvidenceCount())
	}
	byKind := map[string][]typedSnapshotEntity{}
	known := map[string]bool{}
	for _, entity := range entities {
		envelope, expected := want[entity.Kind]
		if !expected {
			t.Fatalf("unexpected kind in snapshot: %s", entity.Kind)
		}
		if entity.IdentityNamespace != entity.Kind || entity.ProductKind != envelope.productKind || entity.ConfidenceBasisPoints != envelope.confidence || entity.IdentityRuleVersion < 1 || entity.IdentityPriority < 1 || entity.SourceProjectionVersion < 1 ||
			entity.ObservedAt != request.ObservationTime.Format(time.RFC3339) || entity.FreshUntil <= entity.ObservedAt || entity.EvidenceID == "" {
			t.Fatalf("entity envelope = %+v", entity)
		}
		for name, raw := range map[string]json.RawMessage{"stable_fields": entity.StableFields, "attributes": entity.Attributes} {
			var decoded map[string]any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatalf("%s %s: %v", entity.Kind, name, err)
			}
			if canonical, err := json.Marshal(decoded); err != nil || !bytes.Equal(canonical, raw) {
				t.Fatalf("%s %s is not canonical: %s", entity.Kind, name, raw)
			}
		}
		byKind[entity.Kind] = append(byKind[entity.Kind], entity)
		known[entity.ID] = true
	}
	for kind := range want {
		if len(byKind[kind]) == 0 {
			t.Fatalf("snapshot has no %s: %s", kind, snapshot.Entities())
		}
	}
	for _, relationship := range relationships {
		if !known[relationship.FromEntityID] || !known[relationship.ToEntityID] {
			t.Fatalf("relationship endpoint missing from snapshot: %+v", relationship)
		}
	}
	return byKind, relationships
}

// typedSnapshotEdge reports whether the snapshot relates two entities.
func typedSnapshotEdge(relationships []typedSnapshotRelationship, kind, from, to string) bool {
	for _, relationship := range relationships {
		if relationship.Kind == kind && relationship.FromEntityID == from && relationship.ToEntityID == to {
			return true
		}
	}
	return false
}
