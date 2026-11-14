package demodata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The versions a demo collection is stamped with. They are the values the
// reference deployments configure for their collectors.
const (
	CollectorVersion = "collector_v1"
	ParserVersion    = "parser_v1"
	ToolVersion      = "tool_v1"
)

// EvidenceBucket is the bucket name of the object references a demo
// snapshot carries. The raw pages of a demo collection are not stored
// anywhere: the reference keeps the shape the pipeline requires, and the
// evidence download of a demo entity answers that the object is missing.
const EvidenceBucket = "zasp-demo-evidence-not-stored"

// ErrCollection means the real collector did not complete on a fixture.
var ErrCollection = errors.New("demo collection did not complete")

// Target says where a collection's results belong.
type Target struct {
	Scope         domain.Scope
	IntegrationID domain.ProductID
	// ObservedAt is the collection time, in whole seconds, UTC.
	ObservedAt time.Time
	// Earlier selects the integration's earlier state (Integration.HasEarlier).
	Earlier bool
}

// Snapshot is a completed collection: what the pipeline applies.
type Snapshot struct {
	Provider          string
	ManifestReference string
	ManifestChecksum  [sha256.Size]byte
	CursorValue       string
	Entities          json.RawMessage
	Relationships     json.RawMessage
	Evidence          json.RawMessage
	// Unanswered lists the provider requests the fixture has no route for.
	// The collectors treat an absent API as "nothing there", so these are
	// not failures; the dataset test keeps the list reviewed.
	Unanswered []string
}

// memoryArtifacts keeps the raw pages of a collection in memory for the
// duration of the collection, which reads them back to build its manifest.
type memoryArtifacts struct {
	mutex   sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *memoryArtifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object.VersionID = "demo-" + hex.EncodeToString(object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *memoryArtifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, found := store.objects[locator.Key+"/"+locator.VersionID]
	if !found {
		return artifactstore.DriverObject{}, errors.New("demo artifact missing")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *memoryArtifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*memoryArtifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://" + EvidenceBucket + "/" + locator.Key, nil
}

func newArtifacts() (*artifactstore.Store, error) {
	return artifactstore.New(&memoryArtifacts{objects: map[string]artifactstore.DriverObject{}}, artifactstore.Config{OperationTimeout: 5 * time.Second, MaximumBytes: 64 << 20})
}

// derivedID is a product ID that depends only on the target and a label, so
// that a repeated collection of the same integration is the same request.
func derivedID(target Target, label string) domain.ProductID {
	digest := sha256.Sum256([]byte("zasp-demo\x1f" + target.Scope.OrganizationID().String() + "\x1f" + target.Scope.WorkspaceID().String() + "\x1f" + target.Scope.EnvironmentID().String() + "\x1f" + target.IntegrationID.String() + "\x1f" + label))
	text := hex.EncodeToString(digest[:])
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%s-%s-4%s-8%s-%s", text[:8], text[8:12], text[13:16], text[17:20], text[20:32]))
	if err != nil {
		panic("demodata: derived product ID: " + err.Error())
	}
	return id
}

func clock() time.Time { return time.Now().UTC() }

// request builds the collection request of an integration.
func request(integration Integration, target Target, provider collection.Provider, class collection.CredentialClass, reference, subjectKind string) (collection.Request, error) {
	built := collection.Request{
		Scope: target.Scope, IntegrationID: target.IntegrationID, ConnectionID: derivedID(target, "connection"), JobID: derivedID(target, "job"), Attempt: 1,
		Provider: provider, CollectorVersion: CollectorVersion, CredentialClass: class, CredentialReference: reference,
		ExpectedSubject: collection.SubjectBinding{Kind: subjectKind, ID: integration.Subject}, ParserVersion: ParserVersion, ToolVersion: ToolVersion,
		ObservationTime: target.ObservedAt, Bounds: collection.Bounds{MaxPages: 400, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 2 * time.Minute},
	}
	if err := built.Validate(); err != nil {
		return collection.Request{}, fmt.Errorf("%w: %s: the collection request is not valid", ErrCollection, integration.Key)
	}
	return built, nil
}

// finish turns the collection outcome into a Snapshot.
func finish(integration Integration, outcome collection.Outcome, err error, transport *replay) (Snapshot, error) {
	complete, isComplete := outcome.(collection.CompleteResult)
	if err != nil || !isComplete {
		detail := ""
		if transport != nil && len(transport.misses) > 0 {
			detail = fmt.Sprintf("; unanswered requests: %v", sortedKeys(transport.misses))
		}
		return Snapshot{}, fmt.Errorf("%w: %s: outcome %T, %v%s", ErrCollection, integration.Key, outcome, err, detail)
	}
	candidate := complete.Snapshot()
	if !candidate.TypedObservations() {
		return Snapshot{}, fmt.Errorf("%w: %s: the snapshot is not typed", ErrCollection, integration.Key)
	}
	manifest := complete.Manifest().Descriptor()
	snapshot := Snapshot{Provider: integration.Provider, ManifestReference: manifest.ObjectReference(), ManifestChecksum: manifest.Checksum(), CursorValue: complete.NextCursor().Value,
		Entities: candidate.Entities(), Relationships: candidate.Relationships(), Evidence: candidate.Evidence()}
	if transport != nil {
		snapshot.Unanswered = sortedKeys(transport.misses)
	}
	return snapshot, nil
}

// Collect runs the real collector of the integration's provider over the
// integration's fixture and returns the typed snapshot.
func Collect(ctx context.Context, integration Integration, target Target) (Snapshot, error) {
	if ctx == nil || target.Scope.Validate() != nil || target.IntegrationID.IsZero() || target.ObservedAt.IsZero() || !target.ObservedAt.Equal(target.ObservedAt.UTC().Truncate(time.Second)) {
		return Snapshot{}, fmt.Errorf("%w: %s: target", ErrCollection, integration.Key)
	}
	if target.Earlier && !integration.HasEarlier() {
		return Snapshot{}, fmt.Errorf("%w: %s has no earlier state", ErrCollection, integration.Key)
	}
	target.ObservedAt = target.ObservedAt.UTC()
	collector, known := collectors[integration.Provider]
	if !known {
		return Snapshot{}, fmt.Errorf("%w: %s: provider %q", ErrCollection, integration.Key, integration.Provider)
	}
	return collector(ctx, integration, target)
}

var collectors = map[string]func(context.Context, Integration, Target) (Snapshot, error){}
