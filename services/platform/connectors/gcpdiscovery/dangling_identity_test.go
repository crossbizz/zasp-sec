package gcpdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// droppingAPI is the collector with one entity removed from its pages: what
// a collection looks like when the page that owns an identity does not emit
// it.
type droppingAPI struct {
	*GCPCollectionAPI
	native string
}

func (api droppingAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	page, err := api.GCPCollectionAPI.FetchCollectionPage(ctx, credential, request)
	if err != nil {
		return page, err
	}
	kept := make([]json.RawMessage, 0, len(page.Entities))
	removed := ""
	for _, raw := range page.Entities {
		var entity gcpTestEntity
		_ = json.Unmarshal(raw, &entity)
		if entity.SourceNativeID == api.native {
			removed = entity.ID
			continue
		}
		kept = append(kept, raw)
	}
	relationships := make([]json.RawMessage, 0, len(page.Relationships))
	for _, raw := range page.Relationships {
		var relationship struct {
			Kind string `json:"kind"`
			To   string `json:"to_entity_id"`
		}
		_ = json.Unmarshal(raw, &relationship)
		// The containment of the removed entity goes with it; the
		// uses_identity relationship of another page stays, dangling.
		if removed != "" && relationship.To == removed && relationship.Kind == "contains" {
			continue
		}
		relationships = append(relationships, raw)
	}
	return NewGCPCollectionPage(request.Subject, page.Cursor, page.Complete, kept, relationships, page.Findings)
}

// collectGCPOrganization runs the test organization through the shared
// collection client with api in the collector's place.
func collectGCPOrganization(t *testing.T, wrap func(*GCPCollectionAPI) CollectionAPI) (collection.Outcome, error) {
	t.Helper()
	now := time.Now().UTC()
	fake := gcpTestOrganization(t, now)
	api, err := NewGCPCollectionAPI(CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	driver := &gcpSnapshotArtifacts{objects: map[string]artifactstore.DriverObject{}}
	artifacts, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewGCPCollectionClient(wrap(api), artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
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
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderGCP, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialGCPAccessToken, CredentialReference: "ref:gcp/workload-identity/acme-security/zasp-reader", ExpectedSubject: gcpTestSubject, ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 30 * time.Second}}
	return client.CollectWithCredential(context.Background(), request, bytes.Clone(gcpTestCredential))
}

// A uses_identity relationship whose identity no page emitted is refused by
// the collection: the whole snapshot fails as malformed. This is why the
// collector relates a workload to a service account only when it knows the
// identities pass of the same collection emitted that account.
func TestCollectionRejectsADanglingIdentityRelationship(t *testing.T) {
	outcome, err := collectGCPOrganization(t, func(api *GCPCollectionAPI) CollectionAPI {
		return droppingAPI{api, "gcp:service_account:shared-runner@gamma-shared.iam.gserviceaccount.com"}
	})
	var failure *collection.Failure
	if _, complete := outcome.(collection.CompleteResult); complete || !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
		t.Fatalf("a dangling identity relationship: outcome = %T, err = %v", outcome, err)
	}
}

// forgettingAPI is the collector in a process that does not remember what
// the identities pass emitted: a worker that restarted between the passes.
type forgettingAPI struct{ *GCPCollectionAPI }

func (api forgettingAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	api.emittedMutex.Lock()
	api.emitted = map[string]*gcpEmitted{}
	api.emittedMutex.Unlock()
	return api.GCPCollectionAPI.FetchCollectionPage(ctx, credential, request)
}

// Without that memory the collection still completes, with every entity
// and without any identity relationship: nothing dangles.
func TestCollectionWithoutIdentityMemoryRelatesNothing(t *testing.T) {
	outcome, err := collectGCPOrganization(t, func(api *GCPCollectionAPI) CollectionAPI { return forgettingAPI{api} })
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	var relationships []struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(complete.Snapshot().Relationships(), &relationships); err != nil {
		t.Fatal(err)
	}
	for _, relationship := range relationships {
		if relationship.Kind == "uses_identity" {
			t.Fatal("an identity relationship was emitted without knowing its identity is in the snapshot")
		}
	}
	if complete.Snapshot().EntityCount() != 33 {
		t.Fatalf("entities = %d", complete.Snapshot().EntityCount())
	}
}
