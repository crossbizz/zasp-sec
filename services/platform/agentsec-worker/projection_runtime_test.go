package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

func TestProjectionProcessorClaimsExactKindAndFinishesOnlyDurableDriverResult(t *testing.T) {
	t.Parallel()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	authority := &projectionAuthorityStub{
		leases: []apiserver.ProjectionWorkLease{{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
			SnapshotID: projectionID(4), Kind: "search", Version: "projection-v1", InputDigest: digest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		}},
		pages: projectionPages(t, scope, digest),
	}
	projector := &projectionProjectorStub{result: projectionDriverResult{Receipt: "opensearch:durable:receipt-0001", Digest: sha256.Sum256([]byte("driver-result"))}}
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: authority, Projector: projector, Kind: "search", WorkerID: "projection-search-01", LeaseSeconds: 30, BatchSize: 8,
		HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatalf("newProjectionProcessor() error = %v", err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if authority.claimKind != "search" || authority.claimWorker != "projection-search-01" || authority.claimLimit != 8 {
		t.Fatalf("claim = kind %q worker %q limit %d", authority.claimKind, authority.claimWorker, authority.claimLimit)
	}
	if len(projector.inputs) != 1 || projector.inputs[0].Kind != "search" || projector.inputs[0].SnapshotID != projectionID(4) || projector.inputs[0].InputDigest != digest || len(projector.inputs[0].Entities) != 2 || len(projector.inputs[0].Relationships) != 1 || len(projector.inputs[0].Evidence) != 1 {
		t.Fatalf("projector inputs = %#v", projector.inputs)
	}
	if len(authority.finished) != 1 {
		t.Fatalf("finish calls = %#v", authority.finished)
	}
	completion := authority.finished[0]
	if completion.Outcome != "succeeded" || completion.Kind != "search" || completion.DriverReceipt != projector.result.Receipt || !reflect.DeepEqual(completion.DriverDigest, projector.result.Digest[:]) || completion.LastError != "" {
		t.Fatalf("completion = %#v", completion)
	}
}

func TestProjectionProcessorRenewsLeaseDuringSlowDriverAndCancelsOnLeaseLoss(t *testing.T) {
	t.Parallel()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	authority := &projectionAuthorityStub{
		leases: []apiserver.ProjectionWorkLease{{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
			SnapshotID: projectionID(4), Kind: "graph", Version: "projection-v1", InputDigest: digest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		}},
		pages: projectionPages(t, scope, digest), heartbeatErr: errors.New("lease lost"),
	}
	projector := &projectionProjectorStub{blockUntilCanceled: true}
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: authority, Projector: projector, Kind: "graph", WorkerID: "projection-graph-01", LeaseSeconds: 30, BatchSize: 1,
		HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatalf("newProjectionProcessor() error = %v", err)
	}
	if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("RunOnce() error = %v, want errWorkerExecution", err)
	}
	if authority.heartbeats != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", authority.heartbeats)
	}
	if len(authority.finished) != 0 {
		t.Fatalf("lease-lost worker finalized = %#v", authority.finished)
	}
}

func TestProjectionProcessorKeepsLeaseAliveUntilDurableCompletion(t *testing.T) {
	t.Parallel()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	finishStarted := make(chan struct{})
	allowFinish := make(chan struct{})
	authority := &projectionAuthorityStub{
		leases: []apiserver.ProjectionWorkLease{{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
			SnapshotID: projectionID(4), Kind: "search", Version: "projection-v1", InputDigest: digest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		}},
		pages: projectionPages(t, scope, digest), finishStarted: finishStarted, allowFinish: allowFinish,
	}
	projector := &projectionProjectorStub{result: projectionDriverResult{Receipt: "opensearch:durable:receipt-0001", Digest: sha256.Sum256([]byte("driver-result"))}}
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: authority, Projector: projector, Kind: "search", WorkerID: "projection-search-01", LeaseSeconds: 30, BatchSize: 1,
		HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- processor.RunOnce(context.Background()) }()
	select {
	case <-finishStarted:
	case <-time.After(time.Second):
		t.Fatal("durable completion did not start")
	}
	deadline := time.Now().Add(time.Second)
	for authority.heartbeatCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if authority.heartbeatCount() == 0 {
		t.Fatal("lease heartbeat stopped before durable completion")
	}
	close(allowFinish)
	if err := <-result; err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
}

func TestProjectionCandidateBoundsMatchProductionCollectionBounds(t *testing.T) {
	t.Parallel()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	base := projectionCandidate{Scope: scope, Kind: "search", Generation: 1, InputDigest: digest}

	tooManyEntities := base
	tooManyEntities.Entities = make([]json.RawMessage, 1_001)
	if validProjectionCounts(tooManyEntities) {
		t.Fatal("accepted more entities than the production collector can project")
	}
	tooManyRelationships := base
	tooManyRelationships.Relationships = make([]json.RawMessage, 2_001)
	if validProjectionCounts(tooManyRelationships) {
		t.Fatal("accepted more relationships than the production collector can project")
	}
	tooMuchEvidence := base
	tooMuchEvidence.Evidence = make([]json.RawMessage, 1_001)
	if validProjectionCounts(tooMuchEvidence) {
		t.Fatal("accepted more evidence than the production collector can project")
	}
}

func TestProjectionProcessorDoesNotConstructRiskWorker(t *testing.T) {
	t.Parallel()
	if _, err := newProjectionProcessor(projectionProcessorConfig{Kind: "risk"}); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("newProjectionProcessor(risk) error = %v", err)
	}
}

func TestProjectionProcessorKeepsTransientPageReadRetryable(t *testing.T) {
	t.Parallel()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	authority := &projectionAuthorityStub{
		leases: []apiserver.ProjectionWorkLease{{
			OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
			SnapshotID: projectionID(4), Kind: "search", Version: "projection-v1", InputDigest: digest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
		}}, pageErr: apiserver.ErrRepositoryUnavailable,
	}
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: authority, Projector: &projectionProjectorStub{}, Kind: "search", WorkerID: "projection-search-01", LeaseSeconds: 30, BatchSize: 1,
		HeartbeatInterval: time.Second, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if len(authority.finished) != 1 || authority.finished[0].Outcome != "retryable" || authority.finished[0].LastError != "projection_unavailable" {
		t.Fatalf("completion = %#v", authority.finished)
	}
}

func TestSearchProjectionProjectorStrictlyMapsCanonicalEntities(t *testing.T) {
	t.Parallel()
	candidate := projectionCandidateFromPages(t, "search")
	store := &searchSnapshotStoreStub{result: inventorysearch.ApplyResult{
		SnapshotID: mustProjectionID(t, 4), Generation: candidate.Generation, InputDigest: candidate.InputDigest, ContentDigest: sha256.Sum256([]byte("search-content")),
	}}
	projector, err := newSearchProjectionProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := projector.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(store.inputs) != 1 || len(store.inputs[0].Documents) != 2 || store.inputs[0].Documents[0].EntityID.String() != projectionID(10) || !reflect.DeepEqual(store.inputs[0].Documents[0].Attributes, []inventorysearch.Attribute{{Name: "account_id", Value: "123456789012"}}) {
		t.Fatalf("search inputs = %#v", store.inputs)
	}
	if result.Digest != store.result.ContentDigest || result.Receipt != "opensearch:snapshot:"+projectionID(4)+":"+resultDigestHex(result.Digest) {
		t.Fatalf("result = %#v", result)
	}

	hostile := candidate
	hostile.Entities = cloneRawMessages(candidate.Entities)
	hostile.Entities[0] = json.RawMessage(`{"id":"` + projectionID(10) + `","kind":"aws_instance","source_native_id":"i-a","display_name":"A","stable_fields":{},"attributes":{},"credential":"escape"}`)
	if _, err := projector.Apply(context.Background(), hostile); !errors.Is(err, errWorkerExecution) || len(store.inputs) != 1 {
		t.Fatalf("hostile Apply() error=%v calls=%d", err, len(store.inputs))
	}
}

func TestGraphProjectionProjectorStrictlyMapsCompleteTopology(t *testing.T) {
	t.Parallel()
	candidate := projectionCandidateFromPages(t, "graph")
	store := &graphSnapshotStoreStub{result: graphstore.SnapshotApplyResult{
		SnapshotID: mustProjectionID(t, 4), Source: "aws", Generation: candidate.Generation, InputDigest: candidate.InputDigest, ContentDigest: sha256.Sum256([]byte("graph-content")),
	}}
	projector, err := newGraphProjectionProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := projector.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(store.inputs) != 1 || len(store.inputs[0].Projection.Nodes) != 2 || len(store.inputs[0].Projection.Edges) != 1 || store.inputs[0].Projection.Edges[0].SourceID.String() != projectionID(10) || store.inputs[0].Projection.Edges[0].TargetID.String() != projectionID(11) {
		t.Fatalf("graph inputs = %#v", store.inputs)
	}
	if result.Digest != store.result.ContentDigest || result.Receipt != "neo4j:snapshot:"+projectionID(4)+":"+resultDigestHex(result.Digest) {
		t.Fatalf("result = %#v", result)
	}

	hostile := candidate
	hostile.Relationships = cloneRawMessages(candidate.Relationships)
	hostile.Relationships[0] = json.RawMessage(`{"id":"` + projectionID(12) + `","kind":"contains","source_native_id":"rel-a","from_entity_id":"` + projectionID(10) + `","to_entity_id":"` + projectionID(99) + `","attributes":{}}`)
	if _, err := projector.Apply(context.Background(), hostile); !errors.Is(err, errWorkerExecution) || len(store.inputs) != 1 {
		t.Fatalf("dangling Apply() error=%v calls=%d", err, len(store.inputs))
	}
}

type projectionAuthorityStub struct {
	mu                     sync.Mutex
	leases                 []apiserver.ProjectionWorkLease
	pages                  map[string]apiserver.SnapshotProjectionPage
	heartbeatErr           error
	pageErr                error
	finishStarted          chan struct{}
	allowFinish            chan struct{}
	claimKind, claimWorker string
	claimLimit, heartbeats int
	finished               []apiserver.ProjectionWorkCompletion
}

func (stub *projectionAuthorityStub) ClaimProjectionWork(_ context.Context, kind, worker, _ string, _ int, limit int) ([]apiserver.ProjectionWorkLease, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.claimKind, stub.claimWorker, stub.claimLimit = kind, worker, limit
	return append([]apiserver.ProjectionWorkLease(nil), stub.leases...), nil
}

func (stub *projectionAuthorityStub) GetSnapshotProjectionPage(_ context.Context, _ domain.Scope, _ string, section, afterID string, _ int) (apiserver.SnapshotProjectionPage, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.pageErr != nil {
		return apiserver.SnapshotProjectionPage{}, stub.pageErr
	}
	page, ok := stub.pages[section+"/"+afterID]
	if !ok {
		return apiserver.SnapshotProjectionPage{}, errors.New("unexpected page")
	}
	return page, nil
}

func (stub *projectionAuthorityStub) HeartbeatProjectionWork(_ context.Context, _ domain.Scope, _ apiserver.ProjectionHeartbeat) (apiserver.LeaseHeartbeatResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.heartbeats++
	return apiserver.LeaseHeartbeatResult{}, stub.heartbeatErr
}

func (stub *projectionAuthorityStub) FinishProjectionWork(_ context.Context, _ domain.Scope, input apiserver.ProjectionWorkCompletion) (apiserver.WorkCompletionResult, error) {
	if stub.finishStarted != nil {
		select {
		case stub.finishStarted <- struct{}{}:
		default:
		}
	}
	if stub.allowFinish != nil {
		<-stub.allowFinish
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.finished = append(stub.finished, input)
	return apiserver.WorkCompletionResult{SnapshotID: input.SnapshotID, Kind: input.Kind, State: input.Outcome, Attempt: 1}, nil
}

func (stub *projectionAuthorityStub) heartbeatCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.heartbeats
}

type projectionProjectorStub struct {
	mu                 sync.Mutex
	inputs             []projectionCandidate
	result             projectionDriverResult
	err                error
	blockUntilCanceled bool
}

type searchSnapshotStoreStub struct {
	inputs []inventorysearch.Snapshot
	result inventorysearch.ApplyResult
	err    error
}

func (stub *searchSnapshotStoreStub) ApplySnapshot(_ context.Context, input inventorysearch.Snapshot) (inventorysearch.ApplyResult, error) {
	stub.inputs = append(stub.inputs, input)
	return stub.result, stub.err
}

type graphSnapshotStoreStub struct {
	inputs []graphstore.CompleteSnapshot
	result graphstore.SnapshotApplyResult
	err    error
}

func (stub *graphSnapshotStoreStub) ApplySnapshot(_ context.Context, input graphstore.CompleteSnapshot) (graphstore.SnapshotApplyResult, error) {
	stub.inputs = append(stub.inputs, input)
	return stub.result, stub.err
}

func (stub *projectionProjectorStub) Apply(ctx context.Context, input projectionCandidate) (projectionDriverResult, error) {
	stub.mu.Lock()
	stub.inputs = append(stub.inputs, input)
	stub.mu.Unlock()
	if stub.blockUntilCanceled {
		<-ctx.Done()
		return projectionDriverResult{}, ctx.Err()
	}
	return stub.result, stub.err
}

func projectionPages(t *testing.T, scope domain.Scope, digest [sha256.Size]byte) map[string]apiserver.SnapshotProjectionPage {
	t.Helper()
	base := apiserver.SnapshotProjectionPage{
		SnapshotID: projectionID(4), IntegrationID: projectionID(5), Source: "aws", Generation: 7, CandidateDigest: digest[:],
		ManifestReference: "s3://evidence-bucket/organizations/manifest.json", ManifestKey: "organizations/manifest-000000000000.json", ManifestVersionID: "version-1",
		ManifestChecksum: digest[:], ManifestSizeBytes: 4096, ManifestMediaType: "application/json", ManifestSchemaVersion: "manifest-v1", ParserVersion: "parser-v1", ToolVersion: "tool-v1",
	}
	entityA := json.RawMessage(`{"id":"` + projectionID(10) + `","kind":"aws_instance","source_native_id":"i-a","display_name":"A","stable_fields":{"account_id":"123456789012"},"attributes":{"region":"us-west-2"}}`)
	entityB := json.RawMessage(`{"id":"` + projectionID(11) + `","kind":"aws_instance","source_native_id":"i-b","display_name":"B","stable_fields":{"account_id":"123456789012"},"attributes":{"region":"us-west-2"}}`)
	relation := json.RawMessage(`{"id":"` + projectionID(12) + `","kind":"contains","source_native_id":"rel-a","from_entity_id":"` + projectionID(10) + `","to_entity_id":"` + projectionID(11) + `","attributes":{}}`)
	evidence := json.RawMessage(`{"id":"` + projectionID(13) + `","entity_id":"` + projectionID(10) + `","object_reference":"s3://evidence-bucket/organizations/raw.json","artifact_reference":"` + projectionID(14) + `","artifact_key":"organizations/raw-000000000000.json","artifact_version_id":"version-1","checksum_hex":"` + resultDigestHex(digest) + `","size_bytes":128,"media_type":"application/json","schema_version":"raw-v1","parser_version":"parser-v1","tool_version":"tool-v1"}`)
	entitiesFirst := base
	entitiesFirst.Section, entitiesFirst.Items = "entities", []json.RawMessage{entityA}
	next := projectionID(10)
	entitiesFirst.NextID = &next
	entitiesSecond := base
	entitiesSecond.Section, entitiesSecond.Items = "entities", []json.RawMessage{entityB}
	relationships := base
	relationships.Section, relationships.Items = "relationships", []json.RawMessage{relation}
	evidencePage := base
	evidencePage.Section, evidencePage.Items = "evidence", []json.RawMessage{evidence}
	return map[string]apiserver.SnapshotProjectionPage{
		"entities/": entitiesFirst, "entities/" + projectionID(10): entitiesSecond, "relationships/": relationships, "evidence/": evidencePage,
	}
}

func projectionCandidateFromPages(t *testing.T, kind string) projectionCandidate {
	t.Helper()
	scope := projectionTestScope(t)
	digest := sha256.Sum256([]byte("candidate"))
	pages := projectionPages(t, scope, digest)
	candidate := projectionCandidate{Scope: scope, SnapshotID: projectionID(4), Kind: kind, Version: "projection-v1", InputDigest: digest}
	for _, section := range []string{"entities", "relationships", "evidence"} {
		after := ""
		for {
			page := pages[section+"/"+after]
			if !bindProjectionPage(&candidate, page, section) {
				t.Fatalf("bindProjectionPage(%s, %q) rejected", section, after)
			}
			switch section {
			case "entities":
				candidate.Entities = append(candidate.Entities, page.Items...)
			case "relationships":
				candidate.Relationships = append(candidate.Relationships, page.Items...)
			case "evidence":
				candidate.Evidence = append(candidate.Evidence, page.Items...)
			}
			if page.NextID == nil {
				break
			}
			after = *page.NextID
		}
	}
	return candidate
}

func projectionTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(mustProjectionID(t, 1), mustProjectionID(t, 2), mustProjectionID(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func mustProjectionID(t *testing.T, suffix int) domain.ProductID {
	t.Helper()
	value, err := domain.ParseProductID(projectionID(suffix))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func projectionID(suffix int) string {
	return fmt.Sprintf("pid_10000000-0000-4000-8000-%012d", suffix)
}
