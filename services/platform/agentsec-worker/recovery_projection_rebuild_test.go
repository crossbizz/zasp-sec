package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recoveryProjectionDatabaseFake struct {
	payload json.RawMessage
	pages   map[string]apiserver.SnapshotProjectionPage
	calls   []string
}

func (fake *recoveryProjectionDatabaseFake) ValidateScope(context.Context, string, string, string) (json.RawMessage, error) {
	return append(json.RawMessage(nil), fake.payload...), nil
}

func (fake *recoveryProjectionDatabaseFake) ProjectionPage(_ context.Context, _, _, _, snapshotID, section, afterID string, limit int) (apiserver.SnapshotProjectionPage, error) {
	fake.calls = append(fake.calls, snapshotID+"/"+section+"/"+afterID)
	if limit != projectionPageSize {
		return apiserver.SnapshotProjectionPage{}, errors.New("unexpected page limit")
	}
	page, ok := fake.pages[section+"/"+afterID]
	if !ok || page.SnapshotID != snapshotID {
		return apiserver.SnapshotProjectionPage{}, errors.New("missing projection page")
	}
	return page, nil
}

func TestRecoveryProjectionJobsReplayEveryPinnedSnapshotIntoDurableDisposableTargets(t *testing.T) {
	scope := projectionTestScope(t)
	candidateDigest := sha256.Sum256([]byte("candidate"))
	pages := recoveryProjectionPages(t, scope, candidateDigest)
	graphDigest := recoveryExpectedGraphDigest(t, candidateDigest)
	searchDigest := recoveryExpectedSearchDigest(candidateDigest)
	projection := recoveryProjectionDescriptorFixture(t, candidateDigest, graphDigest, searchDigest)
	descriptorDigest := sha256.Sum256(projection)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	database := &recoveryProjectionDatabaseFake{
		payload: json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":` + string(projection) + `}`),
		pages:   pages,
	}
	var decoded []recoveryProjectionDescriptor
	if decodeStrictWorkerJSON(projection, &decoded) != nil || !validRecoveryProjectionDescriptors(decoded) {
		t.Fatalf("projection descriptor rejected: %s", projection)
	}
	targetDirectory := t.TempDir()
	base := recoveryJobConfig{
		PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7",
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		TargetEnvironment: "recovery-test", ProjectionSHA256: hex.EncodeToString(descriptorDigest[:]), EvidenceSampleSHA256: hex.EncodeToString(evidenceDigest[:]), TargetDirectory: targetDirectory,
	}
	graphCursor := decoded[0].ProjectionCursors[0]
	graphInput, found := recoveryProjectionInput(decoded[0].SnapshotInputs, graphCursor)
	if !found {
		t.Fatal("graph projection input missing")
	}
	loadedGraph, err := loadRecoveryProjectionCandidate(context.Background(), base, database, decoded[0].IntegrationID, graphCursor, graphInput)
	if err != nil {
		t.Fatalf("load graph candidate: %v", err)
	}
	graphTarget, err := newRecoveryProjectionTarget(targetDirectory, "graph")
	if err != nil {
		t.Fatalf("graph target: %v", err)
	}
	graphResult, err := graphTarget.Apply(context.Background(), loadedGraph)
	if err != nil || graphResult.Digest != graphDigest {
		t.Fatalf("graph apply digest=%x want=%x err=%v", graphResult.Digest, graphDigest, err)
	}
	database.calls = nil
	for _, kind := range []string{"graph", "search"} {
		config := base
		config.Mode = recoveryJobMode("recovery-" + kind + "-projection")
		if err := runRecoveryJob(context.Background(), config, database, &discardRecoveryJobOutput{}); err != nil {
			t.Fatalf("%s rebuild: %v", kind, err)
		}
	}
	if len(database.calls) != 8 {
		t.Fatalf("projection page calls=%v", database.calls)
	}
	entries, err := os.ReadDir(targetDirectory)
	if err != nil || len(entries) < 3 {
		t.Fatalf("durable target entries=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		info, statErr := entry.Info()
		if statErr != nil || info.Mode().Perm() != 0o600 || info.Size() < 2 || info.Size() > 8<<20 {
			t.Fatalf("target %q info=%#v err=%v", filepath.Join(targetDirectory, entry.Name()), info, statErr)
		}
	}
}

func TestRecoveryProjectionJobRejectsReceiptDigestDriftWithoutCreatingTarget(t *testing.T) {
	scope := projectionTestScope(t)
	candidateDigest := sha256.Sum256([]byte("candidate"))
	pages := recoveryProjectionPages(t, scope, candidateDigest)
	projection := recoveryProjectionDescriptorFixture(t, candidateDigest, sha256.Sum256([]byte("wrong-graph")), recoveryExpectedSearchDigest(candidateDigest))
	descriptorDigest := sha256.Sum256(projection)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	targetDirectory := t.TempDir()
	database := &recoveryProjectionDatabaseFake{payload: json.RawMessage(`{"counts":{"assets":3,"findings":2,"policies":1},"evidence_samples":[],"projection":` + string(projection) + `}`), pages: pages}
	config := recoveryJobConfig{Mode: recoveryJobModeGraphProjection, PostgresDSN: "postgres://recovery@ep-recovery.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", BranchIP: "10.24.8.7", OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), TargetEnvironment: "recovery-test", ProjectionSHA256: hex.EncodeToString(descriptorDigest[:]), EvidenceSampleSHA256: hex.EncodeToString(evidenceDigest[:]), TargetDirectory: targetDirectory}
	if err := runRecoveryJob(context.Background(), config, database, &discardRecoveryJobOutput{}); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("digest drift err=%v", err)
	}
}

type discardRecoveryJobOutput struct{}

func (*discardRecoveryJobOutput) Write(value []byte) (int, error) { return len(value), nil }

func recoveryProjectionDescriptorFixture(t *testing.T, inputDigest, graphDigest, searchDigest [sha256.Size]byte) json.RawMessage {
	t.Helper()
	input := map[string]any{
		"candidate_digest": hex.EncodeToString(inputDigest[:]), "generation": int64(7), "manifest_checksum": hex.EncodeToString(inputDigest[:]),
		"manifest_key": "organizations/manifest-000000000000.json", "manifest_media_type": "application/json", "manifest_reference": "s3://evidence-bucket/organizations/manifest.json",
		"manifest_schema_version": "manifest-v1", "manifest_size_bytes": int64(4096), "manifest_version_id": "version-1", "parser_version": "parser-v1",
		"snapshot_id": projectionID(4), "source": "aws", "tool_version": "tool-v1",
	}
	cursor := func(kind string, digest [sha256.Size]byte) map[string]any {
		return map[string]any{"driver_digest": hex.EncodeToString(digest[:]), "generation": int64(7), "input_digest": hex.EncodeToString(inputDigest[:]), "kind": kind, "snapshot_id": projectionID(4), "source": "aws", "updated_at": "2026-08-24T16:00:00Z"}
	}
	body, err := json.Marshal([]any{map[string]any{"collection_cursors": []any{}, "integration_id": projectionID(5), "projection_cursors": []any{cursor("graph", graphDigest), cursor("search", searchDigest)}, "snapshot_inputs": []any{input}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func recoveryExpectedGraphDigest(t *testing.T, inputDigest [sha256.Size]byte) [sha256.Size]byte {
	t.Helper()
	nodes := []recoveryGraphDigestNode{{id: projectionID(10), kind: "database"}, {id: projectionID(11), kind: "database"}}
	edges := []recoveryGraphDigestEdge{{id: projectionID(12), kind: "contains", source: projectionID(10), target: projectionID(11)}}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].id < nodes[right].id })
	sort.Slice(edges, func(left, right int) bool { return edges[left].id < edges[right].id })
	hasher := sha256.New()
	for _, value := range []string{"zasp.graph.complete-snapshot.v1", projectionID(1), projectionID(2), projectionID(3), projectionID(5), "aws", projectionID(4)} {
		recoveryWriteDigestString(hasher, value)
	}
	recoveryWriteDigestInt64(hasher, 7)
	recoveryWriteDigestBytes(hasher, inputDigest[:])
	recoveryWriteDigestInt64(hasher, int64(len(nodes)))
	for _, node := range nodes {
		recoveryWriteDigestString(hasher, node.id)
		recoveryWriteDigestString(hasher, node.kind)
	}
	recoveryWriteDigestInt64(hasher, int64(len(edges)))
	for _, edge := range edges {
		for _, value := range []string{edge.id, edge.kind, edge.source, edge.target} {
			recoveryWriteDigestString(hasher, value)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func recoveryExpectedSearchDigest(inputDigest [sha256.Size]byte) [sha256.Size]byte {
	hasher := sha256.New()
	for _, value := range []string{"zasp.inventory-search.complete-snapshot.v1", projectionID(1), projectionID(2), projectionID(3), projectionID(5), projectionID(4)} {
		recoveryWriteDigestString(hasher, value)
	}
	recoveryWriteDigestInt64(hasher, 7)
	recoveryWriteDigestBytes(hasher, inputDigest[:])
	recoveryWriteDigestInt64(hasher, 2)
	for _, entity := range []struct{ id, name string }{{projectionID(10), "A"}, {projectionID(11), "B"}} {
		for _, value := range []string{entity.id, "database", entity.name} {
			recoveryWriteDigestString(hasher, value)
		}
		recoveryWriteDigestInt64(hasher, 1)
		recoveryWriteDigestString(hasher, "engine")
		recoveryWriteDigestString(hasher, "postgres")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

type recoveryGraphDigestNode struct{ id, kind string }
type recoveryGraphDigestEdge struct{ id, kind, source, target string }

func recoveryProjectionPages(t *testing.T, scope domain.Scope, digest [sha256.Size]byte) map[string]apiserver.SnapshotProjectionPage {
	t.Helper()
	pages := projectionPages(t, scope, digest)
	first := pages["entities/"]
	first.Items = []json.RawMessage{json.RawMessage(`{"id":"` + projectionID(10) + `","kind":"database","source_native_id":"db-a","display_name":"A","stable_fields":{"engine":"postgres"},"attributes":{"region":"us-west-2"}}`)}
	pages["entities/"] = first
	second := pages["entities/"+projectionID(10)]
	second.Items = []json.RawMessage{json.RawMessage(`{"id":"` + projectionID(11) + `","kind":"database","source_native_id":"db-b","display_name":"B","stable_fields":{"engine":"postgres"},"attributes":{"region":"us-west-2"}}`)}
	pages["entities/"+projectionID(10)] = second
	return pages
}

func recoveryWriteDigestString(hasher hash.Hash, value string) {
	recoveryWriteDigestBytes(hasher, []byte(value))
}
func recoveryWriteDigestBytes(hasher hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write(value)
}
func recoveryWriteDigestInt64(hasher hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = hasher.Write(encoded[:])
}
