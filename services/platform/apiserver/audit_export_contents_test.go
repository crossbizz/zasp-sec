package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func auditExportEmptyContentsFixture(t *testing.T) (*auditExportArtifactFixture, auditExportReadResult) {
	t.Helper()
	store, id, _ := auditExportArtifactFixtureForTest(t)
	_, database, _, _ := auditExportRepositoryFixture(t)
	var descriptor AuditExportDescriptor
	if err := json.Unmarshal(database.responses[postgresAuditExportCreateSQL], &descriptor); err != nil {
		t.Fatal(err)
	}
	binding := audit.ExportBinding{OrganizationID: descriptor.OrganizationID, WorkspaceID: descriptor.WorkspaceID, EnvironmentID: descriptor.EnvironmentID, ExportID: descriptor.ID, CaptureID: "pid_73000002-0000-4000-8000-000000000002"}
	manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest}
	body, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.object.Body = body
	store.object.Size = int64(len(body))
	store.object.SHA256 = sha256.Sum256(body)
	digest := hex.EncodeToString(store.object.SHA256[:])
	zero := int64(0)
	descriptor.Status = "ready"
	descriptor.EventCount = &zero
	descriptor.ChunkCount = &zero
	descriptor.ChunkBytes = &zero
	descriptor.CapturedAt = "2026-09-12T10:00:01.000000Z"
	descriptor.ManifestSHA256 = digest
	_, policy := auditExportPolicyFixture(t)
	return store, auditExportReadResult{export: descriptor, authority: &auditExportReadAuthority{StoragePolicy: policy, Binding: binding, Manifest: auditExportArtifactAuthority{ArtifactID: id, ObjectReference: store.reference, VersionID: store.object.VersionID, SHA256: digest, SizeBytes: store.object.Size}}}
}

func TestAuditExportContentsVerifiesEmptyManifest(t *testing.T) {
	store, result := auditExportEmptyContentsFixture(t)
	got, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || got == nil || got.manifest.Binding != result.authority.Binding || got.chunk != nil || got.chunkSHA256 != "" || store.gets != 1 {
		t.Fatal("empty export verification failed", err)
	}
}

func TestAuditExportContentsRejectsAuthorityMismatch(t *testing.T) {
	for _, kind := range []string{"binding", "descriptor digest", "descriptor count", "missing authority", "unexpected chunk", "corrupt bytes"} {
		t.Run(kind, func(t *testing.T) {
			store, result := auditExportEmptyContentsFixture(t)
			switch kind {
			case "binding":
				result.authority.Binding.ExportID = "pid_73000003-0000-4000-8000-000000000003"
			case "descriptor digest":
				result.export.ManifestSHA256 = audit.ExportZeroDigest
			case "descriptor count":
				one := int64(1)
				result.export.EventCount = &one
			case "missing authority":
				result.authority = nil
			case "unexpected chunk":
				result.authority.Chunk = &auditExportChunkAuthority{}
			case "corrupt bytes":
				store.object.Body[2] = 'X'
				store.object.SHA256 = sha256.Sum256(store.object.Body)
			}
			if _, err := verifyAuditExportContents(context.Background(), store, result); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("accepted inconsistent export", err)
			}
		})
	}
}

// Keep the interface expectation explicit: retrieval cannot Put or Delete.
var _ auditExportArtifactReader = (*auditExportArtifactFixture)(nil)

type auditExportContentsStore map[artifactstore.Locator]*auditExportArtifactFixture

func (store auditExportContentsStore) Get(ctx context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	if item := store[locator]; item != nil {
		return item.Get(ctx, locator)
	}
	return artifactstore.Artifact{}, ErrRepositoryUnavailable
}
func (store auditExportContentsStore) ObjectReference(locator artifactstore.Locator) (string, error) {
	if item := store[locator]; item != nil {
		return item.ObjectReference(locator)
	}
	return "", ErrRepositoryUnavailable
}

func auditExportPopulatedContentsFixture(t *testing.T) (auditExportContentsStore, auditExportReadResult) {
	t.Helper()
	manifestStore, result := auditExportEmptyContentsFixture(t)
	binding := result.authority.Binding
	event := audit.ExportEvent{Ordinal: 1, ID: "pid_73000004-0000-4000-8000-000000000004", OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, ActorID: "pid_73000005-0000-4000-8000-000000000005", Action: "policy.update", TargetID: "policy:fixture", Outcome: "succeeded", Metadata: map[string]string{}, OccurredAt: "2026-09-12T10:00:00.000000Z"}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 1, PreviousDigest: audit.ExportZeroDigest, Events: []audit.ExportEvent{event}}
	body, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := domain.ParseProductID("pid_73000006-0000-4000-8000-000000000006")
	ref, _ := domain.NewEvidenceRef(id)
	key, err := bucketlayout.ExportKey(manifestStore.object.Scope, id)
	if err != nil {
		t.Fatal(err)
	}
	chunkStore := &auditExportArtifactFixture{object: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: manifestStore.object.Scope, Reference: ref, VersionID: "chunk-version-1"}, Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body), MediaType: "application/json"}, reference: "s3://owned-export-fixture/" + key}
	chunkHash := hex.EncodeToString(chunkStore.object.SHA256[:])
	manifest := audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1, ChunkCount: 1, ChunkBytes: chunkStore.object.Size, ChainRoot: chunkHash}
	body, err = audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestStore.object.Body = body
	manifestStore.object.Size = int64(len(body))
	manifestStore.object.SHA256 = sha256.Sum256(body)
	result.authority.Manifest.SizeBytes = manifestStore.object.Size
	result.authority.Manifest.SHA256 = hex.EncodeToString(manifestStore.object.SHA256[:])
	result.export.ManifestSHA256 = result.authority.Manifest.SHA256
	one, total := int64(1), chunkStore.object.Size
	result.export.EventCount = &one
	result.export.ChunkCount = &one
	result.export.ChunkBytes = &total
	result.authority.Chunk = &auditExportChunkAuthority{auditExportArtifactAuthority: auditExportArtifactAuthority{ArtifactID: id.String(), ObjectReference: chunkStore.reference, VersionID: chunkStore.object.VersionID, SHA256: chunkHash, SizeBytes: chunkStore.object.Size}, Ordinal: 1, FirstEvent: 1, EventCount: 1, PreviousDigest: audit.ExportZeroDigest}
	return auditExportContentsStore{manifestStore.object.Locator: manifestStore, chunkStore.object.Locator: chunkStore}, result
}

func TestAuditExportContentsVerifiesActualChunk(t *testing.T) {
	store, result := auditExportPopulatedContentsFixture(t)
	got, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || got == nil || got.chunk == nil || len(got.chunk.Events) != 1 || got.chunk.Events[0].Action != "policy.update" || got.chunkSHA256 != result.authority.Chunk.SHA256 {
		t.Fatal("did not retrieve verified audit bytes", err)
	}
}

func TestAuditExportContentsSingleChunkMustMatchTotalBytes(t *testing.T) {
	store, result := auditExportPopulatedContentsFixture(t)
	for _, item := range store {
		if item.object.Reference.ArtifactID().String() != result.authority.Manifest.ArtifactID {
			continue
		}
		manifest, err := audit.DecodeExportManifest(item.object.Body)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ChunkBytes++
		body, err := audit.EncodeExportManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		item.object.Body = body
		item.object.Size = int64(len(body))
		item.object.SHA256 = sha256.Sum256(body)
		result.authority.Manifest.SizeBytes = item.object.Size
		result.authority.Manifest.SHA256 = hex.EncodeToString(item.object.SHA256[:])
		result.export.ManifestSHA256 = result.authority.Manifest.SHA256
		result.export.ChunkBytes = &manifest.ChunkBytes
	}
	if _, err := verifyAuditExportContents(context.Background(), store, result); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatal("single chunk did not match manifest total", err)
	}
}

func auditExportTwoChunkContentsFixture(t *testing.T) (auditExportContentsStore, auditExportReadResult, *auditExportChunkAuthority) {
	t.Helper()
	store, result := auditExportPopulatedContentsFixture(t)
	firstPin := *result.authority.Chunk
	var firstStore, manifestStore *auditExportArtifactFixture
	for _, item := range store {
		if item.object.Reference.ArtifactID().String() == firstPin.ArtifactID {
			firstStore = item
		} else {
			manifestStore = item
		}
	}
	chunk, err := audit.DecodeExportChunk(firstStore.object.Body)
	if err != nil {
		t.Fatal(err)
	}
	chunk.Ordinal = 2
	chunk.FirstEvent = 2
	chunk.PreviousDigest = firstPin.SHA256
	chunk.Events[0].Ordinal = 2
	chunk.Events[0].ID = "pid_73000007-0000-4000-8000-000000000007"
	chunk.Events[0].OccurredAt = "2026-09-12T09:59:59.000000Z"
	body, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := domain.ParseProductID("pid_73000008-0000-4000-8000-000000000008")
	ref, _ := domain.NewEvidenceRef(id)
	key, err := bucketlayout.ExportKey(firstStore.object.Scope, id)
	if err != nil {
		t.Fatal(err)
	}
	secondStore := &auditExportArtifactFixture{object: artifactstore.Artifact{Locator: artifactstore.Locator{Scope: firstStore.object.Scope, Reference: ref, VersionID: "chunk-version-2"}, MediaType: "application/json", Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body)}, reference: "s3://owned-export-fixture/" + key}
	store[secondStore.object.Locator] = secondStore
	digest := hex.EncodeToString(secondStore.object.SHA256[:])
	lastPin := &auditExportChunkAuthority{auditExportArtifactAuthority: auditExportArtifactAuthority{ArtifactID: id.String(), ObjectReference: secondStore.reference, VersionID: secondStore.object.VersionID, SHA256: digest, SizeBytes: secondStore.object.Size}, Ordinal: 2, FirstEvent: 2, EventCount: 1, PreviousDigest: firstPin.SHA256}
	manifest, err := audit.DecodeExportManifest(manifestStore.object.Body)
	if err != nil {
		t.Fatal(err)
	}
	manifest.EventCount = 2
	manifest.ChunkCount = 2
	manifest.ChunkBytes = firstPin.SizeBytes + lastPin.SizeBytes
	manifest.ChainRoot = digest
	rewriteAuditExportManifestFixture(t, manifestStore, &result, manifest)
	return store, result, lastPin
}

func rewriteAuditExportManifestFixture(t *testing.T, store *auditExportArtifactFixture, result *auditExportReadResult, manifest audit.ExportManifest) {
	t.Helper()
	body, err := audit.EncodeExportManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.object.Body = body
	store.object.Size = int64(len(body))
	store.object.SHA256 = sha256.Sum256(body)
	result.authority.Manifest.SHA256 = hex.EncodeToString(store.object.SHA256[:])
	result.authority.Manifest.SizeBytes = store.object.Size
	result.export.ManifestSHA256 = result.authority.Manifest.SHA256
	result.export.EventCount = &manifest.EventCount
	result.export.ChunkCount = &manifest.ChunkCount
	result.export.ChunkBytes = &manifest.ChunkBytes
}

func TestAuditExportContentsTraversesTwoChunks(t *testing.T) {
	store, result, last := auditExportTwoChunkContentsFixture(t)
	first, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || first.chunk == nil || first.chunk.Ordinal != 1 {
		t.Fatal("first chunk failed", err)
	}
	result.authority.Chunk = last
	second, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || second.chunk == nil || second.chunk.Ordinal != 2 || second.chunk.PreviousDigest != first.chunkSHA256 || second.manifest.ChainRoot != second.chunkSHA256 {
		t.Fatal("final chunk failed", err)
	}
}

func TestAuditExportContentsRejectsImpossibleRemainder(t *testing.T) {
	for _, kind := range []string{"remaining events", "remaining bytes", "prior events", "previous digest", "final root"} {
		t.Run(kind, func(t *testing.T) {
			store, result, last := auditExportTwoChunkContentsFixture(t)
			var manifestStore *auditExportArtifactFixture
			for _, item := range store {
				if item.object.Reference.ArtifactID().String() == result.authority.Manifest.ArtifactID {
					manifestStore = item
				}
			}
			manifest, err := audit.DecodeExportManifest(manifestStore.object.Body)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "remaining events":
				manifest.EventCount = 1002
			case "remaining bytes":
				manifest.ChunkBytes = result.authority.Chunk.SizeBytes + audit.ExportMaximumChunkBytes + 1
			case "prior events":
				manifest.EventCount = 1003
				last.FirstEvent = 1003
				result.authority.Chunk = last
			case "previous digest":
				last.PreviousDigest = manifest.ChainRoot
				result.authority.Chunk = last
			case "final root":
				manifest.ChainRoot = result.authority.Chunk.SHA256
				result.authority.Chunk = last
			}
			rewriteAuditExportManifestFixture(t, manifestStore, &result, manifest)
			if _, err := verifyAuditExportContents(context.Background(), store, result); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("accepted impossible remainder", err)
			}
		})
	}
}

func TestAuditExportContentsPendingDoesNotReadProvider(t *testing.T) {
	store, result := auditExportEmptyContentsFixture(t)
	_, database, _, _ := auditExportRepositoryFixture(t)
	// Decode into a fresh value: absent optional fields do not clear old Go fields.
	result.export = AuditExportDescriptor{}
	if err := json.Unmarshal(database.responses[postgresAuditExportCreateSQL], &result.export); err != nil {
		t.Fatal(err)
	}
	result.authority = nil
	if got, err := verifyAuditExportContents(context.Background(), store, result); err != nil || got != nil || store.gets != 0 || store.references != 0 {
		t.Fatal("pending export read provider", err)
	}
}
