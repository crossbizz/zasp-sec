package apiserver

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type auditExportVerifiedContents struct {
	manifest    audit.ExportManifest
	chunk       *audit.ExportChunk
	chunkSHA256 string
}

func verifyAuditExportContents(ctx context.Context, store auditExportArtifactReader, result auditExportReadResult) (*auditExportVerifiedContents, error) {
	if ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result.export)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	descriptor, err := decodeAuditExportDescriptor(encoded)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	if descriptor.Status != "ready" {
		if result.authority != nil {
			return nil, ErrRepositoryUnavailable
		}
		return nil, nil
	}
	if result.authority == nil {
		return nil, ErrRepositoryUnavailable
	}
	authority := result.authority
	binding := authority.Binding
	if binding.OrganizationID != descriptor.OrganizationID || binding.WorkspaceID != descriptor.WorkspaceID || binding.EnvironmentID != descriptor.EnvironmentID || binding.ExportID != descriptor.ID || authority.Manifest.SHA256 != descriptor.ManifestSHA256 {
		return nil, ErrRepositoryUnavailable
	}
	org, e1 := domain.ParseProductID(binding.OrganizationID)
	workspace, e2 := domain.ParseProductID(binding.WorkspaceID)
	environment, e3 := domain.ParseProductID(binding.EnvironmentID)
	scope, e4 := domain.NewScope(org, workspace, environment)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return nil, ErrRepositoryUnavailable
	}
	pin := authority.Manifest
	body, err := readAuditExportArtifact(ctx, store, scope, pin.ArtifactID, pin.ObjectReference, pin.VersionID, pin.SHA256, pin.SizeBytes, 2048)
	if err != nil {
		return nil, err
	}
	manifest, err := audit.DecodeExportManifest(body)
	if err != nil || manifest.Binding != binding || manifest.EventCount != *descriptor.EventCount || manifest.ChunkCount != *descriptor.ChunkCount || manifest.ChunkBytes != *descriptor.ChunkBytes {
		return nil, ErrRepositoryUnavailable
	}
	if manifest.EventCount == 0 && authority.Chunk == nil {
		return &auditExportVerifiedContents{manifest: manifest}, nil
	}
	if manifest.EventCount == 0 || authority.Chunk == nil {
		return nil, ErrRepositoryUnavailable
	}
	chunkPin := authority.Chunk
	if manifest.ChunkCount == 1 && chunkPin.SizeBytes != manifest.ChunkBytes {
		return nil, ErrRepositoryUnavailable
	}
	if chunkPin.Ordinal < 1 || chunkPin.Ordinal > manifest.ChunkCount || chunkPin.FirstEvent < 1 || chunkPin.EventCount < 1 || chunkPin.EventCount > audit.ExportMaximumChunkEvents || chunkPin.FirstEvent > manifest.EventCount-chunkPin.EventCount+1 || chunkPin.SizeBytes > manifest.ChunkBytes {
		return nil, ErrRepositoryUnavailable
	}
	before, after := chunkPin.FirstEvent-1, manifest.EventCount-(chunkPin.FirstEvent-1)-chunkPin.EventCount
	if !auditExportCountFitsChunks(before, chunkPin.Ordinal-1, audit.ExportMaximumChunkEvents) || !auditExportCountFitsChunks(after, manifest.ChunkCount-chunkPin.Ordinal, audit.ExportMaximumChunkEvents) || !auditExportCountFitsChunks(manifest.ChunkBytes-chunkPin.SizeBytes, manifest.ChunkCount-1, audit.ExportMaximumChunkBytes) {
		return nil, ErrRepositoryUnavailable
	}
	final := chunkPin.Ordinal == manifest.ChunkCount
	if final && (chunkPin.FirstEvent+chunkPin.EventCount-1 != manifest.EventCount || chunkPin.SHA256 != manifest.ChainRoot) {
		return nil, ErrRepositoryUnavailable
	}
	if !final && chunkPin.FirstEvent+chunkPin.EventCount-1 >= manifest.EventCount {
		return nil, ErrRepositoryUnavailable
	}
	chunkBody, err := readAuditExportArtifact(ctx, store, scope, chunkPin.ArtifactID, chunkPin.ObjectReference, chunkPin.VersionID, chunkPin.SHA256, chunkPin.SizeBytes, audit.ExportMaximumChunkBytes)
	if err != nil {
		return nil, err
	}
	chunk, err := audit.VerifyExportChunk(chunkBody, audit.ExportChunkExpectation{Binding: binding, Ordinal: chunkPin.Ordinal, FirstEvent: chunkPin.FirstEvent, EventCount: chunkPin.EventCount, PreviousDigest: chunkPin.PreviousDigest, SHA256: chunkPin.SHA256})
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return &auditExportVerifiedContents{manifest: manifest, chunk: &chunk, chunkSHA256: chunkPin.SHA256}, nil
}
