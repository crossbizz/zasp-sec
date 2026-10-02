package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const postgresAuditExportGetSQL = `SELECT zasp_audit_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

type AuditExportRead struct {
	ExportID       string
	SessionDigest  []byte
	ChunkOrdinal   int64
	ManifestSHA256 []byte
}

// Unexported fields prevent accidentally serializing private storage authority
// as a public HTTP response. The handler must verify artifacts before projection.
type auditExportReadResult struct {
	export    AuditExportDescriptor
	authority *auditExportReadAuthority
}

type auditExportReadAuthority struct {
	StoragePolicy auditExportStoragePolicy     `json:"storage_policy"`
	Binding       audit.ExportBinding          `json:"binding"`
	Manifest      auditExportArtifactAuthority `json:"manifest"`
	Chunk         *auditExportChunkAuthority   `json:"chunk"`
}

type auditExportArtifactAuthority struct {
	ArtifactID      string `json:"artifact_id"`
	ObjectReference string `json:"object_reference"`
	VersionID       string `json:"version_id"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
}

type auditExportChunkAuthority struct {
	auditExportArtifactAuthority
	Ordinal        int64  `json:"ordinal"`
	FirstEvent     int64  `json:"first_event"`
	EventCount     int64  `json:"event_count"`
	PreviousDigest string `json:"previous_digest"`
}

func (repository *AuditExportRepository) Get(ctx context.Context, identity RequestIdentity, input AuditExportRead) (auditExportReadResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || !validProductID(input.ExportID) {
		return auditExportReadResult{}, ErrRepositoryOperation
	}
	if !currentRequestHasPermission(ctx, identity, "view_audit") {
		return auditExportReadResult{}, ErrAuditExportForbidden
	}
	if !nonzeroAuditExportDigest(input.SessionDigest) || input.ChunkOrdinal < 1 || input.ChunkOrdinal > 1<<53-1 || (input.ChunkOrdinal > 1 && len(input.ManifestSHA256) == 0) || (len(input.ManifestSHA256) != 0 && !nonzeroAuditExportDigest(input.ManifestSHA256)) {
		return auditExportReadResult{}, ErrRepositoryOperation
	}
	if err := repository.Ready(ctx); err != nil {
		return auditExportReadResult{}, err
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAuditExportGetSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(input.SessionDigest), identity.CSRFToken, input.ExportID, input.ChunkOrdinal, bytes.Clone(input.ManifestSHA256), repository.checksum, repository.fingerprint)
	if contextErr := ctx.Err(); contextErr != nil {
		return auditExportReadResult{}, contextErr
	}
	if err != nil {
		return auditExportReadResult{}, auditExportRepositoryError(err)
	}
	fields, err := auditExportClosedObject(payload, 16384, "export", "authority")
	if err != nil {
		return auditExportReadResult{}, err
	}
	descriptor, err := decodeAuditExportDescriptor(fields["export"])
	if err != nil || descriptor.ID != input.ExportID || descriptor.OrganizationID != identity.Scope.OrganizationID().String() {
		return auditExportReadResult{}, ErrRepositoryUnavailable
	}
	if descriptor.Status == "ready" {
		authority, err := decodeAuditExportReadAuthority(fields["authority"], descriptor, input)
		if err != nil {
			return auditExportReadResult{}, ErrRepositoryUnavailable
		}
		if err := ctx.Err(); err != nil {
			return auditExportReadResult{}, err
		}
		return auditExportReadResult{export: descriptor, authority: authority}, nil
	}
	if !bytes.Equal(bytes.TrimSpace(fields["authority"]), []byte("null")) || input.ChunkOrdinal != 1 || len(input.ManifestSHA256) != 0 {
		return auditExportReadResult{}, ErrRepositoryUnavailable
	}
	return auditExportReadResult{export: descriptor}, nil
}

func decodeAuditExportReadAuthority(payload []byte, descriptor AuditExportDescriptor, input AuditExportRead) (*auditExportReadAuthority, error) {
	fields, err := auditExportClosedObject(payload, 16384, "binding", "manifest", "chunk", "storage_policy")
	if err != nil {
		return nil, err
	}
	policy, err := decodeAuditExportStoragePolicy(fields["storage_policy"])
	if err != nil {
		return nil, err
	}
	if _, err := auditExportClosedObject(fields["binding"], 1024, "organization_id", "workspace_id", "environment_id", "export_id", "capture_id"); err != nil {
		return nil, err
	}
	receiptKeys := []string{"artifact_id", "object_reference", "version_id", "sha256", "size_bytes"}
	if _, err := auditExportClosedObject(fields["manifest"], 8192, receiptKeys...); err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSpace(fields["chunk"]), []byte("null")) {
		if _, err := auditExportClosedObject(fields["chunk"], 8192, append(receiptKeys, "ordinal", "first_event", "event_count", "previous_digest")...); err != nil {
			return nil, err
		}
	}
	var authority auditExportReadAuthority
	if json.Unmarshal(payload, &authority) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if authority.StoragePolicy != policy || !strings.HasPrefix(authority.Manifest.ObjectReference, "s3://"+policy.Bucket+"/") || authority.Chunk != nil && !strings.HasPrefix(authority.Chunk.ObjectReference, "s3://"+policy.Bucket+"/") {
		return nil, ErrRepositoryUnavailable
	}
	binding := authority.Binding
	// Reuse the codec's exact identity rules without interpreting jsonb's field
	// order as canonical artifact bytes. The manifest bytes are verified later.
	_, err = audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest})
	if err != nil || binding.OrganizationID != descriptor.OrganizationID || binding.WorkspaceID != descriptor.WorkspaceID || binding.EnvironmentID != descriptor.EnvironmentID || binding.ExportID != descriptor.ID ||
		!validAuditExportArtifactAuthority(authority.Manifest, binding, 2048) || authority.Manifest.SHA256 != descriptor.ManifestSHA256 {
		return nil, ErrRepositoryUnavailable
	}
	if len(input.ManifestSHA256) != 0 && hex.EncodeToString(input.ManifestSHA256) != authority.Manifest.SHA256 {
		return nil, ErrRepositoryUnavailable
	}
	events, chunks, totalBytes := *descriptor.EventCount, *descriptor.ChunkCount, *descriptor.ChunkBytes
	if authority.Manifest.SizeBytes > policy.MaximumExportBytes || totalBytes > policy.MaximumExportBytes-authority.Manifest.SizeBytes {
		return nil, ErrRepositoryUnavailable
	}
	if events == 0 {
		if authority.Chunk != nil || input.ChunkOrdinal != 1 {
			return nil, ErrRepositoryUnavailable
		}
		return &authority, nil
	}
	chunk := authority.Chunk
	if chunk == nil || !validAuditExportArtifactAuthority(chunk.auditExportArtifactAuthority, binding, audit.ExportMaximumChunkBytes) ||
		chunk.ArtifactID == authority.Manifest.ArtifactID || chunk.Ordinal != input.ChunkOrdinal || chunk.Ordinal > chunks ||
		chunk.FirstEvent < 1 || chunk.FirstEvent > events || chunk.EventCount < 1 || chunk.EventCount > audit.ExportMaximumChunkEvents || chunk.EventCount > events-chunk.FirstEvent+1 ||
		!validAuditExportSHA256(chunk.PreviousDigest) || (chunk.Ordinal == 1 && chunk.PreviousDigest != audit.ExportZeroDigest) || (chunk.Ordinal > 1 && chunk.PreviousDigest == audit.ExportZeroDigest) {
		return nil, ErrRepositoryUnavailable
	}
	before, after := chunk.FirstEvent-1, events-(chunk.FirstEvent-1)-chunk.EventCount
	priorChunks, remainingChunks := chunk.Ordinal-1, chunks-chunk.Ordinal
	// Every preceding/following chunk must have at least one event and at most
	// 1000. Division avoids multiplying untrusted large totals or adding ranges.
	if !auditExportCountFitsChunks(before, priorChunks, audit.ExportMaximumChunkEvents) || !auditExportCountFitsChunks(after, remainingChunks, audit.ExportMaximumChunkEvents) ||
		totalBytes < chunk.SizeBytes || !auditExportCountFitsChunks(totalBytes-chunk.SizeBytes, chunks-1, audit.ExportMaximumChunkBytes) {
		return nil, ErrRepositoryUnavailable
	}
	return &authority, nil
}

func auditExportCountFitsChunks(count, chunks, maximum int64) bool {
	if chunks == 0 {
		return count == 0
	}
	return count >= chunks && 1+(count-1)/maximum <= chunks
}

var auditExportObjectBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func validAuditExportArtifactAuthority(receipt auditExportArtifactAuthority, binding audit.ExportBinding, maximumBytes int64) bool {
	if receipt.SizeBytes < 1 || receipt.SizeBytes > maximumBytes || !validAuditExportSHA256(receipt.SHA256) || receipt.SHA256 == audit.ExportZeroDigest ||
		len(receipt.VersionID) < 1 || len(receipt.VersionID) > 1024 || receipt.VersionID == "null" {
		return false
	}
	for _, value := range []byte(receipt.VersionID) {
		if value < '!' || value > '~' {
			return false
		}
	}
	for _, id := range []string{binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, binding.ExportID, binding.CaptureID} {
		if receipt.ArtifactID == id {
			return false
		}
	}
	organization, err := domain.ParseProductID(binding.OrganizationID)
	if err != nil {
		return false
	}
	workspace, err := domain.ParseProductID(binding.WorkspaceID)
	if err != nil {
		return false
	}
	environment, err := domain.ParseProductID(binding.EnvironmentID)
	if err != nil {
		return false
	}
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		return false
	}
	reference, err := domain.ParseEvidenceRef(receipt.ArtifactID)
	if err != nil {
		return false
	}
	key, err := bucketlayout.ExportKey(scope, reference.ArtifactID())
	if err != nil {
		return false
	}
	object, err := url.Parse(receipt.ObjectReference)
	// This checks the typed export key only. The configured export store must
	// still prove exact ObjectReference(locator) equality before fetching bytes.
	return err == nil && object.Scheme == "s3" && auditExportObjectBucketPattern.MatchString(object.Host) && receipt.ObjectReference == "s3://"+object.Host+"/"+key
}

func nonzeroAuditExportDigest(value []byte) bool {
	return len(value) == sha256.Size && !bytes.Equal(value, make([]byte, sha256.Size))
}

func auditExportClosedObject(payload []byte, limit int, required ...string) (map[string]json.RawMessage, error) {
	if len(payload) == 0 || len(payload) > limit || !utf8.Valid(payload) {
		return nil, ErrRepositoryUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrRepositoryUnavailable
	}
	fields := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !slices.Contains(required, name) || fields[name] != nil {
			return nil, ErrRepositoryUnavailable
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, ErrRepositoryUnavailable
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || len(fields) != len(required) {
		return nil, ErrRepositoryUnavailable
	}
	return fields, nil
}
