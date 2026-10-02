package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"time"
)

// Public status deliberately excludes storage keys and immutable version IDs.
type SecurityAgentExportStatus struct {
	ExportID           string                              `json:"export_id"`
	State              string                              `json:"state"`
	Phase              string                              `json:"phase"`
	FailureCode        *string                             `json:"failure_code"`
	CreatedAt          time.Time                           `json:"created_at"`
	RetrievalExpiresAt time.Time                           `json:"retrieval_expires_at"`
	MappingRevision    string                              `json:"mapping_revision"`
	SnapshotAt         *time.Time                          `json:"snapshot_at"`
	CleanupState       string                              `json:"cleanup_state"`
	Selection          []SecurityAgentExportSelection      `json:"selection"`
	Artifact           *SecurityAgentExportArtifactSummary `json:"artifact"`
}
type SecurityAgentExportArtifactSummary struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func (r *SecurityAgentExportsRepository) Get(ctx context.Context, identity RequestIdentity, digest []byte, run, step string) (SecurityAgentExportStatus, error) {
	var result SecurityAgentExportStatus
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || !validProductID(run) || !validProductID(step) {
		return result, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), run, step, identity.PrincipalID.String(), bytes.Clone(digest), identity.CSRFToken, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil {
		return result, complianceExportError(err)
	}
	f, err := auditExportClosedObject(raw, 65536, "export_id", "state", "phase", "failure_code", "created_at", "retrieval_expires_at", "mapping_revision", "snapshot_at", "cleanup_state", "selection", "artifact")
	if err != nil || json.Unmarshal(raw, &result) != nil || !validProductID(result.ExportID) || !stringIn(result.State, "pending", "completed", "failed") || !stringIn(result.Phase, "queued", "collecting", "uploading", "terminal") || (result.State == "pending") == (result.Phase == "terminal") || result.CreatedAt.IsZero() || result.RetrievalExpiresAt.IsZero() || result.MappingRevision != "security-agent-run-evidence-v1" || !stringIn(result.CleanupState, "retained", "pending", "deleted") || !validAgentExportDownloadBinding(SecurityAgentExportBinding{RunID: run, StepID: step, Selection: result.Selection}) {
		return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
	}
	if result.FailureCode != nil && !stringIn(*result.FailureCode, "collection_failed", "storage_unresolved", "authorization_revoked", "retrieval_expired", "integrity_failure", "export_cancelled", "export_parent_stopped") {
		return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
	}
	if result.SnapshotAt != nil && result.SnapshotAt.IsZero() {
		return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
	}
	var items []json.RawMessage
	if json.Unmarshal(f["selection"], &items) != nil {
		return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
	}
	for _, item := range items {
		if _, err := auditExportClosedObject(item, 4096, "source_kind", "source_id", "source_version", "association_digest"); err != nil {
			return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
		}
	}
	if result.Artifact != nil {
		if _, err := auditExportClosedObject(f["artifact"], 1024, "sha256", "size"); err != nil || !validExistingTestPublicDigest(result.Artifact.SHA256) || result.Artifact.Size < 1 || result.Artifact.Size > compliancePackageMaximum {
			return SecurityAgentExportStatus{}, ErrRepositoryUnavailable
		}
	}
	return result, nil
}
