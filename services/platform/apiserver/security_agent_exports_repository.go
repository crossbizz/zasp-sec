package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"time"
)

type SecurityAgentExportsRepository struct{ database JSONDatabase }

func NewSecurityAgentExportsRepository(db JSONDatabase) (*SecurityAgentExportsRepository, error) {
	if nilInterface(db) {
		return nil, ErrRepositoryUnavailable
	}
	return &SecurityAgentExportsRepository{database: db}, nil
}
func (r *SecurityAgentExportsRepository) grantAction(ctx context.Context, identity RequestIdentity, digest []byte, run, step, token, format, operation string) (complianceGrantResult, error) {
	var result complianceGrantResult
	if operation == "read" {
		return result, ErrRepositoryOperation
	}
	raw, err := r.grant(ctx, identity, digest, run, step, token, format, operation)
	if err != nil {
		return result, err
	}
	f, err := auditExportClosedObject(raw, 1024, "expires_at", "consumed")
	if err != nil || json.Unmarshal(raw, &result) != nil || result.ExpiresAt.IsZero() || string(f["consumed"]) == "null" || result.Consumed != (operation == "consume" || operation == "integrity_failure") {
		return complianceGrantResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
func (r *SecurityAgentExportsRepository) readGrant(ctx context.Context, identity RequestIdentity, digest []byte, run, step, token, format string) (securityAgentExportReadReceipt, error) {
	var result securityAgentExportReadReceipt
	raw, err := r.grant(ctx, identity, digest, run, step, token, format, "read")
	if err != nil {
		return result, err
	}
	f, err := auditExportClosedObject(raw, 65536, "reference", "version", "size", "sha256", "renderer_revision", "read_expires_at", "binding")
	if err != nil || json.Unmarshal(raw, &result) != nil || !validProductID(result.Reference) || !complianceVersion(result.Version) || result.Size < 1 || result.Size > compliancePackageMaximum || !validExistingTestPublicDigest(result.SHA256) || result.RendererRevision != "security-agent-evidence-envelope-v1" || !result.ReadExpiresAt.After(time.Now()) || result.Binding.RunID != run || result.Binding.StepID != step || !validAgentExportDownloadBinding(result.Binding) {
		return securityAgentExportReadReceipt{}, ErrRepositoryUnavailable
	}
	b, err := auditExportClosedObject(f["binding"], 65536, "run_id", "step_id", "selection")
	if err != nil {
		return securityAgentExportReadReceipt{}, ErrRepositoryUnavailable
	}
	var items []json.RawMessage
	if json.Unmarshal(b["selection"], &items) != nil {
		return securityAgentExportReadReceipt{}, ErrRepositoryUnavailable
	}
	for _, item := range items {
		if _, err := auditExportClosedObject(item, 4096, "source_kind", "source_id", "source_version", "association_digest"); err != nil {
			return securityAgentExportReadReceipt{}, ErrRepositoryUnavailable
		}
	}
	return result, nil
}

func (r *SecurityAgentExportsRepository) grant(ctx context.Context, identity RequestIdentity, digest []byte, run, step, token, format, operation string) (json.RawMessage, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || !validProductID(run) || !validProductID(step) || !validExistingTestPublicDigest(token) || !stringIn(format, "json", "csv", "readable") || !stringIn(operation, "issue", "read", "consume", "integrity_failure") {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, `SELECT public.zasp_sa_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), run, step, identity.PrincipalID.String(), bytes.Clone(digest), identity.CSRFToken, token, format, operation, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, complianceExportError(err)
	}
	return raw, nil
}
