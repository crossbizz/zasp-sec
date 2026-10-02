package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const postgresComplianceExportCreateSQL = `SELECT public.zasp_compliance_export_create($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const postgresComplianceExportGetSQL = `SELECT public.zasp_compliance_export_get($1,$2,$3,$4,$5,$6,$7,$8)`

type ComplianceExportRequest struct {
	Framework string `json:"framework,omitempty"`
	ControlID string `json:"control_id,omitempty"`
}
type ComplianceExportJob struct {
	ExportID           string    `json:"export_id"`
	OrganizationID     string    `json:"organization_id"`
	WorkspaceID        string    `json:"workspace_id"`
	EnvironmentID      string    `json:"environment_id"`
	State              string    `json:"state"`
	Phase              string    `json:"phase"`
	FailureCode        *string   `json:"failure_code"`
	CreatedAt          time.Time `json:"created_at"`
	RetrievalExpiresAt time.Time `json:"retrieval_expires_at"`
	MappingRevision    string    `json:"mapping_revision"`
}
type ComplianceExportsRepository struct{ source *ComplianceRepository }

func NewComplianceExportsRepository(db JSONDatabase) (*ComplianceExportsRepository, error) {
	r, e := NewComplianceRepository(db)
	if e != nil {
		return nil, e
	}
	return &ComplianceExportsRepository{source: r}, nil
}

var complianceIdempotencyKey = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var ErrComplianceCapacity = errors.New("compliance capacity exhausted")

func (r *ComplianceExportsRepository) Create(ctx context.Context, identity RequestIdentity, digest []byte, key string, request ComplianceExportRequest) (ComplianceExportJob, error) {
	if !validRequestIdentity(identity, true) || !identity.FreshAuthenticated || !complianceIdempotencyKey.MatchString(key) || request.Framework != "" && !validComplianceFramework(request.Framework) || request.ControlID != "" && !validComplianceControl(request.ControlID, request.Framework) {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	if request.Framework == "" && request.ControlID != "" {
		request.Framework = strings.Split(request.ControlID, "-")[0]
	}
	payload, e := json.Marshal(request)
	if e != nil {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	return r.job(ctx, identity, digest, postgresComplianceExportCreateSQL, key, json.RawMessage(payload))
}
func (r *ComplianceExportsRepository) Get(ctx context.Context, identity RequestIdentity, digest []byte, id string) (ComplianceExportJob, error) {
	if v, e := domain.ParseProductID(id); e != nil || v.IsZero() {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	job, err := r.job(ctx, identity, digest, postgresComplianceExportGetSQL, id)
	if err == nil && job.ExportID != id {
		return ComplianceExportJob{}, ErrRepositoryUnavailable
	}
	return job, err
}
func (r *ComplianceExportsRepository) job(ctx context.Context, identity RequestIdentity, digest []byte, query string, values ...any) (ComplianceExportJob, error) {
	if r == nil || r.source == nil || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	for _, p := range []string{"view", "view_audit", "view_compliance"} {
		if !currentRequestHasPermission(ctx, identity, p) {
			return ComplianceExportJob{}, ErrComplianceForbidden
		}
	}
	if err := ctx.Err(); err != nil {
		return ComplianceExportJob{}, err
	}
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(digest)}
	args = append(args, values...)
	args = append(args, r.source.checksum, r.source.fingerprint)
	raw, err := r.source.database.QueryJSON(ctx, query, args...)
	if ctx.Err() != nil {
		return ComplianceExportJob{}, ctx.Err()
	}
	if err != nil {
		return ComplianceExportJob{}, complianceExportError(err)
	}
	return decodeComplianceExportJob(raw, identity)
}
func complianceExportError(err error) error {
	if errors.Is(err, ErrRepositoryConflict) {
		return ErrRepositoryConflict
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "40001", "23505":
			return ErrRepositoryConflict
		case "42501":
			return ErrComplianceForbidden
		case "28000":
			return ErrRepositoryAuthentication
		case "54000":
			return ErrComplianceCapacity
		}
	}
	return auditExportRepositoryError(err)
}
func decodeComplianceExportJob(raw []byte, identity RequestIdentity) (ComplianceExportJob, error) {
	if _, err := auditExportClosedObject(raw, 16384, "export_id", "organization_id", "workspace_id", "environment_id", "state", "phase", "failure_code", "created_at", "retrieval_expires_at", "mapping_revision"); err != nil {
		return ComplianceExportJob{}, ErrRepositoryUnavailable
	}
	var j ComplianceExportJob
	if json.Unmarshal(raw, &j) != nil || j.OrganizationID != identity.Scope.OrganizationID().String() || j.WorkspaceID != identity.Scope.WorkspaceID().String() || j.EnvironmentID != identity.Scope.EnvironmentID().String() || !slices.Contains([]string{"pending", "completed", "failed"}, j.State) || !slices.Contains([]string{"queued", "collecting", "uploading", "terminal"}, j.Phase) || j.MappingRevision != "product-evidence-v1" || j.CreatedAt.IsZero() || !j.RetrievalExpiresAt.After(j.CreatedAt) {
		return ComplianceExportJob{}, ErrRepositoryUnavailable
	}
	if id, err := domain.ParseProductID(j.ExportID); err != nil || id.IsZero() {
		return ComplianceExportJob{}, ErrRepositoryUnavailable
	}
	if j.State == "pending" && j.Phase == "terminal" || j.State != "pending" && j.Phase != "terminal" || j.FailureCode != nil && !slices.Contains([]string{"collection_failed", "storage_unresolved", "authorization_revoked", "retrieval_expired"}, *j.FailureCode) {
		return ComplianceExportJob{}, ErrRepositoryUnavailable
	}
	return j, nil
}
