package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/audit"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAuditExportReadySQL = `SELECT to_jsonb(zasp_audit_export_api_readiness($1,$2))`
const postgresAuditExportCreateSQL = `SELECT zasp_audit_export_create($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

var ErrAuditExportForbidden = errors.New("audit export request forbidden")

// AuditExportDescriptor contains public job state, never provider coordinates.
// CreatedAt is the request time, not the later frozen-snapshot time.
type AuditExportDescriptor = audit.ExportDescriptor
type AuditExportCreate struct {
	ExportID, AuditID, OutboxID, IdempotencyKey string
	SessionDigest                               []byte
}

// AuditExportRepository uses the registered API connection. SQL independently
// rechecks the stored browser session and permissions after blocking work.
type AuditExportRepository struct {
	database              JSONDatabase
	checksum, fingerprint string
}

func NewAuditExportRepository(database JSONDatabase) (*AuditExportRepository, error) {
	return newAuditExportRepository(context.Background(), database)
}

func newAuditExportRepository(parent context.Context, database JSONDatabase) (*AuditExportRepository, error) {
	if parent == nil || parent.Err() != nil || nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil || version != ProductionRecoverySchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	repository := &AuditExportRepository{database: database, checksum: migrations.ProductionAuditExports().Checksum(), fingerprint: migrations.ProductionAuditExportsSemanticFingerprint()}
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *AuditExportRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil {
		return ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, err := currentAuthorizationSourceReady(ctx, repository.database, 52, repository.checksum, repository.fingerprint); current {
		return err
	}
	if release, ok := repository.database.(interface {
		SecurityAgentRunContextAvailable(context.Context) (bool, error)
	}); ok {
		if _, err := release.SecurityAgentRunContextAvailable(ctx); err != nil {
			return ErrRepositoryUnavailable
		}
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAuditExportReadySQL, repository.checksum, repository.fingerprint)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	var ready bool
	if err != nil || len(payload) > 16 || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *AuditExportRepository) Create(ctx context.Context, identity RequestIdentity, input AuditExportCreate) (AuditExportDescriptor, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession {
		return AuditExportDescriptor{}, ErrRepositoryOperation
	}
	if !identity.FreshAuthenticated || !currentRequestHasPermission(ctx, identity, "view_audit") {
		return AuditExportDescriptor{}, ErrAuditExportForbidden
	}
	if !validPublicIdempotency(input.IdempotencyKey) || len(input.SessionDigest) != sha256.Size || bytes.Equal(input.SessionDigest, make([]byte, sha256.Size)) {
		return AuditExportDescriptor{}, ErrRepositoryOperation
	}
	seen := map[string]bool{}
	for _, id := range []string{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.ExportID, input.AuditID, input.OutboxID} {
		if !validProductID(id) || seen[id] {
			return AuditExportDescriptor{}, ErrRepositoryOperation
		}
		seen[id] = true
	}
	if err := repository.Ready(ctx); err != nil {
		return AuditExportDescriptor{}, err
	}
	// The public request is exactly {}. Callers cannot substitute another digest
	// while reusing a key; SQL independently enforces the same request contract.
	digest := sha256.Sum256([]byte("{}"))
	payload, err := repository.database.QueryJSON(ctx, postgresAuditExportCreateSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		bytes.Clone(input.SessionDigest), identity.CSRFToken, input.IdempotencyKey, input.ExportID, input.AuditID, input.OutboxID, digest[:], repository.checksum, repository.fingerprint)
	if contextErr := ctx.Err(); contextErr != nil {
		return AuditExportDescriptor{}, contextErr
	}
	if err != nil {
		return AuditExportDescriptor{}, auditExportRepositoryError(err)
	}
	descriptor, err := decodeAuditExportDescriptor(payload)
	if err != nil || descriptor.OrganizationID != identity.Scope.OrganizationID().String() || descriptor.WorkspaceID != identity.Scope.WorkspaceID().String() || descriptor.EnvironmentID != identity.Scope.EnvironmentID().String() {
		return AuditExportDescriptor{}, ErrRepositoryUnavailable
	}
	return descriptor, nil
}

func auditExportRepositoryError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "22023":
			return ErrRepositoryOperation
		case "23505":
			return ErrRepositoryConflict
		case "P0002":
			return ErrRepositoryNotFound
		case "28000":
			return ErrRepositoryAuthentication
		case "42501":
			return ErrAuditExportForbidden
		}
	}
	for _, known := range []error{ErrRepositoryOperation, ErrRepositoryConflict, ErrRepositoryNotFound, ErrRepositoryAuthentication, ErrAuditExportForbidden} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrRepositoryUnavailable
}

// The descriptor is a bounded flat object. Reject duplicate and case-alias keys
// without assuming PostgreSQL jsonb uses Go's canonical field order.
func decodeAuditExportDescriptor(payload []byte) (AuditExportDescriptor, error) {
	descriptor, err := audit.DecodeExportDescriptor(payload)
	if err != nil {
		return AuditExportDescriptor{}, ErrRepositoryUnavailable
	}
	return descriptor, nil
}
func validAuditExportSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
