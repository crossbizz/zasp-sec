package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresRecoveryStartBackupSQL  = `SELECT zasp_recovery_create_backup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresRecoveryGetBackupSQL    = `SELECT zasp_recovery_get_backup($1,$2,$3,$4)`
	postgresRecoveryStartRestoreSQL = `SELECT zasp_recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`
	postgresRecoveryGetRestoreSQL   = `SELECT zasp_recovery_get_restore($1,$2,$3,$4)`
)

var (
	recoveryVersionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	recoveryMediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$`)
	recoverySchemaPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	recoveryUUIDPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	recoveryTargetPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type RecoveryPublicRepository struct {
	database    JSONDatabase
	checksum    string
	fingerprint string
}

type RecoveryArtifactLocator struct {
	Reference string `json:"reference"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
	Schema    string `json:"schema"`
}

type RecoveryManifestLocator struct {
	Reference    string `json:"reference"`
	VersionID    string `json:"version_id"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	MediaType    string `json:"media_type"`
	Schema       string `json:"schema"`
	SigningKeyID string `json:"signing_key_id"`
	Signature    string `json:"signature"`
}

type RecoveryCounts struct {
	Assets   uint64 `json:"assets"`
	Findings uint64 `json:"findings"`
	Policies uint64 `json:"policies"`
}

type RecoveryValidationEvidence struct {
	State          string                  `json:"state"`
	ExpectedCounts RecoveryCounts          `json:"expected_counts"`
	ObservedCounts RecoveryCounts          `json:"observed_counts"`
	Evidence       RecoveryArtifactLocator `json:"evidence"`
}

type RecoveryCleanupEvidence struct {
	State    string                  `json:"state"`
	Evidence RecoveryArtifactLocator `json:"evidence"`
}

type RecoveryBackup struct {
	ID            string                   `json:"id"`
	Version       int64                    `json:"version"`
	State         string                   `json:"state"`
	RetentionDays int                      `json:"retention_days"`
	Attempt       int                      `json:"attempt"`
	Manifest      *RecoveryManifestLocator `json:"manifest,omitempty"`
	ErrorCode     *string                  `json:"error_code,omitempty"`
	CreatedAt     time.Time                `json:"created_at"`
	StartedAt     *time.Time               `json:"started_at,omitempty"`
	CompletedAt   *time.Time               `json:"completed_at,omitempty"`
}

type RecoveryRestore struct {
	ID                 string                      `json:"id"`
	Version            int64                       `json:"version"`
	State              string                      `json:"state"`
	TargetEnvironment  string                      `json:"target_environment"`
	Attempt            int                         `json:"attempt"`
	Manifest           *RecoveryManifestLocator    `json:"manifest"`
	ObservedCounts     *RecoveryCounts             `json:"observed_counts,omitempty"`
	ValidationEvidence *RecoveryValidationEvidence `json:"validation_evidence,omitempty"`
	CleanupEvidence    *RecoveryCleanupEvidence    `json:"cleanup_evidence,omitempty"`
	ErrorCode          *string                     `json:"error_code,omitempty"`
	CreatedAt          time.Time                   `json:"created_at"`
	StartedAt          *time.Time                  `json:"started_at,omitempty"`
	CompletedAt        *time.Time                  `json:"completed_at,omitempty"`
}

type RecoveryBackupMutation struct {
	BackupID       string
	RetentionDays  int
	IdempotencyKey string
	RequestDigest  []byte
	AuditID        string
	CorrelationID  string
	ReceiptID      string
}

type RecoveryRestoreMutation struct {
	RestoreID         string
	TargetEnvironment string
	Manifest          RecoveryManifestLocator
	IdempotencyKey    string
	RequestDigest     []byte
	AuditID           string
	CorrelationID     string
	ReceiptID         string
}

type RecoveryBackupMutationResult struct {
	Body          RecoveryBackup `json:"body"`
	AuditID       string         `json:"audit_id"`
	CorrelationID string         `json:"correlation_id"`
	ReceiptID     string         `json:"receipt_id"`
	Replayed      bool           `json:"replayed"`
}

type RecoveryRestoreMutationResult struct {
	Body          RecoveryRestore `json:"body"`
	AuditID       string          `json:"audit_id"`
	CorrelationID string          `json:"correlation_id"`
	ReceiptID     string          `json:"receipt_id"`
	Replayed      bool            `json:"replayed"`
}

func NewRecoveryPublicRepository(database JSONDatabase) (*RecoveryPublicRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil || version != ProductionRecoverySchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	checksum := migrations.ProductionRecovery().Checksum()
	fingerprint := migrations.ProductionRecoverySemanticFingerprint()
	payload, err := database.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, checksum, fingerprint)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	return &RecoveryPublicRepository{database: database, checksum: checksum, fingerprint: fingerprint}, nil
}

func (repository *RecoveryPublicRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, repository.checksum, repository.fingerprint)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RecoveryPublicRepository) StartBackup(ctx context.Context, identity RequestIdentity, input RecoveryBackupMutation) (RecoveryBackupMutationResult, error) {
	if !validRecoveryRepository(repository, ctx) || !validRecoveryMutationIdentity(identity, input.AuditID, input.CorrelationID, input.ReceiptID) || !validProductID(input.BackupID) || input.RetentionDays < 7 || input.RetentionDays > 90 || !validPublicIdempotency(input.IdempotencyKey) || !validRecoveryDigest(input.RequestDigest) {
		return RecoveryBackupMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRecoveryStartBackupSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.BackupID, input.CorrelationID, input.RetentionDays, input.AuditID, input.ReceiptID, input.RequestDigest)
	if err != nil {
		return RecoveryBackupMutationResult{}, discoveryProviderError(err)
	}
	var result RecoveryBackupMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRecoveryMutationResultIdentity(identity, result.AuditID, result.CorrelationID, result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) || !validRecoveryBackup(result.Body, identity.Scope) || result.Body.ID != input.BackupID || result.Body.Version != 1 || result.Body.State != "queued" || result.Body.RetentionDays != input.RetentionDays {
		return RecoveryBackupMutationResult{}, ErrRepositoryUnavailable
	}
	canonicalizeRecoveryBackup(&result.Body)
	return result, nil
}

func (repository *RecoveryPublicRepository) GetBackup(ctx context.Context, identity RequestIdentity, id string) (RecoveryBackup, error) {
	if !validRecoveryRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validProductID(id) {
		return RecoveryBackup{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRecoveryGetBackupSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), id)
	if err != nil {
		return RecoveryBackup{}, discoveryProviderError(err)
	}
	var result RecoveryBackup
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validRecoveryBackup(result, identity.Scope) {
		return RecoveryBackup{}, ErrRepositoryUnavailable
	}
	canonicalizeRecoveryBackup(&result)
	return result, nil
}

func (repository *RecoveryPublicRepository) StartRestore(ctx context.Context, identity RequestIdentity, input RecoveryRestoreMutation) (RecoveryRestoreMutationResult, error) {
	if !validRecoveryRepository(repository, ctx) || !validRecoveryMutationIdentity(identity, input.AuditID, input.CorrelationID, input.ReceiptID) || !validProductID(input.RestoreID) || !validRecoveryTarget(input.TargetEnvironment, identity.Scope) || !validPublicIdempotency(input.IdempotencyKey) || !validRecoveryDigest(input.RequestDigest) || !validRecoveryManifestLocator(input.Manifest, identity.Scope) {
		return RecoveryRestoreMutationResult{}, ErrRepositoryOperation
	}
	manifest, err := json.Marshal(input.Manifest)
	if err != nil || len(manifest) > 8192 {
		return RecoveryRestoreMutationResult{}, ErrRepositoryOperation
	}
	digest, err := hex.DecodeString(input.Manifest.SHA256)
	if err != nil {
		return RecoveryRestoreMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRecoveryStartRestoreSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.RestoreID, input.TargetEnvironment, input.CorrelationID, input.AuditID, input.ReceiptID, input.RequestDigest, json.RawMessage(manifest), digest)
	if err != nil {
		return RecoveryRestoreMutationResult{}, discoveryProviderError(err)
	}
	var result RecoveryRestoreMutationResult
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed") || decodeStrictDiscovery(payload, &result) != nil || !validRecoveryMutationResultIdentity(identity, result.AuditID, result.CorrelationID, result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) || !validRecoveryRestore(result.Body, identity.Scope) || result.Body.ID != input.RestoreID || result.Body.Version != 1 || result.Body.State != "queued" || result.Body.TargetEnvironment != input.TargetEnvironment || result.Body.Manifest == nil || *result.Body.Manifest != input.Manifest {
		return RecoveryRestoreMutationResult{}, ErrRepositoryUnavailable
	}
	canonicalizeRecoveryRestore(&result.Body)
	return result, nil
}

func (repository *RecoveryPublicRepository) GetRestore(ctx context.Context, identity RequestIdentity, id string) (RecoveryRestore, error) {
	if !validRecoveryRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validProductID(id) {
		return RecoveryRestore{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRecoveryGetRestoreSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), id)
	if err != nil {
		return RecoveryRestore{}, discoveryProviderError(err)
	}
	var result RecoveryRestore
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validRecoveryRestore(result, identity.Scope) {
		return RecoveryRestore{}, ErrRepositoryUnavailable
	}
	canonicalizeRecoveryRestore(&result)
	return result, nil
}

func validRecoveryRepository(repository *RecoveryPublicRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validRecoveryMutationIdentity(identity RequestIdentity, auditID, correlationID, receiptID string) bool {
	return validRequestIdentity(identity, false) && validProductID(auditID) && validProductID(correlationID) && validProductID(receiptID) && auditID != receiptID && auditID != correlationID && receiptID != correlationID
}

func validRecoveryMutationResultIdentity(identity RequestIdentity, auditID, correlationID, receiptID string) bool {
	return validRequestIdentity(identity, false) && validProductID(auditID) && validProductID(correlationID) && validProductID(receiptID) && auditID != receiptID && auditID != correlationID && receiptID != correlationID
}

func validRecoveryDigest(value []byte) bool {
	return len(value) == sha256.Size && !bytes.Equal(value, make([]byte, sha256.Size))
}

func validRecoveryTarget(value string, scope domain.Scope) bool {
	return len(value) >= 1 && len(value) <= 63 && recoveryTargetPattern.MatchString(value) && value != "production" && value != scope.EnvironmentID().String()
}

func validRecoveryManifestLocator(value RecoveryManifestLocator, scope domain.Scope) bool {
	if !validRecoveryArtifactLocator(RecoveryArtifactLocator{Reference: value.Reference, VersionID: value.VersionID, SHA256: value.SHA256, SizeBytes: value.SizeBytes, MediaType: value.MediaType, Schema: value.Schema}, scope) || value.MediaType != "application/vnd.zasp.recovery-manifest+json" || value.Schema != "recovery_signed_manifest_v1" || !recoveryUUIDPattern.MatchString(value.SigningKeyID) {
		return false
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(value.Signature)
	return err == nil && len(signature) >= sha256.Size && len(signature) <= 512
}

func validRecoveryArtifactLocator(value RecoveryArtifactLocator, scope domain.Scope) bool {
	digest, digestErr := hex.DecodeString(value.SHA256)
	return validRecoveryScopedReference(value.Reference, scope) && len(value.VersionID) >= 1 && len(value.VersionID) <= 1024 && recoveryVersionIDPattern.MatchString(value.VersionID) && digestErr == nil && len(digest) == sha256.Size && !bytes.Equal(digest, make([]byte, sha256.Size)) && value.SizeBytes >= 1 && value.SizeBytes <= 64<<20 && recoveryMediaTypePattern.MatchString(value.MediaType) && recoverySchemaPattern.MatchString(value.Schema)
}

func validRecoveryScopedReference(value string, scope domain.Scope) bool {
	if scope.Validate() != nil || !validS3ObjectReference(value) {
		return false
	}
	parts := s3ObjectReferencePattern.FindStringSubmatch(value)
	if len(parts) != 3 {
		return false
	}
	prefix := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/"
	if !strings.HasPrefix(parts[2], prefix) || strings.Contains(parts[2][len(prefix):], "/") {
		return false
	}
	return validProductID(parts[2][len(prefix):])
}

func validRecoveryBackup(value RecoveryBackup, scope domain.Scope) bool {
	if !validProductID(value.ID) || value.Version < 1 || value.Version > 1000000 || !stringIn(value.State, "queued", "draining", "capturing", "publishing", "succeeded", "retryable", "failed") || value.RetentionDays < 7 || value.RetentionDays > 90 || value.Attempt < 0 || value.Attempt > 100 || !validPublicTime(value.CreatedAt) || !validRecoveryTimeOrder(value.CreatedAt, value.StartedAt, value.CompletedAt) || value.Manifest != nil && !validRecoveryManifestLocator(*value.Manifest, scope) || value.ErrorCode != nil && !validRecoveryErrorCode(*value.ErrorCode) {
		return false
	}
	switch value.State {
	case "queued":
		return value.Attempt == 0 && value.StartedAt == nil && value.CompletedAt == nil && value.Manifest == nil && value.ErrorCode == nil
	case "draining", "capturing", "publishing":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt == nil && value.Manifest == nil && value.ErrorCode == nil
	case "retryable":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt == nil && value.Manifest == nil && value.ErrorCode != nil
	case "succeeded":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt != nil && value.Manifest != nil && value.ErrorCode == nil
	case "failed":
		return value.CompletedAt != nil && value.Manifest == nil && value.ErrorCode != nil && (value.Attempt >= 1 && value.StartedAt != nil || value.Attempt == 0 && value.StartedAt == nil && *value.ErrorCode == "exhausted")
	default:
		return false
	}
}

func validRecoveryRestore(value RecoveryRestore, scope domain.Scope) bool {
	if !validProductID(value.ID) || value.Version < 1 || value.Version > 1000000 || !stringIn(value.State, "queued", "verifying", "provisioning", "validating", "rebuilding", "cleanup_required", "cleaning", "succeeded", "retryable", "failed", "failed_cleanup") || !validRecoveryTarget(value.TargetEnvironment, scope) || value.Attempt < 0 || value.Attempt > 100 || value.Manifest == nil || !validRecoveryManifestLocator(*value.Manifest, scope) || !validPublicTime(value.CreatedAt) || !validRecoveryTimeOrder(value.CreatedAt, value.StartedAt, value.CompletedAt) || value.ErrorCode != nil && !validRecoveryErrorCode(*value.ErrorCode) || value.ValidationEvidence != nil && !validRecoveryValidationEvidence(*value.ValidationEvidence, scope) || value.CleanupEvidence != nil && !validRecoveryCleanupEvidence(*value.CleanupEvidence, scope) {
		return false
	}
	switch value.State {
	case "queued":
		return value.Attempt == 0 && value.StartedAt == nil && value.CompletedAt == nil && value.ObservedCounts == nil && value.ValidationEvidence == nil && value.CleanupEvidence == nil && value.ErrorCode == nil
	case "verifying", "provisioning", "validating", "rebuilding":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt == nil && value.ObservedCounts == nil && value.CleanupEvidence == nil && value.ErrorCode == nil
	case "cleanup_required", "cleaning":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt == nil
	case "retryable":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt == nil && value.ErrorCode != nil
	case "succeeded":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt != nil && value.ErrorCode == nil && value.ObservedCounts != nil && value.ValidationEvidence != nil && value.CleanupEvidence != nil && value.ValidationEvidence.State == "validated" && value.CleanupEvidence.State == "deleted" && *value.ObservedCounts == value.ValidationEvidence.ObservedCounts
	case "failed":
		return value.CompletedAt != nil && value.ErrorCode != nil && (value.Attempt >= 1 && value.StartedAt != nil || value.Attempt == 0 && value.StartedAt == nil && *value.ErrorCode == "exhausted" && value.ObservedCounts == nil && value.ValidationEvidence == nil && value.CleanupEvidence == nil)
	case "failed_cleanup":
		return value.Attempt >= 1 && value.StartedAt != nil && value.CompletedAt != nil && value.ErrorCode != nil && value.CleanupEvidence != nil && value.CleanupEvidence.State == "failed"
	default:
		return false
	}
}

func validRecoveryValidationEvidence(value RecoveryValidationEvidence, scope domain.Scope) bool {
	return value.State == "validated" && value.ExpectedCounts == value.ObservedCounts && validRecoveryArtifactLocator(value.Evidence, scope)
}

func validRecoveryCleanupEvidence(value RecoveryCleanupEvidence, scope domain.Scope) bool {
	return stringIn(value.State, "deleted", "failed") && validRecoveryArtifactLocator(value.Evidence, scope)
}

func validRecoveryErrorCode(value string) bool {
	return stringIn(value, "dependency_unavailable", "outcome_unknown", "signature_invalid", "manifest_invalid", "manifest_expired", "validation_failed", "projection_mismatch", "cleanup_failed", "exhausted", "lease_lost", "cancelled")
}

func validRecoveryTimeOrder(created time.Time, started, completed *time.Time) bool {
	if !validOptionalPublicTime(started) || !validOptionalPublicTime(completed) || started != nil && started.Before(created) || completed != nil && completed.Before(created) || started != nil && completed != nil && completed.Before(*started) {
		return false
	}
	return true
}

func canonicalizeRecoveryBackup(value *RecoveryBackup) {
	value.CreatedAt = value.CreatedAt.UTC()
	canonicalizeTimePointer(&value.StartedAt)
	canonicalizeTimePointer(&value.CompletedAt)
}

func canonicalizeRecoveryRestore(value *RecoveryRestore) {
	value.CreatedAt = value.CreatedAt.UTC()
	canonicalizeTimePointer(&value.StartedAt)
	canonicalizeTimePointer(&value.CompletedAt)
}
