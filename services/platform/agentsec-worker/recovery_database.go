package main

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var recoveryRequestDigestPattern = regexp.MustCompile(`^\\x[0-9a-f]{64}$`)

const (
	recoveryWorkerReadySQL        = `SELECT zasp_recovery_execution_readiness($1,$2) AND zasp_recovery_principal_ready('zasp_recovery_worker')`
	recoveryClaimOperationSQL     = `SELECT zasp_recovery_claim_operation($1,$2,$3,$4,$5)`
	recoveryClaimDeliverySQL      = `SELECT zasp_recovery_claim_delivery($1,$2,$3,$4,$5,$6,$7,$8)`
	recoveryHeartbeatOperationSQL = `SELECT zasp_recovery_heartbeat_operation($1,$2,$3,$4,$5,$6,$7,$8)`
	recoveryBeginHoldSQL          = `SELECT zasp_recovery_begin_hold($1,$2,$3,$4,$5,$6)`
	recoveryReleaseHoldSQL        = `SELECT zasp_recovery_release_hold($1,$2,$3,$4,$5,$6)`
	recoveryCapturePageSQL        = `SELECT zasp_recovery_capture_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	recoveryFinishBackupSQL       = `SELECT zasp_recovery_finish_backup($1,$2,$3,$4,$5,$6,$7::jsonb)`
	recoveryCheckpointRestoreSQL  = `SELECT zasp_recovery_checkpoint_restore($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`
	recoveryFinishRestoreSQL      = `SELECT zasp_recovery_finish_restore($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb)`
	recoveryFailOperationSQL      = `SELECT zasp_recovery_fail_operation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`
	recoveryCurrentLSNSQL         = `SELECT to_jsonb(pg_current_wal_lsn()::text)`
)

type recoveryJSONDatabase interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

func (authority *postgresRecoveryOperationAuthority) ClaimDelivery(ctx context.Context, kind string, scope domain.Scope, operationID, worker, token string, leaseSeconds int) (recoveryDeliveryClaim, error) {
	parsedID, idErr := domain.ParseProductID(operationID)
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil || !stringInWorker(kind, "backup", "restore") || scope.Validate() != nil || idErr != nil || parsedID.IsZero() || !workerIdentityPattern.MatchString(worker) || len(token) != 32 || leaseSeconds < 5 || leaseSeconds > 900 {
		return recoveryDeliveryClaim{}, errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryClaimDeliverySQL, kind, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), operationID, worker, []byte(token), leaseSeconds)
	var wire struct {
		Disposition string `json:"disposition"`
		Operation   *struct {
			Attempt           int                                `json:"attempt"`
			BackupID          string                             `json:"backup_id"`
			RestoreID         string                             `json:"restore_id"`
			EnvironmentID     string                             `json:"environment_id"`
			OrganizationID    string                             `json:"organization_id"`
			RequestDigest     string                             `json:"request_digest"`
			WorkspaceID       string                             `json:"workspace_id"`
			LeaseExpiresAt    time.Time                          `json:"lease_expires_at"`
			CreatedAt         time.Time                          `json:"created_at"`
			RetentionDays     int                                `json:"retention_days"`
			TargetEnvironment string                             `json:"target_environment"`
			Manifest          *apiserver.RecoveryManifestLocator `json:"manifest"`
			ManifestDigest    string                             `json:"manifest_digest"`
		} `json:"operation"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &wire) != nil || !stringInWorker(wire.Disposition, "claimed", "retry_later", "ack_terminal", "exhausted") {
		return recoveryDeliveryClaim{}, errWorkerExecution
	}
	if wire.Disposition != "claimed" {
		if wire.Operation != nil {
			return recoveryDeliveryClaim{}, errWorkerExecution
		}
		return recoveryDeliveryClaim{Disposition: wire.Disposition}, nil
	}
	if wire.Operation == nil {
		return recoveryDeliveryClaim{}, errWorkerExecution
	}
	item := wire.Operation
	decodedScope, ok := recoveryScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID)
	decodedID := item.BackupID
	if kind == "restore" {
		decodedID = item.RestoreID
	}
	claim := recoveryOperationClaim{Kind: kind, Scope: decodedScope, OperationID: decodedID, Attempt: item.Attempt, RetentionDays: item.RetentionDays, TargetEnvironment: item.TargetEnvironment, Manifest: item.Manifest, CreatedAt: item.CreatedAt.UTC()}
	if !ok || decodedScope != scope || decodedID != operationID || !validRecoveryOperationClaim(claim) || item.CreatedAt.IsZero() || item.CreatedAt.Location() != time.UTC || !validRecoveryLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) || !recoveryRequestDigestPattern.MatchString(item.RequestDigest) || item.RequestDigest == `\x`+strings.Repeat("0", 64) || kind == "restore" && (!recoveryRequestDigestPattern.MatchString(item.ManifestDigest) || item.Manifest == nil || strings.TrimPrefix(item.ManifestDigest, `\x`) != item.Manifest.SHA256) {
		return recoveryDeliveryClaim{}, errWorkerExecution
	}
	return recoveryDeliveryClaim{Disposition: "claimed", Operation: claim}, nil
}

type postgresRecoveryOperationAuthority struct {
	database    recoveryJSONDatabase
	checksum    string
	fingerprint string
}

func newPostgresRecoveryOperationAuthority(database recoveryJSONDatabase) (*postgresRecoveryOperationAuthority, error) {
	if database == nil {
		return nil, errRuntimeUnavailable
	}
	authority := &postgresRecoveryOperationAuthority{database: database, checksum: migrations.ProductionRecovery().Checksum(), fingerprint: migrations.ProductionRecoverySemanticFingerprint()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if authority.Ready(ctx) != nil {
		return nil, errRuntimeUnavailable
	}
	return authority, nil
}

func (authority *postgresRecoveryOperationAuthority) Ready(ctx context.Context) error {
	if authority == nil || authority.database == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryWorkerReadySQL, authority.checksum, authority.fingerprint)
	var ready bool
	if err != nil || decodeStrictWorkerJSON(payload, &ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) Claim(ctx context.Context, kind, worker, token string, leaseSeconds, limit int) ([]recoveryOperationClaim, error) {
	if authority == nil || ctx == nil || ctx.Err() != nil || !stringInWorker(kind, "backup", "restore") || !workerIdentityPattern.MatchString(worker) || len(token) != 32 || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 25 {
		return nil, errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryClaimOperationSQL, kind, worker, []byte(token), leaseSeconds, limit)
	var wire struct {
		Items []struct {
			Attempt           int                                `json:"attempt"`
			BackupID          string                             `json:"backup_id"`
			RestoreID         string                             `json:"restore_id"`
			EnvironmentID     string                             `json:"environment_id"`
			OrganizationID    string                             `json:"organization_id"`
			RequestDigest     string                             `json:"request_digest"`
			WorkspaceID       string                             `json:"workspace_id"`
			LeaseExpiresAt    time.Time                          `json:"lease_expires_at"`
			RetentionDays     int                                `json:"retention_days"`
			TargetEnvironment string                             `json:"target_environment"`
			Manifest          *apiserver.RecoveryManifestLocator `json:"manifest"`
			ManifestDigest    string                             `json:"manifest_digest"`
		} `json:"items"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &wire) != nil || len(wire.Items) > limit {
		return nil, errWorkerExecution
	}
	claims := make([]recoveryOperationClaim, len(wire.Items))
	for index, item := range wire.Items {
		scope, ok := recoveryScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID)
		operationID := item.BackupID
		if kind == "restore" {
			operationID = item.RestoreID
		}
		claim := recoveryOperationClaim{Kind: kind, Scope: scope, OperationID: operationID, Attempt: item.Attempt, RetentionDays: item.RetentionDays, TargetEnvironment: item.TargetEnvironment, Manifest: item.Manifest}
		if !ok || !validRecoveryOperationClaim(claim) || !validRecoveryLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) || !recoveryRequestDigestPattern.MatchString(item.RequestDigest) || item.RequestDigest == `\x`+strings.Repeat("0", 64) || kind == "restore" && (!recoveryRequestDigestPattern.MatchString(item.ManifestDigest) || item.Manifest == nil || strings.TrimPrefix(item.ManifestDigest, `\x`) != item.Manifest.SHA256) {
			return nil, errWorkerExecution
		}
		claims[index] = claim
	}
	return claims, nil
}

func (authority *postgresRecoveryOperationAuthority) CheckpointRestore(ctx context.Context, lease recoveryOperationLease, from, to string, evidence any) error {
	if !validRecoveryLease(lease) || lease.Kind != "restore" || evidence == nil || !stringInWorker(from+":"+to, "verifying:provisioning", "provisioning:validating", "validating:rebuilding", "rebuilding:cleanup_required", "cleanup_required:cleaning") {
		return errWorkerExecution
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || len(encoded) < 2 || len(encoded) > 8192 {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryCheckpointRestoreSQL, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken), from, to, json.RawMessage(encoded))
	var result struct {
		State string `json:"state"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.State != to {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) FinishRestore(ctx context.Context, lease recoveryOperationLease, observed apiserver.RecoveryCounts, validation apiserver.RecoveryValidationEvidence, cleanup apiserver.RecoveryCleanupEvidence) error {
	if !validRecoveryLease(lease) || lease.Kind != "restore" {
		return errWorkerExecution
	}
	observedJSON, observedErr := json.Marshal(observed)
	validationJSON, validationErr := json.Marshal(validation)
	cleanupJSON, cleanupErr := json.Marshal(cleanup)
	if observedErr != nil || validationErr != nil || cleanupErr != nil || len(observedJSON) > 1024 || len(validationJSON) > 8192 || len(cleanupJSON) > 8192 {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryFinishRestoreSQL, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken), json.RawMessage(observedJSON), json.RawMessage(validationJSON), json.RawMessage(cleanupJSON))
	var result struct {
		State    string `json:"state"`
		Replayed bool   `json:"replayed"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.State != "succeeded" {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) Heartbeat(ctx context.Context, lease recoveryOperationLease, leaseSeconds int) error {
	payload, err := authority.queryLease(ctx, recoveryHeartbeatOperationSQL, lease, leaseSeconds)
	var result struct {
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.LeaseExpiresAt.IsZero() || result.LeaseExpiresAt.Location() != time.UTC {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) BeginHold(ctx context.Context, lease recoveryOperationLease) error {
	payload, err := authority.queryLease(ctx, recoveryBeginHoldSQL, lease)
	var result struct {
		Epoch int64  `json:"epoch"`
		State string `json:"state"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.State != "held" || result.Epoch < 1 {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) ReleaseHold(ctx context.Context, lease recoveryOperationLease) error {
	payload, err := authority.queryLease(ctx, recoveryReleaseHoldSQL, lease)
	var result struct {
		Released bool `json:"released"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || !result.Released {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) CapturePage(ctx context.Context, lease recoveryOperationLease, section string, after *string, limit int) (recoveryCapturePage, error) {
	if !validRecoveryLease(lease) || !stringInWorker(section, "configuration", "projection", "evidence", "counts") || limit < 1 || limit > 100 {
		return recoveryCapturePage{}, errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryCapturePageSQL, recoveryLeaseArguments(lease, section, after, limit)...)
	var result recoveryCapturePage
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.Section != section {
		return recoveryCapturePage{}, errWorkerExecution
	}
	return result, nil
}

func (authority *postgresRecoveryOperationAuthority) FinishBackup(ctx context.Context, lease recoveryOperationLease, manifest apiserver.RecoveryManifestLocator) error {
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) > 8192 {
		return errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryFinishBackupSQL, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken), json.RawMessage(encoded))
	var result struct {
		State          string `json:"state"`
		Replayed       bool   `json:"replayed"`
		ManifestDigest string `json:"manifest_digest"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || result.State != "succeeded" || result.ManifestDigest == "" {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) Fail(ctx context.Context, lease recoveryOperationLease, code string, retry time.Duration, cleanup *apiserver.RecoveryCleanupEvidence) error {
	if retry < 0 || retry > 24*time.Hour || retry%time.Second != 0 {
		return errWorkerExecution
	}
	var cleanupJSON any
	if cleanup != nil {
		encoded, err := json.Marshal(cleanup)
		if err != nil || len(encoded) > 8192 {
			return errWorkerExecution
		}
		cleanupJSON = json.RawMessage(encoded)
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryFailOperationSQL, lease.Kind, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken), code, int(retry/time.Second), cleanupJSON)
	var result struct {
		State string `json:"state"`
	}
	if err != nil || decodeStrictWorkerJSON(payload, &result) != nil || !stringInWorker(result.State, "retryable", "failed") {
		return errWorkerExecution
	}
	return nil
}

func (authority *postgresRecoveryOperationAuthority) PostgresLSN(ctx context.Context, scope domain.Scope) (string, error) {
	if authority == nil || scope.Validate() != nil || ctx == nil || ctx.Err() != nil {
		return "", errWorkerExecution
	}
	payload, err := authority.database.QueryJSON(ctx, recoveryCurrentLSNSQL)
	var value string
	if err != nil || decodeStrictWorkerJSON(payload, &value) != nil || value == "" {
		return "", errWorkerExecution
	}
	return value, nil
}

func (authority *postgresRecoveryOperationAuthority) queryLease(ctx context.Context, statement string, lease recoveryOperationLease, trailing ...any) (json.RawMessage, error) {
	if authority == nil || !validRecoveryLease(lease) || ctx == nil || ctx.Err() != nil {
		return nil, errWorkerExecution
	}
	arguments := []any{lease.Kind, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken)}
	if statement != recoveryHeartbeatOperationSQL {
		arguments = arguments[1:]
	}
	arguments = append(arguments, trailing...)
	return authority.database.QueryJSON(ctx, statement, arguments...)
}

func recoveryLeaseArguments(lease recoveryOperationLease, trailing ...any) []any {
	return append([]any{lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.OperationID, lease.WorkerID, []byte(lease.LeaseToken)}, trailing...)
}

func validRecoveryLease(lease recoveryOperationLease) bool {
	return validRecoveryOperationClaim(lease.recoveryOperationClaim) && workerIdentityPattern.MatchString(lease.WorkerID) && len(lease.LeaseToken) == 32
}

func recoveryScope(organization, workspace, environment string) (domain.Scope, bool) {
	organizationID, organizationErr := domain.ParseProductID(organization)
	workspaceID, workspaceErr := domain.ParseProductID(workspace)
	environmentID, environmentErr := domain.ParseProductID(environment)
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	return scope, organizationErr == nil && workspaceErr == nil && environmentErr == nil && err == nil
}

var _ recoveryOperationAuthority = (*postgresRecoveryOperationAuthority)(nil)
