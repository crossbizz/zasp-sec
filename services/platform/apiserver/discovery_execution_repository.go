package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/riskprojection"
)

const (
	DiscoveryExecutionSchemaVersion             = "production-discovery-execution-v1"
	DiscoveryExecutionAuthorityScheduler        = "zasp_discovery_scheduler"
	DiscoveryExecutionAuthorityWorker           = "zasp_discovery_worker"
	DiscoveryExecutionAuthorityProjectionRisk   = "zasp_projection_risk_worker"
	DiscoveryExecutionAuthorityProjectionGraph  = "zasp_projection_graph_worker"
	DiscoveryExecutionAuthorityProjectionSearch = "zasp_projection_search_worker"

	postgresExecutionReadySQL               = `SELECT to_jsonb(zasp_execution_readiness($1,$2))`
	postgresExecutionPrincipalReadySQL      = `SELECT to_jsonb(zasp_execution_principal_ready($1))`
	postgresExecutionRequestSyncSQL         = `SELECT zasp_execution_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresExecutionJobInputSQL            = `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`
	postgresExecutionClaimDeliverySQL       = `SELECT zasp_execution_claim_delivery($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionHeartbeatJobSQL        = `SELECT zasp_execution_heartbeat_job($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionCheckpointPartialSQL   = `SELECT zasp_execution_checkpoint_partial($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`
	postgresExecutionFinishJobSQL           = `SELECT zasp_execution_finish_job($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,''),$11)`
	postgresExecutionClaimJobsSQL           = `SELECT zasp_execution_claim_jobs($1,$2,$3,$4)`
	postgresExecutionScheduleInputSQL       = `SELECT zasp_execution_schedule_input($1,$2,$3,$4,$5,$6)`
	postgresExecutionHeartbeatScheduleSQL   = `SELECT zasp_execution_heartbeat_schedule($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionClaimSchedulesSQL      = `SELECT zasp_execution_claim_schedules($1,$2,$3,$4)`
	postgresExecutionScheduledSyncSQL       = `SELECT zasp_execution_request_scheduled_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	postgresExecutionCompleteScheduleSQL    = `SELECT zasp_execution_complete_schedule($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresExecutionApplySnapshotSQL       = `SELECT zasp_execution_apply_complete_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24::jsonb,$25::jsonb)`
	postgresExecutionProjectionPageSQL      = `SELECT zasp_execution_snapshot_projection_page($1,$2,$3,$4,$5,NULLIF($6,''),$7)`
	postgresExecutionProjectionStatusSQL    = `SELECT zasp_execution_projection_status($1,$2,$3,$4)`
	postgresExecutionClaimProjectionSQL     = `SELECT zasp_execution_claim_projection_work($1,$2,$3,$4,$5)`
	postgresExecutionHeartbeatProjectionSQL = `SELECT zasp_execution_heartbeat_projection($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresExecutionFinishProjectionSQL    = `SELECT zasp_execution_finish_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresExecutionApplyRiskProjectionSQL = `SELECT zasp_execution_apply_risk_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`
	postgresExecutionBindSubjectSQL         = `SELECT zasp_execution_bind_connection_subject($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`
)

var executionVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
var riskProjectionReceiptPattern = regexp.MustCompile(`^postgres:risk-input:pid_[0-9a-f-]{36}:sha256:[0-9a-f]{64}$`)

type DiscoveryExecutionRepository struct {
	database  JSONDatabase
	authority string
}

func NewDiscoveryExecutionRepository(database JSONDatabase, authority string) (*DiscoveryExecutionRepository, error) {
	return newDiscoveryExecutionRepository(database, authority, 5*time.Second)
}

func newDiscoveryExecutionRepository(database JSONDatabase, authority string, readinessTimeout time.Duration) (*DiscoveryExecutionRepository, error) {
	if nilInterface(database) || !stringIn(authority, DiscoveryExecutionAuthorityScheduler, DiscoveryExecutionAuthorityWorker, DiscoveryExecutionAuthorityProjectionRisk, DiscoveryExecutionAuthorityProjectionGraph, DiscoveryExecutionAuthorityProjectionSearch) {
		return nil, ErrRepositoryConfiguration
	}
	if readinessTimeout <= 0 || readinessTimeout > 5*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	probeContext, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	repository := &DiscoveryExecutionRepository{database: database, authority: authority}
	if err := repository.Ready(probeContext); err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *DiscoveryExecutionRepository) Ready(ctx context.Context) error {
	if !validExecutionRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	if !discoveryExecutionReady(ctx, repository.database) {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPrincipalReadySQL, repository.authority)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func discoveryExecutionReady(ctx context.Context, database JSONDatabase) bool {
	if ctx == nil || ctx.Err() != nil || nilInterface(database) {
		return false
	}
	var ready bool
	for _, version := range []string{RuntimeIngestReconciliationSchemaVersion, RuntimeGatewayReconciliationSchemaVersion, RuntimeDataPlaneSchemaVersion, TypedInventorySchemaVersion, DiscoveryExecutionSchemaVersion} {
		readySQL, checksum, fingerprint, _ := exactProductReadiness(version)
		payload, err := database.QueryJSON(ctx, readySQL, checksum, fingerprint)
		ready = false
		if err == nil && decodeStrictDiscovery(payload, &ready) == nil && ready {
			return true
		}
	}
	return false
}

type ExecutionJobInput struct {
	OrganizationID                  string                     `json:"organization_id"`
	WorkspaceID                     string                     `json:"workspace_id"`
	EnvironmentID                   string                     `json:"environment_id"`
	JobID                           string                     `json:"job_id"`
	Attempt                         int                        `json:"attempt"`
	LeaseExpiresAt                  time.Time                  `json:"lease_expires_at"`
	SyncID                          string                     `json:"sync_id"`
	IntegrationID                   string                     `json:"integration_id"`
	ConnectionID                    string                     `json:"connection_id"`
	SnapshotID                      string                     `json:"snapshot_id"`
	Generation                      int64                      `json:"generation"`
	ObservationTime                 time.Time                  `json:"observation_time"`
	Provider                        collection.Provider        `json:"provider"`
	CollectorVersion                string                     `json:"collector_version"`
	CredentialClass                 collection.CredentialClass `json:"credential_class"`
	CredentialReference             string                     `json:"credential_reference"`
	SubjectKind                     string                     `json:"subject_kind"`
	SubjectID                       string                     `json:"subject_id"`
	CursorProvider                  *collection.Provider       `json:"cursor_provider"`
	CursorVersion                   *string                    `json:"cursor_version"`
	CursorValue                     *string                    `json:"cursor_value"`
	ParserVersion                   string                     `json:"parser_version"`
	ToolVersion                     string                     `json:"tool_version"`
	Configuration                   json.RawMessage            `json:"configuration"`
	CheckpointVersion               int64                      `json:"checkpoint_version"`
	CheckpointDigest                []byte                     `json:"checkpoint_digest"`
	CheckpointManifestReference     string                     `json:"checkpoint_manifest_reference"`
	CheckpointManifestKey           string                     `json:"checkpoint_manifest_key"`
	CheckpointManifestVersionID     string                     `json:"checkpoint_manifest_version_id"`
	CheckpointManifestChecksum      []byte                     `json:"checkpoint_manifest_checksum"`
	CheckpointManifestSizeBytes     int64                      `json:"checkpoint_manifest_size_bytes"`
	CheckpointManifestMediaType     string                     `json:"checkpoint_manifest_media_type"`
	CheckpointManifestSchemaVersion string                     `json:"checkpoint_manifest_schema_version"`
	ExpectedSubject                 collection.SubjectBinding  `json:"-"`
}

type DiscoveryDeliveryClaim struct {
	ID             string     `json:"id"`
	Disposition    string     `json:"disposition"`
	State          string     `json:"state"`
	AuthorityID    string     `json:"authority_id,omitempty"`
	Attempt        int        `json:"attempt"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
}

func (repository *DiscoveryExecutionRepository) ClaimDiscoveryDelivery(ctx context.Context, scope domain.Scope, jobID, worker, leaseToken string, leaseSeconds int) (DiscoveryDeliveryClaim, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(jobID) || !validWorkerLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 {
		return DiscoveryDeliveryClaim{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionClaimDeliverySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), jobID, worker, leaseToken, leaseSeconds)
	if err != nil {
		return DiscoveryDeliveryClaim{}, discoveryProviderError(err)
	}
	var result DiscoveryDeliveryClaim
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != jobID || result.Attempt < 0 || result.Attempt > 5 || !stringIn(result.Disposition, "claimed", "busy", "ack_terminal") {
		return DiscoveryDeliveryClaim{}, ErrRepositoryUnavailable
	}
	switch result.Disposition {
	case "claimed":
		if result.State != "leased" || !validProductID(result.AuthorityID) || result.LeaseExpiresAt == nil || !validLeaseExpiration(*result.LeaseExpiresAt, leaseSeconds) || result.Attempt < 1 {
			return DiscoveryDeliveryClaim{}, ErrRepositoryUnavailable
		}
		expiresAt := result.LeaseExpiresAt.UTC()
		result.LeaseExpiresAt = &expiresAt
	case "busy":
		if result.LeaseExpiresAt != nil || result.AuthorityID != "" || !stringIn(result.State, "queued", "retryable", "leased") {
			return DiscoveryDeliveryClaim{}, ErrRepositoryUnavailable
		}
	case "ack_terminal":
		if result.LeaseExpiresAt != nil || result.AuthorityID != "" || !stringIn(result.State, "succeeded", "failed", "cancelled") {
			return DiscoveryDeliveryClaim{}, ErrRepositoryUnavailable
		}
	}
	return result, nil
}

func (repository *DiscoveryExecutionRepository) GetDiscoveryJobInput(ctx context.Context, scope domain.Scope, jobID, worker, leaseToken string) (ExecutionJobInput, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(jobID) || !validWorkerLease(worker, leaseToken) {
		return ExecutionJobInput{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionJobInputSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), jobID, worker, leaseToken)
	if err != nil {
		return ExecutionJobInput{}, discoveryProviderError(err)
	}
	var result ExecutionJobInput
	if decodeStrictDiscovery(payload, &result) != nil || !validExecutionJobInput(scope, jobID, result) {
		return ExecutionJobInput{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	result.ExpectedSubject = collection.SubjectBinding{Kind: result.SubjectKind, ID: result.SubjectID}
	result.Configuration = append(json.RawMessage(nil), result.Configuration...)
	return result, nil
}

type JobHeartbeat struct {
	JobID, Worker, LeaseToken string
	LeaseSeconds              int
}

type LeaseHeartbeatResult struct {
	ID             string    `json:"id"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

func (repository *DiscoveryExecutionRepository) HeartbeatDiscoveryJob(ctx context.Context, scope domain.Scope, input JobHeartbeat) (LeaseHeartbeatResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(input.JobID) || !validWorkerLease(input.Worker, input.LeaseToken) || input.LeaseSeconds < 5 || input.LeaseSeconds > 900 {
		return LeaseHeartbeatResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionHeartbeatJobSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.JobID, input.Worker, input.LeaseToken, input.LeaseSeconds)
	if err != nil {
		return LeaseHeartbeatResult{}, discoveryProviderError(err)
	}
	var result LeaseHeartbeatResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.JobID || !validLeaseExpiration(result.LeaseExpiresAt, input.LeaseSeconds) {
		return LeaseHeartbeatResult{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	return result, nil
}

type ExecutionPartialCheckpoint struct {
	JobID, Worker, LeaseToken                                            string
	ExpectedVersion                                                      int64
	CursorProvider                                                       collection.Provider
	CursorVersion, CursorValue                                           string
	ManifestReference, ManifestKey, ManifestVersionID                    string
	ManifestChecksum                                                     []byte
	ManifestSizeBytes                                                    int64
	ManifestMediaType, ManifestSchemaVersion, ParserVersion, ToolVersion string
}

type ExecutionPartialCheckpointResult struct {
	ID                string              `json:"id"`
	Version           int64               `json:"version"`
	CheckpointDigest  []byte              `json:"checkpoint_digest"`
	CursorProvider    collection.Provider `json:"cursor_provider"`
	CursorVersion     string              `json:"cursor_version"`
	CursorValue       string              `json:"cursor_value"`
	ManifestVersionID string              `json:"manifest_version_id"`
	UpdatedAt         time.Time           `json:"updated_at"`
}

func (repository *DiscoveryExecutionRepository) CheckpointPartialDiscoveryJob(ctx context.Context, scope domain.Scope, input ExecutionPartialCheckpoint) (ExecutionPartialCheckpointResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(input.JobID) || !validWorkerLease(input.Worker, input.LeaseToken) || input.ExpectedVersion < 0 || input.ExpectedVersion > 9999 || !stringIn(string(input.CursorProvider), "aws", "kubernetes", "github", "okta") || !executionVersionPattern.MatchString(input.CursorVersion) || len(input.CursorValue) < 1 || len(input.CursorValue) > 2048 || !validS3ObjectReference(input.ManifestReference) || len(input.ManifestKey) < 32 || len(input.ManifestKey) > 1024 || !strings.HasSuffix(input.ManifestReference, "/"+input.ManifestKey) || len(input.ManifestReference) != strings.LastIndex(input.ManifestReference, "/"+input.ManifestKey)+1+len(input.ManifestKey) || len(input.ManifestVersionID) < 1 || len(input.ManifestVersionID) > 1024 || len(input.ManifestChecksum) != sha256.Size || bytes.Equal(input.ManifestChecksum, make([]byte, sha256.Size)) || input.ManifestSizeBytes < 1 || input.ManifestSizeBytes > 512<<20 || input.ManifestMediaType != "application/json" || !executionVersionPattern.MatchString(input.ManifestSchemaVersion) || !executionVersionPattern.MatchString(input.ParserVersion) || !executionVersionPattern.MatchString(input.ToolVersion) {
		return ExecutionPartialCheckpointResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionCheckpointPartialSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.JobID, input.Worker, input.LeaseToken, input.ExpectedVersion, input.CursorProvider, input.CursorVersion, input.CursorValue, input.ManifestReference, input.ManifestKey, input.ManifestVersionID, input.ManifestChecksum, input.ManifestSizeBytes, input.ManifestMediaType, input.ManifestSchemaVersion, input.ParserVersion, input.ToolVersion)
	if err != nil {
		return ExecutionPartialCheckpointResult{}, discoveryProviderError(err)
	}
	var result ExecutionPartialCheckpointResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.JobID || result.Version < 1 || result.Version > 10000 || len(result.CheckpointDigest) != sha256.Size || result.CursorProvider != input.CursorProvider || result.CursorVersion != input.CursorVersion || result.CursorValue != input.CursorValue || result.ManifestVersionID != input.ManifestVersionID || !validPastServerTime(result.UpdatedAt) {
		return ExecutionPartialCheckpointResult{}, ErrRepositoryUnavailable
	}
	result.CheckpointDigest = bytes.Clone(result.CheckpointDigest)
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func (repository *DiscoveryExecutionRepository) FinishDiscoveryJob(ctx context.Context, scope domain.Scope, input DiscoveryJobCompletion) (WorkCompletionResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(input.ID) || !validWorkerLease(input.Worker, input.LeaseToken) || !stringIn(input.Outcome, "succeeded", "retryable", "failed", "cancelled") || input.Outcome == "succeeded" && (len(input.ResultDigest) != sha256.Size || input.LastErrorCode != "" || input.LastError != "") || input.Outcome != "succeeded" && (len(input.ResultDigest) != 0 && len(input.ResultDigest) != sha256.Size || !stringIn(input.LastErrorCode, "retryable", "rate_limited", "denied", "revoked", "malformed", "partial", "terminal", "cancelled", "outcome_unknown") || len(input.LastError) < 1 || len(input.LastError) > 1024) || input.RetryAfterSeconds < 0 || input.RetryAfterSeconds > 3600 {
		return WorkCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionFinishJobSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.Worker, input.LeaseToken, input.Outcome, input.ResultDigest, input.LastErrorCode, input.LastError, input.RetryAfterSeconds)
	if err != nil {
		return WorkCompletionResult{}, discoveryProviderError(err)
	}
	var result WorkCompletionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || !validCompletionState(input.Outcome, result.State) || result.Attempt < 1 || result.Attempt > 5 || (result.State == "retryable") != (result.CompletedAt == nil) || result.CompletedAt != nil && !validPastServerTime(*result.CompletedAt) {
		return WorkCompletionResult{}, ErrRepositoryUnavailable
	}
	if result.CompletedAt != nil {
		completedAt := result.CompletedAt.UTC()
		result.CompletedAt = &completedAt
	}
	return result, nil
}

func (repository *DiscoveryExecutionRepository) ClaimDiscoveryJobs(ctx context.Context, worker, leaseToken string, leaseSeconds, limit int) ([]DiscoveryJobLease, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || !validWorkerLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 64 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionClaimJobsSQL, worker, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []DiscoveryJobLease `json:"items"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.AuthorityID) || item.Kind != "discovery" || item.Attempt < 1 || item.Attempt > 5 || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

type ExecutionScheduleInput struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	ScheduleID     string    `json:"schedule_id"`
	IntegrationID  string    `json:"integration_id"`
	CadenceSeconds int       `json:"cadence_seconds"`
	TimeZone       string    `json:"time_zone"`
	NextRunAt      time.Time `json:"next_run_at"`
	Version        int64     `json:"version"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

func (repository *DiscoveryExecutionRepository) ClaimDiscoverySchedules(ctx context.Context, worker, leaseToken string, leaseSeconds, limit int) ([]DiscoveryScheduleLease, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityScheduler || !validWorkerLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 64 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionClaimSchedulesSQL, worker, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []DiscoveryScheduleLease `json:"items"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.IntegrationID) || item.NextRunAt.IsZero() || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) {
			return nil, ErrRepositoryUnavailable
		}
		item.NextRunAt, item.LeaseExpiresAt = item.NextRunAt.UTC(), item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

func (repository *DiscoveryExecutionRepository) GetDiscoveryScheduleInput(ctx context.Context, scope domain.Scope, scheduleID, worker, leaseToken string) (ExecutionScheduleInput, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityScheduler || scope.Validate() != nil || !validProductID(scheduleID) || !validWorkerLease(worker, leaseToken) {
		return ExecutionScheduleInput{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionScheduleInputSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), scheduleID, worker, leaseToken)
	if err != nil {
		return ExecutionScheduleInput{}, discoveryProviderError(err)
	}
	var result ExecutionScheduleInput
	if decodeStrictDiscovery(payload, &result) != nil || result.OrganizationID != scope.OrganizationID().String() || result.WorkspaceID != scope.WorkspaceID().String() || result.EnvironmentID != scope.EnvironmentID().String() || result.ScheduleID != scheduleID || !validProductID(result.IntegrationID) || result.CadenceSeconds < 300 || result.CadenceSeconds > 2678400 || len(result.TimeZone) < 1 || len(result.TimeZone) > 64 || result.NextRunAt.IsZero() || result.Version < 1 || !validLeaseExpiration(result.LeaseExpiresAt, 900) {
		return ExecutionScheduleInput{}, ErrRepositoryUnavailable
	}
	result.NextRunAt, result.LeaseExpiresAt = result.NextRunAt.UTC(), result.LeaseExpiresAt.UTC()
	return result, nil
}

type ScheduleHeartbeat struct {
	ScheduleID, Worker, LeaseToken string
	LeaseSeconds                   int
}

func (repository *DiscoveryExecutionRepository) HeartbeatDiscoverySchedule(ctx context.Context, scope domain.Scope, input ScheduleHeartbeat) (LeaseHeartbeatResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityScheduler || scope.Validate() != nil || !validProductID(input.ScheduleID) || !validWorkerLease(input.Worker, input.LeaseToken) || input.LeaseSeconds < 5 || input.LeaseSeconds > 900 {
		return LeaseHeartbeatResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionHeartbeatScheduleSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ScheduleID, input.Worker, input.LeaseToken, input.LeaseSeconds)
	if err != nil {
		return LeaseHeartbeatResult{}, discoveryProviderError(err)
	}
	var result LeaseHeartbeatResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ScheduleID || !validLeaseExpiration(result.LeaseExpiresAt, input.LeaseSeconds) {
		return LeaseHeartbeatResult{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	return result, nil
}

type ScheduledSyncRequest struct {
	ScheduleID, Worker, LeaseToken string
	SyncRequest
}

func (repository *DiscoveryExecutionRepository) RequestScheduledSync(ctx context.Context, identity RequestIdentity, input ScheduledSyncRequest) (SyncRequestResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityScheduler || !validRequestIdentity(identity, false) || !validProductID(input.ScheduleID) || !validWorkerLease(input.Worker, input.LeaseToken) || !validSyncRequest(input.SyncRequest) || input.TriggerKind != "schedule" {
		return SyncRequestResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionScheduledSyncSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.ScheduleID, input.Worker, input.LeaseToken, input.IntegrationID, input.SyncID, input.JobID, input.OutboxID, input.IdempotencyKey, input.RequestDigest, input.ParserVersion, input.ToolVersion)
	if err != nil {
		return SyncRequestResult{}, discoveryProviderError(err)
	}
	var result SyncRequestResult
	if decodeStrictDiscovery(payload, &result) != nil || !validSyncRequestResult(input.SyncRequest, result) {
		return SyncRequestResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *DiscoveryExecutionRepository) CompleteDiscoverySchedule(ctx context.Context, scope domain.Scope, input DiscoveryScheduleCompletion) (DiscoveryScheduleCompletionResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityScheduler || scope.Validate() != nil || !validProductID(input.ID) || !validWorkerLease(input.Worker, input.LeaseToken) || !stringIn(input.Outcome, "advanced", "released", "disabled") || input.NextRunAt.IsZero() || input.NextRunAt.Location() != time.UTC {
		return DiscoveryScheduleCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionCompleteScheduleSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.ID, input.Worker, input.LeaseToken, input.Outcome, input.NextRunAt)
	if err != nil {
		return DiscoveryScheduleCompletionResult{}, discoveryProviderError(err)
	}
	var result DiscoveryScheduleCompletionResult
	wantState := "enabled"
	if input.Outcome == "disabled" {
		wantState = "disabled"
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.State != wantState || !result.NextRunAt.Equal(input.NextRunAt) || result.Version < 1 {
		return DiscoveryScheduleCompletionResult{}, ErrRepositoryUnavailable
	}
	result.NextRunAt = result.NextRunAt.UTC()
	return result, nil
}

type ExecutionCompleteSnapshot struct {
	CompleteSnapshot
	JobID, Worker, LeaseToken                                                                            string
	ManifestKey, ManifestVersionID, ManifestMediaType, ManifestSchemaVersion, ParserVersion, ToolVersion string
	ManifestSizeBytes                                                                                    int64
}

type ExecutionSnapshotApplyResult struct {
	SnapshotApplyResult
	CandidateDigest   []byte `json:"candidate_digest"`
	ManifestVersionID string `json:"manifest_version_id"`
}

func (repository *DiscoveryExecutionRepository) ApplyCompleteSnapshot(ctx context.Context, scope domain.Scope, input ExecutionCompleteSnapshot) (ExecutionSnapshotApplyResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validProductID(input.JobID) || !validWorkerLease(input.Worker, input.LeaseToken) || !validCompleteSnapshot(input.CompleteSnapshot) || len(input.ManifestKey) < 32 || len(input.ManifestKey) > 1024 || !strings.HasSuffix(input.ManifestReference, "/"+input.ManifestKey) || len(input.ManifestReference) != strings.LastIndex(input.ManifestReference, "/"+input.ManifestKey)+1+len(input.ManifestKey) || len(input.ManifestVersionID) < 1 || len(input.ManifestVersionID) > 1024 || input.ManifestSizeBytes < 1 || input.ManifestSizeBytes > 512<<20 || input.ManifestMediaType != "application/json" || !executionVersionPattern.MatchString(input.ManifestSchemaVersion) || !executionVersionPattern.MatchString(input.ParserVersion) || !executionVersionPattern.MatchString(input.ToolVersion) {
		return ExecutionSnapshotApplyResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionApplySnapshotSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.JobID, input.Worker, input.LeaseToken, input.IntegrationID, input.SyncID, input.SnapshotID, input.Generation, input.Source, input.ManifestReference, input.ManifestKey, input.ManifestVersionID, input.ManifestChecksum, input.ManifestSizeBytes, input.ManifestMediaType, input.ManifestSchemaVersion, input.CollectedAt, input.CursorValue, input.ParserVersion, input.ToolVersion, input.Entities, input.Relationships, input.Evidence)
	if err != nil {
		return ExecutionSnapshotApplyResult{}, discoveryProviderError(err)
	}
	var result ExecutionSnapshotApplyResult
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID || len(result.CandidateDigest) != sha256.Size || result.ManifestVersionID != input.ManifestVersionID || result.DiscoveredCount < 0 || result.ChangedCount < 0 || result.RemovedCount < 0 || !validPastServerTime(result.CommittedAt) {
		return ExecutionSnapshotApplyResult{}, ErrRepositoryUnavailable
	}
	result.CommittedAt = result.CommittedAt.UTC()
	result.CandidateDigest = bytes.Clone(result.CandidateDigest)
	return result, nil
}

type SnapshotProjectionPage struct {
	SnapshotID, IntegrationID, Source                                             string
	Generation                                                                    int64
	CandidateDigest                                                               []byte
	ManifestReference, ManifestKey, ManifestVersionID                             string
	ManifestChecksum                                                              []byte
	ManifestSizeBytes                                                             int64
	ManifestMediaType, ManifestSchemaVersion, ParserVersion, ToolVersion, Section string
	Items                                                                         []json.RawMessage
	NextID                                                                        *string
}

func (repository *DiscoveryExecutionRepository) GetSnapshotProjectionPage(ctx context.Context, scope domain.Scope, snapshotID, section, afterID string, limit int) (SnapshotProjectionPage, error) {
	if !validExecutionRepository(repository, ctx) || !isProjectionAuthority(repository.authority) || scope.Validate() != nil || !validProductID(snapshotID) || !stringIn(section, "entities", "relationships", "evidence") || afterID != "" && !validProductID(afterID) || limit < 1 || limit > 500 {
		return SnapshotProjectionPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionProjectionPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), snapshotID, section, afterID, limit)
	if err != nil {
		return SnapshotProjectionPage{}, discoveryProviderError(err)
	}
	// Decode through an explicitly tagged envelope so unknown fields remain rejected.
	var envelope struct {
		SnapshotID            string            `json:"snapshot_id"`
		IntegrationID         string            `json:"integration_id"`
		Source                string            `json:"source"`
		Generation            int64             `json:"generation"`
		CandidateDigest       []byte            `json:"candidate_digest"`
		ManifestReference     string            `json:"manifest_reference"`
		ManifestKey           string            `json:"manifest_key"`
		ManifestVersionID     string            `json:"manifest_version_id"`
		ManifestChecksum      []byte            `json:"manifest_checksum"`
		ManifestSizeBytes     int64             `json:"manifest_size_bytes"`
		ManifestMediaType     string            `json:"manifest_media_type"`
		ManifestSchemaVersion string            `json:"manifest_schema_version"`
		ParserVersion         string            `json:"parser_version"`
		ToolVersion           string            `json:"tool_version"`
		Section               string            `json:"section"`
		Items                 []json.RawMessage `json:"items"`
		NextID                *string           `json:"next_id"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.SnapshotID != snapshotID || !validProductID(envelope.IntegrationID) || !stringIn(envelope.Source, "aws", "kubernetes", "github", "okta") || envelope.Generation < 1 || len(envelope.CandidateDigest) != sha256.Size || !validS3ObjectReference(envelope.ManifestReference) || len(envelope.ManifestKey) < 32 || len(envelope.ManifestKey) > 1024 || len(envelope.ManifestVersionID) < 1 || len(envelope.ManifestVersionID) > 1024 || len(envelope.ManifestChecksum) != sha256.Size || envelope.ManifestSizeBytes < 1 || envelope.ManifestSizeBytes > 512<<20 || envelope.ManifestMediaType != "application/json" || !executionVersionPattern.MatchString(envelope.ManifestSchemaVersion) || !executionVersionPattern.MatchString(envelope.ParserVersion) || !executionVersionPattern.MatchString(envelope.ToolVersion) || envelope.Section != section || envelope.Items == nil || len(envelope.Items) > limit {
		return SnapshotProjectionPage{}, ErrRepositoryUnavailable
	}
	lastID := afterID
	items := make([]json.RawMessage, len(envelope.Items))
	for index, item := range envelope.Items {
		var identity struct {
			ID string `json:"id"`
		}
		if !discoveryValidJSONObject(item, 1<<20) || json.Unmarshal(item, &identity) != nil || !validProductID(identity.ID) || identity.ID <= lastID {
			return SnapshotProjectionPage{}, ErrRepositoryUnavailable
		}
		lastID = identity.ID
		items[index] = bytes.Clone(item)
	}
	if envelope.NextID != nil && (len(envelope.Items) != limit || *envelope.NextID != lastID) {
		return SnapshotProjectionPage{}, ErrRepositoryUnavailable
	}
	return SnapshotProjectionPage{
		SnapshotID: envelope.SnapshotID, IntegrationID: envelope.IntegrationID, Source: envelope.Source, Generation: envelope.Generation,
		CandidateDigest: bytes.Clone(envelope.CandidateDigest), ManifestReference: envelope.ManifestReference, ManifestKey: envelope.ManifestKey,
		ManifestVersionID: envelope.ManifestVersionID, ManifestChecksum: bytes.Clone(envelope.ManifestChecksum), ManifestSizeBytes: envelope.ManifestSizeBytes,
		ManifestMediaType: envelope.ManifestMediaType, ManifestSchemaVersion: envelope.ManifestSchemaVersion, ParserVersion: envelope.ParserVersion,
		ToolVersion: envelope.ToolVersion, Section: envelope.Section, Items: items, NextID: envelope.NextID,
	}, nil
}

func (repository *DiscoveryExecutionRepository) ClaimProjectionWork(ctx context.Context, kind, worker, leaseToken string, leaseSeconds, limit int) ([]ProjectionWorkLease, error) {
	if !validExecutionRepository(repository, ctx) || projectionAuthority(kind) != repository.authority || !validWorkerLease(worker, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 64 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionClaimProjectionSQL, kind, worker, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []ProjectionWorkLease `json:"items"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.SnapshotID) || item.Kind != kind || !executionVersionPattern.MatchString(item.Version) || len(item.InputDigest) != sha256.Size || item.Attempt < 1 || item.Attempt > 5 || item.AvailableAt.IsZero() || item.AvailableAt.After(time.Now().UTC()) || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) {
			return nil, ErrRepositoryUnavailable
		}
		item.InputDigest = bytes.Clone(item.InputDigest)
		item.AvailableAt = item.AvailableAt.UTC()
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

type ProjectionHeartbeat struct {
	SnapshotID, Kind, Version, Worker, LeaseToken string
	LeaseSeconds                                  int
}

func (repository *DiscoveryExecutionRepository) HeartbeatProjectionWork(ctx context.Context, scope domain.Scope, input ProjectionHeartbeat) (LeaseHeartbeatResult, error) {
	if !validExecutionRepository(repository, ctx) || projectionAuthority(input.Kind) != repository.authority || scope.Validate() != nil || !validProductID(input.SnapshotID) || !executionVersionPattern.MatchString(input.Version) || !validWorkerLease(input.Worker, input.LeaseToken) || input.LeaseSeconds < 5 || input.LeaseSeconds > 900 {
		return LeaseHeartbeatResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionHeartbeatProjectionSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SnapshotID, input.Kind, input.Version, input.Worker, input.LeaseToken, input.LeaseSeconds)
	if err != nil {
		return LeaseHeartbeatResult{}, discoveryProviderError(err)
	}
	var result LeaseHeartbeatResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.SnapshotID || !validLeaseExpiration(result.LeaseExpiresAt, input.LeaseSeconds) {
		return LeaseHeartbeatResult{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	return result, nil
}

func (repository *DiscoveryExecutionRepository) ApplyRiskProjectionInput(ctx context.Context, input riskprojection.CompleteInput) (riskprojection.ApplyResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityProjectionRisk || input.Scope.Validate() != nil ||
		!validProductID(input.IntegrationID.String()) || !validProductID(input.SnapshotID.String()) || !stringIn(input.Source, "aws", "kubernetes", "github", "okta") ||
		input.Generation < 1 || !executionVersionPattern.MatchString(input.Version) || !validWorkerLease(input.Worker, input.LeaseToken) || input.InputDigest == [sha256.Size]byte{} ||
		input.Items == nil || len(input.Items) > 4_000 {
		return riskprojection.ApplyResult{}, ErrRepositoryOperation
	}
	type storedItem struct {
		Section string          `json:"section"`
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	items := make([]storedItem, len(input.Items))
	lastKey := ""
	for index, item := range input.Items {
		key := item.Section + ":" + item.ID.String()
		var identity struct {
			ID string `json:"id"`
		}
		if !stringIn(item.Section, "entities", "relationships", "evidence") || !validProductID(item.ID.String()) || !discoveryValidJSONObject(item.Payload, 1<<20) ||
			json.Unmarshal(item.Payload, &identity) != nil || identity.ID != item.ID.String() || key <= lastKey {
			return riskprojection.ApplyResult{}, ErrRepositoryOperation
		}
		lastKey = key
		items[index] = storedItem{Section: item.Section, ID: item.ID.String(), Payload: bytes.Clone(item.Payload)}
	}
	encoded, err := json.Marshal(items)
	if err != nil || len(encoded) > 64<<20 {
		return riskprojection.ApplyResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionApplyRiskProjectionSQL,
		input.Scope.OrganizationID().String(), input.Scope.WorkspaceID().String(), input.Scope.EnvironmentID().String(), input.SnapshotID.String(), input.Version,
		input.Worker, input.LeaseToken, input.IntegrationID.String(), input.Source, input.Generation, input.InputDigest[:], encoded)
	if err != nil {
		return riskprojection.ApplyResult{}, discoveryProviderError(err)
	}
	var result struct {
		SnapshotID         string `json:"snapshot_id"`
		IntegrationID      string `json:"integration_id"`
		Source             string `json:"source"`
		Generation         int64  `json:"generation"`
		InputDigestValue   []byte `json:"input_digest"`
		ContentDigestValue []byte `json:"content_digest"`
		DriverReceipt      string `json:"driver_receipt"`
		Replayed           bool   `json:"replayed"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID.String() || result.IntegrationID != input.IntegrationID.String() ||
		result.Source != input.Source || result.Generation != input.Generation || len(result.InputDigestValue) != sha256.Size || !bytes.Equal(result.InputDigestValue, input.InputDigest[:]) ||
		len(result.ContentDigestValue) != sha256.Size || !riskProjectionReceiptPattern.MatchString(result.DriverReceipt) ||
		!strings.HasSuffix(result.DriverReceipt, hex.EncodeToString(result.ContentDigestValue)) {
		return riskprojection.ApplyResult{}, ErrRepositoryUnavailable
	}
	var contentDigest [sha256.Size]byte
	copy(contentDigest[:], result.ContentDigestValue)
	return riskprojection.ApplyResult{
		SnapshotID: input.SnapshotID, IntegrationID: input.IntegrationID, Source: input.Source, Generation: input.Generation,
		InputDigest: input.InputDigest, ContentDigest: contentDigest, Receipt: result.DriverReceipt, Replayed: result.Replayed,
	}, nil
}

func (repository *DiscoveryExecutionRepository) FinishProjectionWork(ctx context.Context, scope domain.Scope, input ProjectionWorkCompletion) (WorkCompletionResult, error) {
	if !validExecutionRepository(repository, ctx) || projectionAuthority(input.Kind) != repository.authority || scope.Validate() != nil || !validProductID(input.SnapshotID) || !executionVersionPattern.MatchString(input.Version) || !validWorkerLease(input.Worker, input.LeaseToken) || !stringIn(input.Outcome, "succeeded", "retryable", "failed", "cancelled") || input.Outcome == "succeeded" && (input.LastError != "" || len(input.DriverReceipt) < 16 || len(input.DriverReceipt) > 512 || len(input.DriverDigest) != sha256.Size) || input.Outcome != "succeeded" && (len(input.LastError) < 1 || len(input.LastError) > 1024 || input.DriverReceipt != "" || len(input.DriverDigest) != 0) || input.RetryAfterSeconds < 0 || input.RetryAfterSeconds > 3600 {
		return WorkCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionFinishProjectionSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SnapshotID, input.Kind, input.Version, input.Worker, input.LeaseToken, input.Outcome, input.DriverReceipt, input.DriverDigest, input.LastError, input.RetryAfterSeconds)
	if err != nil {
		return WorkCompletionResult{}, discoveryProviderError(err)
	}
	var result WorkCompletionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID || result.Kind != input.Kind || !validCompletionState(input.Outcome, result.State) || result.Attempt < 1 || result.Attempt > 5 || result.CompletedAt != nil {
		return WorkCompletionResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

type ProjectionStatusItem struct {
	Kind               string  `json:"kind"`
	WorkState          string  `json:"work_state"`
	WorkVersion        string  `json:"work_version"`
	WorkInputDigest    []byte  `json:"work_input_digest"`
	Attempt            int     `json:"attempt"`
	CurrentSnapshotID  *string `json:"current_snapshot_id"`
	CurrentGeneration  *int64  `json:"current_generation"`
	CurrentInputDigest []byte  `json:"current_input_digest"`
	Current            bool    `json:"current"`
}

type ProjectionStatus struct {
	IntegrationID string                 `json:"integration_id"`
	Source        string                 `json:"source"`
	SnapshotID    string                 `json:"snapshot_id"`
	Generation    int64                  `json:"generation"`
	InputDigest   []byte                 `json:"input_digest"`
	Projections   []ProjectionStatusItem `json:"projections"`
}

func (repository *DiscoveryExecutionRepository) GetProjectionStatus(ctx context.Context, scope domain.Scope, snapshotID string) (ProjectionStatus, error) {
	if !validExecutionRepository(repository, ctx) || !isProjectionAuthority(repository.authority) || scope.Validate() != nil || !validProductID(snapshotID) {
		return ProjectionStatus{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionProjectionStatusSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), snapshotID)
	if err != nil {
		return ProjectionStatus{}, discoveryProviderError(err)
	}
	var result ProjectionStatus
	if decodeStrictDiscovery(payload, &result) != nil || !validProductID(result.IntegrationID) || !stringIn(result.Source, "aws", "kubernetes", "github", "okta") || result.SnapshotID != snapshotID || result.Generation < 1 || len(result.InputDigest) != sha256.Size || len(result.Projections) != 3 {
		return ProjectionStatus{}, ErrRepositoryUnavailable
	}
	for index, kind := range []string{"graph", "risk", "search"} {
		item := &result.Projections[index]
		if item.Kind != kind || !stringIn(item.WorkState, "pending", "leased", "retryable", "succeeded", "failed", "cancelled") || !executionVersionPattern.MatchString(item.WorkVersion) || !bytes.Equal(item.WorkInputDigest, result.InputDigest) || item.Attempt < 0 || item.Attempt > 5 {
			return ProjectionStatus{}, ErrRepositoryUnavailable
		}
		if item.Current {
			if item.WorkState != "succeeded" || item.CurrentSnapshotID == nil || *item.CurrentSnapshotID != snapshotID || item.CurrentGeneration == nil || *item.CurrentGeneration != result.Generation || !bytes.Equal(item.CurrentInputDigest, result.InputDigest) {
				return ProjectionStatus{}, ErrRepositoryUnavailable
			}
		} else if item.CurrentSnapshotID == nil != (item.CurrentGeneration == nil) || item.CurrentSnapshotID == nil != (item.CurrentInputDigest == nil) {
			return ProjectionStatus{}, ErrRepositoryUnavailable
		}
		item.WorkInputDigest = bytes.Clone(item.WorkInputDigest)
		item.CurrentInputDigest = bytes.Clone(item.CurrentInputDigest)
	}
	result.InputDigest = bytes.Clone(result.InputDigest)
	return result, nil
}

func projectionAuthority(kind string) string {
	switch kind {
	case "risk":
		return DiscoveryExecutionAuthorityProjectionRisk
	case "graph":
		return DiscoveryExecutionAuthorityProjectionGraph
	case "search":
		return DiscoveryExecutionAuthorityProjectionSearch
	default:
		return ""
	}
}

func isProjectionAuthority(authority string) bool {
	return stringIn(authority, DiscoveryExecutionAuthorityProjectionRisk, DiscoveryExecutionAuthorityProjectionGraph, DiscoveryExecutionAuthorityProjectionSearch)
}

func validExecutionRepository(repository *DiscoveryExecutionRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validWorkerLease(worker, token string) bool {
	return len(worker) >= 1 && len(worker) <= 128 && len(token) >= 16 && len(token) <= 128
}

func validExecutionJobInput(scope domain.Scope, jobID string, input ExecutionJobInput) bool {
	if input.OrganizationID != scope.OrganizationID().String() || input.WorkspaceID != scope.WorkspaceID().String() || input.EnvironmentID != scope.EnvironmentID().String() || input.JobID != jobID || !validProductID(input.SyncID) || !validProductID(input.IntegrationID) || !validProductID(input.ConnectionID) || !validProductID(input.SnapshotID) || input.Generation < 1 || input.Attempt < 1 || input.Attempt > 5 || !validLeaseExpiration(input.LeaseExpiresAt, 900) || !executionVersionPattern.MatchString(input.CollectorVersion) || !executionVersionPattern.MatchString(input.ParserVersion) || !executionVersionPattern.MatchString(input.ToolVersion) || !validOpaqueReference(input.CredentialReference) || !validReferenceOnlyJSON(input.Configuration) {
		return false
	}
	integrationID, integrationErr := domain.ParseProductID(input.IntegrationID)
	connectionID, connectionErr := domain.ParseProductID(input.ConnectionID)
	parsedJobID, jobErr := domain.ParseProductID(input.JobID)
	if integrationErr != nil || connectionErr != nil || jobErr != nil {
		return false
	}
	request := collection.Request{
		Scope:               scope,
		IntegrationID:       integrationID,
		ConnectionID:        connectionID,
		JobID:               parsedJobID,
		Attempt:             input.Attempt,
		ObservationTime:     input.ObservationTime,
		Provider:            input.Provider,
		CollectorVersion:    input.CollectorVersion,
		CredentialClass:     input.CredentialClass,
		CredentialReference: input.CredentialReference,
		ExpectedSubject:     collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID},
		ParserVersion:       input.ParserVersion,
		ToolVersion:         input.ToolVersion,
		Bounds:              collection.Bounds{MaxPages: 1, MaxItems: 1, MaxRawBytes: 1, Timeout: time.Second},
	}
	if input.CursorProvider != nil || input.CursorVersion != nil || input.CursorValue != nil {
		if input.CursorProvider == nil || input.CursorVersion == nil || input.CursorValue == nil {
			return false
		}
		request.Cursor = collection.Cursor{Provider: *input.CursorProvider, Version: *input.CursorVersion, Value: *input.CursorValue}
	}
	checkpointPresent := input.CheckpointVersion != 0 || len(input.CheckpointDigest) != 0 || input.CheckpointManifestReference != "" || input.CheckpointManifestKey != "" || input.CheckpointManifestVersionID != "" || len(input.CheckpointManifestChecksum) != 0 || input.CheckpointManifestSizeBytes != 0 || input.CheckpointManifestMediaType != "" || input.CheckpointManifestSchemaVersion != ""
	if checkpointPresent && (input.CheckpointVersion < 1 || input.CheckpointVersion > 10000 || len(input.CheckpointDigest) != sha256.Size || !validS3ObjectReference(input.CheckpointManifestReference) || len(input.CheckpointManifestKey) < 32 || len(input.CheckpointManifestKey) > 1024 || !strings.HasSuffix(input.CheckpointManifestReference, "/"+input.CheckpointManifestKey) || input.CheckpointManifestVersionID == "" || len(input.CheckpointManifestVersionID) > 1024 || len(input.CheckpointManifestChecksum) != sha256.Size || input.CheckpointManifestSizeBytes < 1 || input.CheckpointManifestSizeBytes > 512<<20 || input.CheckpointManifestMediaType != "application/json" || !executionVersionPattern.MatchString(input.CheckpointManifestSchemaVersion)) {
		return false
	}
	return request.Validate() == nil
}
