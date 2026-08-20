package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	DiscoveryExecutionSchemaVersion       = "production-discovery-execution-v1"
	DiscoveryExecutionAuthorityScheduler  = "zasp_discovery_scheduler"
	DiscoveryExecutionAuthorityWorker     = "zasp_discovery_worker"
	DiscoveryExecutionAuthorityProjection = "zasp_projection_worker"

	postgresExecutionReadySQL             = `SELECT to_jsonb(zasp_execution_readiness($1,$2))`
	postgresExecutionPrincipalReadySQL    = `SELECT to_jsonb(zasp_execution_principal_ready($1))`
	postgresExecutionJobInputSQL          = `SELECT zasp_execution_job_input($1,$2,$3,$4,$5,$6)`
	postgresExecutionHeartbeatJobSQL      = `SELECT zasp_execution_heartbeat_job($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionClaimJobsSQL         = `SELECT zasp_execution_claim_jobs($1,$2,$3,$4)`
	postgresExecutionScheduleInputSQL     = `SELECT zasp_execution_schedule_input($1,$2,$3,$4,$5,$6)`
	postgresExecutionHeartbeatScheduleSQL = `SELECT zasp_execution_heartbeat_schedule($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionClaimSchedulesSQL    = `SELECT zasp_execution_claim_schedules($1,$2,$3,$4)`
	postgresExecutionApplySnapshotSQL     = `SELECT zasp_execution_apply_complete_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21::jsonb,$22::jsonb)`
	postgresExecutionProjectionPageSQL    = `SELECT zasp_execution_snapshot_projection_page($1,$2,$3,$4,$5,NULLIF($6,''),$7)`
	postgresExecutionClaimProjectionSQL   = `SELECT zasp_execution_claim_projection_work($1,$2,$3,$4)`
	postgresExecutionFinishProjectionSQL  = `SELECT zasp_execution_finish_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresExecutionBindSubjectSQL       = `SELECT zasp_execution_bind_connection_subject($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`
)

var executionVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)

type DiscoveryExecutionRepository struct {
	database  JSONDatabase
	authority string
}

func NewDiscoveryExecutionRepository(database JSONDatabase, authority string) (*DiscoveryExecutionRepository, error) {
	if nilInterface(database) || !stringIn(authority, DiscoveryExecutionAuthorityScheduler, DiscoveryExecutionAuthorityWorker, DiscoveryExecutionAuthorityProjection) {
		return nil, ErrRepositoryConfiguration
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != DiscoveryExecutionSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	repository := &DiscoveryExecutionRepository{database: database, authority: authority}
	if err := repository.Ready(context.Background()); err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *DiscoveryExecutionRepository) Ready(ctx context.Context) error {
	if !validExecutionRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	version, err := repository.database.SchemaVersion(ctx)
	if err != nil || version != DiscoveryExecutionSchemaVersion {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionReadySQL, migrations.ProductionDiscoveryExecution().Checksum(), migrations.ProductionDiscoveryExecutionSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	payload, err = repository.database.QueryJSON(ctx, postgresExecutionPrincipalReadySQL, repository.authority)
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

type ExecutionJobInput struct {
	OrganizationID      string                     `json:"organization_id"`
	WorkspaceID         string                     `json:"workspace_id"`
	EnvironmentID       string                     `json:"environment_id"`
	JobID               string                     `json:"job_id"`
	Attempt             int                        `json:"attempt"`
	LeaseExpiresAt      time.Time                  `json:"lease_expires_at"`
	SyncID              string                     `json:"sync_id"`
	IntegrationID       string                     `json:"integration_id"`
	ConnectionID        string                     `json:"connection_id"`
	Provider            collection.Provider        `json:"provider"`
	CollectorVersion    string                     `json:"collector_version"`
	CredentialClass     collection.CredentialClass `json:"credential_class"`
	CredentialReference string                     `json:"credential_reference"`
	SubjectKind         string                     `json:"subject_kind"`
	SubjectID           string                     `json:"subject_id"`
	CursorProvider      *collection.Provider       `json:"cursor_provider"`
	CursorVersion       *string                    `json:"cursor_version"`
	CursorValue         *string                    `json:"cursor_value"`
	ParserVersion       string                     `json:"parser_version"`
	ToolVersion         string                     `json:"tool_version"`
	Configuration       json.RawMessage            `json:"configuration"`
	ExpectedSubject     collection.SubjectBinding  `json:"-"`
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
	if decodeStrictDiscovery(payload, &result) != nil || result.OrganizationID != scope.OrganizationID().String() || result.WorkspaceID != scope.WorkspaceID().String() || result.EnvironmentID != scope.EnvironmentID().String() || result.ScheduleID != scheduleID || !validProductID(result.IntegrationID) || result.CadenceSeconds < 60 || result.CadenceSeconds > 604800 || len(result.TimeZone) < 1 || len(result.TimeZone) > 64 || result.NextRunAt.IsZero() || result.Version < 1 || !validLeaseExpiration(result.LeaseExpiresAt, 900) {
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

type ExecutionCompleteSnapshot struct {
	CompleteSnapshot
	ManifestKey, ManifestVersionID, ManifestMediaType, ManifestSchemaVersion, ParserVersion, ToolVersion string
	ManifestSizeBytes                                                                                    int64
}

type ExecutionSnapshotApplyResult struct {
	SnapshotApplyResult
	CandidateDigest   []byte `json:"candidate_digest"`
	ManifestVersionID string `json:"manifest_version_id"`
}

func (repository *DiscoveryExecutionRepository) ApplyCompleteSnapshot(ctx context.Context, scope domain.Scope, input ExecutionCompleteSnapshot) (ExecutionSnapshotApplyResult, error) {
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityWorker || scope.Validate() != nil || !validCompleteSnapshot(input.CompleteSnapshot) || len(input.ManifestKey) < 32 || len(input.ManifestKey) > 1024 || len(input.ManifestVersionID) < 1 || len(input.ManifestVersionID) > 1024 || input.ManifestSizeBytes < 1 || input.ManifestSizeBytes > 512<<20 || input.ManifestMediaType != "application/json" || !executionVersionPattern.MatchString(input.ManifestSchemaVersion) || !executionVersionPattern.MatchString(input.ParserVersion) || !executionVersionPattern.MatchString(input.ToolVersion) {
		return ExecutionSnapshotApplyResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionApplySnapshotSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.IntegrationID, input.SyncID, input.SnapshotID, input.Generation, input.Source, input.ManifestReference, input.ManifestKey, input.ManifestVersionID, input.ManifestChecksum, input.ManifestSizeBytes, input.ManifestMediaType, input.ManifestSchemaVersion, input.CollectedAt, input.CursorValue, input.ParserVersion, input.ToolVersion, input.Entities, input.Relationships, input.Evidence)
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
	if !validExecutionRepository(repository, ctx) || repository.authority != DiscoveryExecutionAuthorityProjection || scope.Validate() != nil || !validProductID(snapshotID) || !stringIn(section, "entities", "relationships", "evidence") || afterID != "" && !validProductID(afterID) || limit < 1 || limit > 500 {
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

func validExecutionRepository(repository *DiscoveryExecutionRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validWorkerLease(worker, token string) bool {
	return len(worker) >= 1 && len(worker) <= 128 && len(token) >= 16 && len(token) <= 128
}

func validExecutionJobInput(scope domain.Scope, jobID string, input ExecutionJobInput) bool {
	if input.OrganizationID != scope.OrganizationID().String() || input.WorkspaceID != scope.WorkspaceID().String() || input.EnvironmentID != scope.EnvironmentID().String() || input.JobID != jobID || !validProductID(input.SyncID) || !validProductID(input.IntegrationID) || !validProductID(input.ConnectionID) || input.Attempt < 1 || input.Attempt > 5 || !validLeaseExpiration(input.LeaseExpiresAt, 900) || !executionVersionPattern.MatchString(input.CollectorVersion) || !executionVersionPattern.MatchString(input.ParserVersion) || !executionVersionPattern.MatchString(input.ToolVersion) || !validOpaqueReference(input.CredentialReference) || !validReferenceOnlyJSON(input.Configuration) {
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
	return request.Validate() == nil
}
