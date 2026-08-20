package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresDiscoveryReadySQL                   = `SELECT to_jsonb(zasp_discovery_readiness($1,$2))`
	postgresDiscoveryPrincipalReadySQL          = `SELECT to_jsonb(zasp_discovery_principal_ready($1))`
	postgresDiscoveryCreateIntegrationSQL       = `SELECT zasp_discovery_create_integration($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NULLIF($9,''))`
	postgresDiscoveryTransitionIntegrationSQL   = `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryPutConnectionSQL           = `SELECT zasp_discovery_put_connection($1,$2,$3,$4,$5,$6,$7)`
	postgresDiscoveryTransitionConnectionSQL    = `SELECT zasp_discovery_transition_connection($1,$2,$3,$4,$5,$6,$7)`
	postgresDiscoveryPutScheduleSQL             = `SELECT zasp_discovery_put_schedule($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryTransitionScheduleSQL      = `SELECT zasp_discovery_transition_schedule($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryCreateSensorSQL            = `SELECT zasp_discovery_create_sensor($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryTransitionSensorSQL        = `SELECT zasp_discovery_transition_sensor($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryCreateGatewayDeviceSQL     = `SELECT zasp_discovery_create_gateway_device($1,$2,$3,$4,$5)`
	postgresDiscoveryTransitionGatewayDeviceSQL = `SELECT zasp_discovery_transition_gateway_device($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryIssueGatewayEnrollmentSQL  = `SELECT zasp_discovery_issue_gateway_enrollment($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryRevokeGatewayEnrollmentSQL = `SELECT zasp_discovery_revoke_gateway_enrollment($1,$2,$3,$4,$5)`
	postgresDiscoveryRequestSyncSQL             = `SELECT zasp_discovery_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresDiscoveryApplySnapshotSQL           = `SELECT zasp_discovery_apply_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb)`
	postgresDiscoveryEntityPageSQL              = `SELECT zasp_discovery_entity_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresDiscoveryClaimOutboxSQL             = `SELECT zasp_discovery_claim_outbox($1,$2,$3,$4)`
	postgresExecutionClaimOutboxTopicSQL        = `SELECT zasp_execution_claim_outbox($1,$2,$3,$4,$5)`
	postgresExecutionHeartbeatOutboxTopicSQL    = `SELECT zasp_execution_heartbeat_outbox($1,$2,$3,$4,$5)`
	postgresExecutionAckOutboxTopicSQL          = `SELECT zasp_execution_ack_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresExecutionRetryOutboxTopicSQL        = `SELECT zasp_execution_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryAckOutboxSQL               = `SELECT zasp_discovery_ack_outbox($1,$2,$3,$4,$5,$6,$7)`
	postgresDiscoveryIssueSensorTokenSQL        = `SELECT zasp_discovery_issue_sensor_token($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryGatewayEnrollSQL           = `SELECT zasp_discovery_gateway_enroll($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresDiscoveryGatewayAdvanceSQL          = `SELECT zasp_discovery_gateway_advance_replay($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryGatewayRotateSQL           = `SELECT zasp_discovery_gateway_rotate($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryGatewayRevokeSQL           = `SELECT zasp_discovery_gateway_revoke($1,$2,$3,$4,$5)`
	postgresDiscoveryGatewayPolicySQL           = `SELECT zasp_discovery_put_gateway_policy($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresDiscoveryClaimJobsSQL               = `SELECT zasp_discovery_claim_jobs($1,$2,$3,$4,$5)`
	postgresDiscoveryClaimSchedulesSQL          = `SELECT zasp_discovery_claim_schedules($1,$2,$3,$4)`
	postgresDiscoveryCompleteScheduleSQL        = `SELECT zasp_discovery_complete_schedule($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryClaimProjectionSQL         = `SELECT zasp_discovery_claim_projection_work($1,$2,$3,$4)`
	postgresDiscoveryFinishJobSQL               = `SELECT zasp_discovery_finish_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresDiscoveryFinishProjectionSQL        = `SELECT zasp_discovery_finish_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresDiscoveryCompleteJobSQL             = `SELECT zasp_discovery_complete_job($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryRetryOutboxSQL             = `SELECT zasp_discovery_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryCompleteProjectionSQL      = `SELECT zasp_discovery_complete_projection($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryEvidenceGetSQL             = `SELECT zasp_discovery_evidence_get($1,$2,$3,$4)`
	postgresDiscoverySensorRotateSQL            = `SELECT zasp_discovery_sensor_rotate($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoverySensorRevokeSQL            = `SELECT zasp_discovery_sensor_revoke($1,$2,$3,$4,$5)`
	postgresDiscoverySensorHeartbeatSQL         = `SELECT zasp_discovery_sensor_heartbeat($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`
	postgresDiscoveryRuntimeBatchSQL            = `SELECT zasp_discovery_create_runtime_batch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	postgresDiscoveryRuntimeStageSQL            = `SELECT zasp_discovery_complete_runtime_stage($1,$2,$3,$4,$5,$6,$7,$8)`
)

const (
	DiscoveryDatabaseAuthorityAPI     = "zasp_discovery_api"
	DiscoveryDatabaseAuthorityWorker  = "zasp_discovery_worker"
	DiscoveryDatabaseAuthorityIngest  = "zasp_runtime_ingest"
	DiscoveryDatabaseAuthorityRuntime = "zasp_runtime_worker"
	DiscoveryDatabaseAuthorityOutbox  = "zasp_outbox_worker"
	DiscoveryDatabaseAuthorityGateway = "zasp_runtime_gateway"
)

var referenceOnlyKeyPattern = regexp.MustCompile(`(?i)(secret|password|token|credential|private.?key|session)`)
var opaqueReferencePattern = regexp.MustCompile(`^ref:[a-z0-9][a-z0-9_./:-]+$`)
var s3ObjectReferencePattern = regexp.MustCompile(`^s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/([A-Za-z0-9][A-Za-z0-9._/-]*)$`)
var outboxProviderAckPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type IntegrationRepository interface {
	CreateIntegration(context.Context, RequestIdentity, IntegrationCreate) (DiscoveryIntegration, error)
	TransitionIntegration(context.Context, domain.Scope, IntegrationTransition) (AuthorityStateRecord, error)
	PutIntegrationConnection(context.Context, domain.Scope, IntegrationConnectionPut) (IntegrationConnectionRecord, error)
	TransitionIntegrationConnection(context.Context, domain.Scope, string, IntegrationTransition) (AuthorityStateRecord, error)
	PutDiscoverySchedule(context.Context, domain.Scope, DiscoverySchedulePut) (DiscoveryScheduleRecord, error)
	TransitionDiscoverySchedule(context.Context, domain.Scope, IntegrationTransition) (AuthorityStateRecord, error)
	RequestDiscoverySync(context.Context, RequestIdentity, SyncRequest) (SyncRequestResult, error)
}

type SnapshotRepository interface {
	ApplyCompleteSnapshot(context.Context, domain.Scope, CompleteSnapshot) (SnapshotApplyResult, error)
	ListInventoryEntityPage(context.Context, domain.Scope, string, int) (InventoryEntityPage, error)
}

type EvidenceRepository interface {
	GetInventoryEvidence(context.Context, domain.Scope, string) (InventoryEvidence, error)
}

type OutboxRepository interface {
	ClaimOutbox(context.Context, string, string, int, int) ([]DiscoveryOutboxEvent, error)
	AcknowledgeOutbox(context.Context, domain.Scope, string, string, string, string) error
	RetryOutbox(context.Context, domain.Scope, string, string, string, int, string) error
}

type TopicOutboxRepository interface {
	ClaimOutboxTopic(context.Context, string, string, string, int, int) ([]DiscoveryOutboxEvent, error)
	HeartbeatOutboxTopic(context.Context, string, string, string, int, int) (OutboxLeaseHeartbeatResult, error)
	AcknowledgeOutboxTopic(context.Context, string, domain.Scope, string, string, string, string) (OutboxLeaseTransitionResult, error)
	RetryOutboxTopic(context.Context, string, domain.Scope, string, string, string, int, string) (OutboxLeaseTransitionResult, error)
}

type OutboxLeaseHeartbeatResult struct {
	ID             string    `json:"id"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	RemainingCount int       `json:"remaining_count"`
}

type OutboxLeaseTransitionResult struct {
	ID             string    `json:"id"`
	ProviderAck    string    `json:"provider_ack,omitempty"`
	PublishedAt    time.Time `json:"published_at,omitempty"`
	AvailableAt    time.Time `json:"available_at,omitempty"`
	RemainingCount int       `json:"remaining_count"`
}

func (repository *DiscoveryRepository) HeartbeatOutboxTopic(ctx context.Context, topic, worker, leaseToken string, leaseSeconds, expectedCount int) (OutboxLeaseHeartbeatResult, error) {
	if !validDiscoveryRepository(repository, ctx) || topic != "discovery-jobs" || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || leaseSeconds < 5 || leaseSeconds > 900 || expectedCount < 1 || expectedCount > 10 {
		return OutboxLeaseHeartbeatResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionHeartbeatOutboxTopicSQL, topic, worker, leaseToken, leaseSeconds, expectedCount)
	if err != nil {
		return OutboxLeaseHeartbeatResult{}, discoveryProviderError(err)
	}
	var result OutboxLeaseHeartbeatResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != topic || result.RemainingCount != expectedCount || !validLeaseExpiration(result.LeaseExpiresAt, leaseSeconds) {
		return OutboxLeaseHeartbeatResult{}, ErrRepositoryUnavailable
	}
	result.LeaseExpiresAt = result.LeaseExpiresAt.UTC()
	return result, nil
}

func (repository *DiscoveryRepository) AcknowledgeOutboxTopic(ctx context.Context, topic string, scope domain.Scope, id, worker, leaseToken, providerAck string) (OutboxLeaseTransitionResult, error) {
	if !validDiscoveryRepository(repository, ctx) || topic != "discovery-jobs" || scope.Validate() != nil || !validProductID(id) || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || !outboxProviderAckPattern.MatchString(providerAck) {
		return OutboxLeaseTransitionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionAckOutboxTopicSQL, topic, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, providerAck)
	if err != nil {
		return OutboxLeaseTransitionResult{}, discoveryProviderError(err)
	}
	var result OutboxLeaseTransitionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.ProviderAck != providerAck || !validPastServerTime(result.PublishedAt) || !result.AvailableAt.IsZero() || result.RemainingCount < 0 || result.RemainingCount > 9 {
		return OutboxLeaseTransitionResult{}, ErrRepositoryUnavailable
	}
	result.PublishedAt = result.PublishedAt.UTC()
	return result, nil
}

func (repository *DiscoveryRepository) RetryOutboxTopic(ctx context.Context, topic string, scope domain.Scope, id, worker, leaseToken string, retrySeconds int, code string) (OutboxLeaseTransitionResult, error) {
	if !validDiscoveryRepository(repository, ctx) || topic != "discovery-jobs" || scope.Validate() != nil || !validProductID(id) || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || retrySeconds < 1 || retrySeconds > 3600 || code != "queue_publish_unknown" {
		return OutboxLeaseTransitionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionRetryOutboxTopicSQL, topic, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, retrySeconds, code)
	if err != nil {
		return OutboxLeaseTransitionResult{}, discoveryProviderError(err)
	}
	var result OutboxLeaseTransitionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.ProviderAck != "" || !result.PublishedAt.IsZero() || !validRetryAvailability(result.AvailableAt, retrySeconds) || result.RemainingCount < 0 || result.RemainingCount > 9 {
		return OutboxLeaseTransitionResult{}, ErrRepositoryUnavailable
	}
	result.AvailableAt = result.AvailableAt.UTC()
	return result, nil
}

type DiscoveryWorkerRepository interface {
	ClaimDiscoveryJobs(context.Context, string, string, string, int, int) ([]DiscoveryJobLease, error)
	FinishDiscoveryJob(context.Context, domain.Scope, DiscoveryJobCompletion) (WorkCompletionResult, error)
	ClaimDiscoverySchedules(context.Context, string, string, int, int) ([]DiscoveryScheduleLease, error)
	CompleteDiscoverySchedule(context.Context, domain.Scope, DiscoveryScheduleCompletion) (DiscoveryScheduleCompletionResult, error)
	ClaimProjectionWork(context.Context, string, string, int, int) ([]ProjectionWorkLease, error)
	FinishProjectionWork(context.Context, domain.Scope, ProjectionWorkCompletion) (WorkCompletionResult, error)
}

type RuntimeAuthorityRepository interface {
	CreateSensor(context.Context, domain.Scope, SensorCreate) (SensorRecord, error)
	TransitionSensor(context.Context, domain.Scope, IntegrationTransition) (AuthorityStateRecord, error)
	IssueSensorToken(context.Context, domain.Scope, SensorTokenIssue) (SensorTokenRecord, error)
	CreateGatewayDevice(context.Context, domain.Scope, GatewayDeviceCreate) (GatewayDeviceRecord, error)
	TransitionGatewayDevice(context.Context, domain.Scope, IntegrationTransition) (AuthorityStateRecord, error)
	IssueGatewayEnrollmentToken(context.Context, domain.Scope, GatewayEnrollmentTokenIssue) (GatewayEnrollmentTokenRecord, error)
	RevokeGatewayEnrollmentToken(context.Context, domain.Scope, string, string) error
	EnrollGateway(context.Context, domain.Scope, GatewayEnrollment) (GatewayCredentialRecord, error)
	AdvanceGatewayReplay(context.Context, domain.Scope, string, int64, int64) error
	RotateGatewayCredential(context.Context, domain.Scope, GatewayCredentialRotation) (GatewayCredentialRecord, error)
	RevokeGatewayCredential(context.Context, domain.Scope, string, string) error
	PutGatewayPolicySubscription(context.Context, domain.Scope, GatewayPolicySubscription) error
	RotateSensorToken(context.Context, domain.Scope, SensorTokenRotation) (SensorTokenRecord, error)
	RevokeSensorToken(context.Context, domain.Scope, string, string) error
	RecordSensorHeartbeat(context.Context, domain.Scope, SensorHeartbeat) error
	CreateRuntimeBatch(context.Context, domain.Scope, RuntimeBatchCreate) (RuntimeBatchResult, error)
	CompleteRuntimeStage(context.Context, domain.Scope, RuntimeStageCompletion) error
}

type DiscoveryRepository struct {
	database  JSONDatabase
	schema    string
	authority string
}

func newDiscoveryRepositoryUnchecked(database JSONDatabase) (*DiscoveryRepository, error) {
	return newDiscoveryRepository(database, 5*time.Second)
}

func newDiscoveryRepository(database JSONDatabase, readinessTimeout time.Duration) (*DiscoveryRepository, error) {
	if readinessTimeout <= 0 || readinessTimeout > 30*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	return newDiscoveryRepositoryWithContext(ctx, database)
}

func newDiscoveryRepositoryWithContext(ctx context.Context, database JSONDatabase) (*DiscoveryRepository, error) {
	if ctx == nil || nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	version, err := database.SchemaVersion(ctx)
	if err != nil || version != DiscoverySchemaVersion && version != ConnectorSchemaVersion && version != ReferenceSchemaVersion && version != DiscoveryExecutionSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	readySQL, checksum, fingerprint := postgresDiscoveryReadySQL, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint()
	if version == ConnectorSchemaVersion || version == ReferenceSchemaVersion {
		readySQL, checksum, fingerprint = postgresConnectorReadySQL, migrations.ConnectorAuthorization().Checksum(), migrations.ConnectorAuthorizationSemanticFingerprint()
	} else if version == DiscoveryExecutionSchemaVersion {
		readySQL, checksum, fingerprint = postgresExecutionReadySQL, migrations.ProductionDiscoveryExecution().Checksum(), migrations.ProductionDiscoveryExecutionSemanticFingerprint()
	}
	payload, err := database.QueryJSON(ctx, readySQL, checksum, fingerprint)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	return &DiscoveryRepository{database: database, schema: version}, nil
}

func NewDiscoveryRepositoryForAuthority(database JSONDatabase, authority string) (*DiscoveryRepository, error) {
	return newDiscoveryRepositoryForAuthority(database, authority, 5*time.Second)
}

func newDiscoveryRepositoryForAuthority(database JSONDatabase, authority string, readinessTimeout time.Duration) (*DiscoveryRepository, error) {
	if !stringIn(authority, DiscoveryDatabaseAuthorityAPI, DiscoveryDatabaseAuthorityWorker, DiscoveryDatabaseAuthorityIngest, DiscoveryDatabaseAuthorityRuntime, DiscoveryDatabaseAuthorityOutbox, DiscoveryDatabaseAuthorityGateway) {
		return nil, ErrRepositoryConfiguration
	}
	if readinessTimeout <= 0 || readinessTimeout > 30*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	repository, err := newDiscoveryRepositoryWithContext(ctx, database)
	if err != nil {
		return nil, err
	}
	payload, err := database.QueryJSON(ctx, postgresDiscoveryPrincipalReadySQL, authority)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	repository.authority = authority
	return repository, nil
}

func (repository *DiscoveryRepository) Ready(ctx context.Context) error {
	if !validDiscoveryRepository(repository, ctx) || repository.authority == "" {
		return ErrRepositoryUnavailable
	}
	candidate, err := newDiscoveryRepositoryWithContext(ctx, repository.database)
	if err != nil || candidate.schema != repository.schema {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryPrincipalReadySQL, repository.authority)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

type IntegrationCreate struct {
	ID                  string
	Kind                string
	ConnectorVersion    string
	DisplayName         string
	Configuration       json.RawMessage
	CredentialReference string
}

type DiscoveryIntegration struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"`
	ConnectorVersion string    `json:"connector_version"`
	DisplayName      string    `json:"display_name"`
	State            string    `json:"state"`
	Version          int64     `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (repository *DiscoveryRepository) CreateIntegration(ctx context.Context, identity RequestIdentity, input IntegrationCreate) (DiscoveryIntegration, error) {
	if !validDiscoveryRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validIntegrationCreate(input) {
		return DiscoveryIntegration{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryCreateIntegrationSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.ID, input.Kind, input.ConnectorVersion, input.DisplayName, input.Configuration, input.CredentialReference)
	if err != nil {
		return DiscoveryIntegration{}, discoveryProviderError(err)
	}
	var result DiscoveryIntegration
	if decodeStrictDiscovery(payload, &result) != nil || !validDiscoveryIntegration(result) || result.ID != input.ID || result.Kind != input.Kind || result.ConnectorVersion != input.ConnectorVersion || result.DisplayName != input.DisplayName {
		return DiscoveryIntegration{}, ErrRepositoryUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

type IntegrationTransition struct {
	ID, State       string
	ExpectedVersion int64
}
type AuthorityStateRecord struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (repository *DiscoveryRepository) TransitionIntegration(ctx context.Context, scope domain.Scope, input IntegrationTransition) (AuthorityStateRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || input.ExpectedVersion < 1 || !stringIn(input.State, "authorizing", "active", "degraded", "disabled", "deleted") {
		return AuthorityStateRecord{}, ErrRepositoryOperation
	}
	return repository.authorityState(ctx, scope, postgresDiscoveryTransitionIntegrationSQL, input.ID, input.ExpectedVersion, input.State)
}

type IntegrationConnectionPut struct{ ID, IntegrationID, Provider, ConnectionReference string }
type IntegrationConnectionRecord struct {
	ID            string    `json:"id"`
	IntegrationID string    `json:"integration_id"`
	Provider      string    `json:"provider"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
}

func (repository *DiscoveryRepository) PutIntegrationConnection(ctx context.Context, scope domain.Scope, input IntegrationConnectionPut) (IntegrationConnectionRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.IntegrationID) || len(input.Provider) < 1 || len(input.Provider) > 64 || !validOpaqueReference(input.ConnectionReference) {
		return IntegrationConnectionRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryPutConnectionSQL, input.ID, input.IntegrationID, input.Provider, input.ConnectionReference)
	if err != nil {
		return IntegrationConnectionRecord{}, err
	}
	var result IntegrationConnectionRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.IntegrationID != input.IntegrationID || result.Provider != input.Provider || !stringIn(result.State, "pending", "verified", "invalid", "revoked") || !validPastServerTime(result.CreatedAt) {
		return IntegrationConnectionRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) TransitionIntegrationConnection(ctx context.Context, scope domain.Scope, integrationID string, input IntegrationTransition) (AuthorityStateRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) || !validProductID(input.ID) || input.ExpectedVersion < 1 || !stringIn(input.State, "pending", "verified", "invalid", "revoked") {
		return AuthorityStateRecord{}, ErrRepositoryOperation
	}
	return repository.authorityState(ctx, scope, postgresDiscoveryTransitionConnectionSQL, input.ID, integrationID, input.ExpectedVersion, input.State)
}

type DiscoverySchedulePut struct {
	ID, IntegrationID string
	CadenceSeconds    int
	NextRunAt         time.Time
	ExpectedVersion   int64
}
type DiscoveryScheduleRecord struct {
	ID             string    `json:"id"`
	IntegrationID  string    `json:"integration_id"`
	State          string    `json:"state"`
	CadenceSeconds int       `json:"cadence_seconds"`
	NextRunAt      time.Time `json:"next_run_at"`
	Version        int64     `json:"version"`
}

func (repository *DiscoveryRepository) PutDiscoverySchedule(ctx context.Context, scope domain.Scope, input DiscoverySchedulePut) (DiscoveryScheduleRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.IntegrationID) || input.CadenceSeconds < 300 || input.CadenceSeconds > 2678400 || input.NextRunAt.Location() != time.UTC || input.ExpectedVersion < 0 {
		return DiscoveryScheduleRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryPutScheduleSQL, input.ID, input.IntegrationID, input.CadenceSeconds, input.NextRunAt, input.ExpectedVersion)
	if err != nil {
		return DiscoveryScheduleRecord{}, err
	}
	var result DiscoveryScheduleRecord
	expectedVersion := input.ExpectedVersion + 1
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.IntegrationID != input.IntegrationID || !stringIn(result.State, "enabled", "disabled") || result.CadenceSeconds != input.CadenceSeconds || !result.NextRunAt.Equal(input.NextRunAt) || result.Version != expectedVersion {
		return DiscoveryScheduleRecord{}, ErrRepositoryUnavailable
	}
	result.NextRunAt = result.NextRunAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) TransitionDiscoverySchedule(ctx context.Context, scope domain.Scope, input IntegrationTransition) (AuthorityStateRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || input.ExpectedVersion < 1 || !stringIn(input.State, "enabled", "disabled", "deleted") {
		return AuthorityStateRecord{}, ErrRepositoryOperation
	}
	return repository.authorityState(ctx, scope, postgresDiscoveryTransitionScheduleSQL, input.ID, input.ExpectedVersion, input.State)
}

type SensorCreate struct{ ID, Name, Kind string }
type SensorRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

func (repository *DiscoveryRepository) CreateSensor(ctx context.Context, scope domain.Scope, input SensorCreate) (SensorRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || len(input.Name) < 1 || len(input.Name) > 128 || !stringIn(input.Kind, "tetragon", "otlp") {
		return SensorRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryCreateSensorSQL, input.ID, input.Name, input.Kind)
	if err != nil {
		return SensorRecord{}, err
	}
	var result SensorRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.Name != input.Name || result.Kind != input.Kind || !stringIn(result.State, "pending", "active", "degraded", "revoked", "deleted") || result.Version < 1 || !validPastServerTime(result.CreatedAt) {
		return SensorRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) TransitionSensor(ctx context.Context, scope domain.Scope, input IntegrationTransition) (AuthorityStateRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || input.ExpectedVersion < 1 || !stringIn(input.State, "active", "degraded", "revoked", "deleted") {
		return AuthorityStateRecord{}, ErrRepositoryOperation
	}
	return repository.authorityState(ctx, scope, postgresDiscoveryTransitionSensorSQL, input.ID, input.ExpectedVersion, input.State)
}

type GatewayDeviceCreate struct{ ID, Name string }
type GatewayDeviceRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	Version     int64     `json:"version"`
	ReplayFloor int64     `json:"replay_floor"`
	CreatedAt   time.Time `json:"created_at"`
}

func (repository *DiscoveryRepository) CreateGatewayDevice(ctx context.Context, scope domain.Scope, input GatewayDeviceCreate) (GatewayDeviceRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || len(input.Name) < 1 || len(input.Name) > 128 {
		return GatewayDeviceRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryCreateGatewayDeviceSQL, input.ID, input.Name)
	if err != nil {
		return GatewayDeviceRecord{}, err
	}
	var result GatewayDeviceRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.Name != input.Name || !stringIn(result.State, "pending", "active", "revoked", "deleted") || result.Version < 1 || result.ReplayFloor < 0 || !validPastServerTime(result.CreatedAt) {
		return GatewayDeviceRecord{}, ErrRepositoryUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) TransitionGatewayDevice(ctx context.Context, scope domain.Scope, input IntegrationTransition) (AuthorityStateRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || input.ExpectedVersion < 1 || !stringIn(input.State, "active", "revoked", "deleted") {
		return AuthorityStateRecord{}, ErrRepositoryOperation
	}
	return repository.authorityState(ctx, scope, postgresDiscoveryTransitionGatewayDeviceSQL, input.ID, input.ExpectedVersion, input.State)
}

type GatewayEnrollmentTokenIssue struct {
	ID, DeviceID    string
	Salt, TokenHash []byte
	ExpiresAt       time.Time
}
type GatewayEnrollmentTokenRecord struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Audience  string    `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (repository *DiscoveryRepository) IssueGatewayEnrollmentToken(ctx context.Context, scope domain.Scope, input GatewayEnrollmentTokenIssue) (GatewayEnrollmentTokenRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.ID) || !validProductID(input.DeviceID) || len(input.Salt) < 16 || len(input.Salt) > 64 || len(input.TokenHash) != 32 || input.ExpiresAt.Location() != time.UTC {
		return GatewayEnrollmentTokenRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryIssueGatewayEnrollmentSQL, input.ID, input.DeviceID, input.Salt, input.TokenHash, input.ExpiresAt)
	if err != nil {
		return GatewayEnrollmentTokenRecord{}, err
	}
	var result GatewayEnrollmentTokenRecord
	if decodeStrictDiscovery(payload, &result) != nil || !validIssuedRecord(result.ID, input.ID, result.DeviceID, input.DeviceID, result.Audience, "runtime-gateway-enroll", result.IssuedAt, result.ExpiresAt, input.ExpiresAt) {
		return GatewayEnrollmentTokenRecord{}, ErrRepositoryUnavailable
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) RevokeGatewayEnrollmentToken(ctx context.Context, scope domain.Scope, deviceID, id string) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deviceID) || !validProductID(id) {
		return ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryRevokeGatewayEnrollmentSQL, id, deviceID)
	if err != nil {
		return err
	}
	var result struct {
		ID        string    `json:"id"`
		RevokedAt time.Time `json:"revoked_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validPastServerTime(result.RevokedAt) {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *DiscoveryRepository) authorityState(ctx context.Context, scope domain.Scope, statement string, args ...any) (AuthorityStateRecord, error) {
	payload, err := repository.scopedTransition(ctx, scope, statement, args...)
	if err != nil {
		return AuthorityStateRecord{}, err
	}
	var result AuthorityStateRecord
	expectedID := args[0].(string)
	expectedState := args[len(args)-1].(string)
	expectedVersion := args[len(args)-2].(int64) + 1
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != expectedID || result.State != expectedState || result.Version != expectedVersion || !validPastServerTime(result.UpdatedAt) {
		return AuthorityStateRecord{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

type SyncRequest struct {
	IntegrationID  string
	SyncID         string
	JobID          string
	OutboxID       string
	IdempotencyKey string
	RequestDigest  []byte
	TriggerKind    string
	ParserVersion  string
	ToolVersion    string
}

type SyncRequestResult struct {
	SyncID   string `json:"sync_id"`
	JobID    string `json:"job_id"`
	OutboxID string `json:"outbox_id"`
	State    string `json:"state"`
	Replayed bool   `json:"replayed"`
}

func (repository *DiscoveryRepository) RequestDiscoverySync(ctx context.Context, identity RequestIdentity, input SyncRequest) (SyncRequestResult, error) {
	if !validDiscoveryRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validSyncRequest(input) {
		return SyncRequestResult{}, ErrRepositoryOperation
	}
	statement := postgresDiscoveryRequestSyncSQL
	if repository.schema == DiscoveryExecutionSchemaVersion {
		statement = postgresExecutionRequestSyncSQL
	}
	payload, err := repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IntegrationID, input.SyncID, input.JobID, input.OutboxID, input.IdempotencyKey, input.RequestDigest, input.TriggerKind, input.ParserVersion, input.ToolVersion)
	if err != nil {
		return SyncRequestResult{}, discoveryProviderError(err)
	}
	var result SyncRequestResult
	if decodeStrictDiscovery(payload, &result) != nil || !validSyncRequestResult(input, result) {
		return SyncRequestResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validSyncRequestResult(input SyncRequest, result SyncRequestResult) bool {
	if result.State != "queued" || !validProductID(result.SyncID) || !validProductID(result.JobID) || !validProductID(result.OutboxID) {
		return false
	}
	return result.Replayed || result.SyncID == input.SyncID && result.JobID == input.JobID && result.OutboxID == input.OutboxID
}

type CompleteSnapshot struct {
	IntegrationID     string
	SyncID            string
	SnapshotID        string
	Generation        int64
	Source            string
	ManifestReference string
	ManifestChecksum  []byte
	CollectedAt       time.Time
	CursorProvider    string
	CursorValue       string
	Entities          json.RawMessage
	Relationships     json.RawMessage
	Evidence          json.RawMessage
}

type SnapshotApplyResult struct {
	SnapshotID      string    `json:"snapshot_id"`
	DiscoveredCount int       `json:"discovered_count"`
	ChangedCount    int       `json:"changed_count"`
	RemovedCount    int       `json:"removed_count"`
	CommittedAt     time.Time `json:"committed_at"`
}

func (repository *DiscoveryRepository) ApplyCompleteSnapshot(ctx context.Context, scope domain.Scope, input CompleteSnapshot) (SnapshotApplyResult, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validCompleteSnapshot(input) {
		return SnapshotApplyResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryApplySnapshotSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.IntegrationID, input.SyncID, input.SnapshotID, input.Generation, input.Source, input.ManifestReference, input.ManifestChecksum, input.CollectedAt, input.CursorProvider, input.CursorValue, input.Entities, input.Relationships, input.Evidence)
	if err != nil {
		return SnapshotApplyResult{}, discoveryProviderError(err)
	}
	var result SnapshotApplyResult
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID || result.DiscoveredCount < 0 || result.ChangedCount < 0 || result.RemovedCount < 0 || !validPastServerTime(result.CommittedAt) {
		return SnapshotApplyResult{}, ErrRepositoryUnavailable
	}
	result.CommittedAt = result.CommittedAt.UTC()
	return result, nil
}

type InventoryEntity struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	DisplayName  string          `json:"display_name"`
	StableFields json.RawMessage `json:"stable_fields"`
	State        string          `json:"state"`
	FirstSeenAt  time.Time       `json:"first_seen_at"`
	LastSeenAt   time.Time       `json:"last_seen_at"`
	Version      int64           `json:"version"`
}
type InventoryEntityPage struct {
	Items  []InventoryEntity
	NextID string
}

func (repository *DiscoveryRepository) ListInventoryEntityPage(ctx context.Context, scope domain.Scope, afterID string, limit int) (InventoryEntityPage, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || limit < 1 || limit > 100 || afterID != "" && !validProductID(afterID) {
		return InventoryEntityPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryEntityPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), afterID, limit)
	if err != nil {
		return InventoryEntityPage{}, discoveryProviderError(err)
	}
	var envelope struct {
		Items  []InventoryEntity `json:"items"`
		NextID *string           `json:"next_id"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return InventoryEntityPage{}, ErrRepositoryUnavailable
	}
	last := ""
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validProductID(item.ID) || item.ID <= last || len(item.Kind) < 1 || len(item.Kind) > 64 || len(item.DisplayName) < 1 || len(item.DisplayName) > 256 || item.State != "active" || item.Version < 1 || item.FirstSeenAt.IsZero() || item.LastSeenAt.Before(item.FirstSeenAt) || !validPastServerTime(item.LastSeenAt) || !discoveryValidJSONObject(item.StableFields, 65536) {
			return InventoryEntityPage{}, ErrRepositoryUnavailable
		}
		last = item.ID
		item.FirstSeenAt = item.FirstSeenAt.UTC()
		item.LastSeenAt = item.LastSeenAt.UTC()
	}
	next := ""
	if envelope.NextID != nil {
		next = *envelope.NextID
		if len(envelope.Items) != limit || len(envelope.Items) == 0 || next != last {
			return InventoryEntityPage{}, ErrRepositoryUnavailable
		}
	}
	return InventoryEntityPage{Items: envelope.Items, NextID: next}, nil
}

type DiscoveryOutboxEvent struct {
	OrganizationID   string          `json:"organization_id"`
	WorkspaceID      string          `json:"workspace_id"`
	EnvironmentID    string          `json:"environment_id"`
	ID               string          `json:"id"`
	Topic            string          `json:"topic"`
	DeterministicKey string          `json:"deterministic_key"`
	PayloadVersion   int             `json:"payload_version"`
	Payload          json.RawMessage `json:"payload"`
	PayloadDigest    []byte          `json:"payload_digest"`
	Attempt          int             `json:"attempt"`
	LeaseExpiresAt   time.Time       `json:"lease_expires_at"`
}

func (repository *DiscoveryRepository) ClaimOutbox(ctx context.Context, worker, leaseToken string, leaseSeconds, limit int) ([]DiscoveryOutboxEvent, error) {
	if !validDiscoveryRepository(repository, ctx) || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryClaimOutboxSQL, worker, leaseToken, leaseSeconds, limit)
	return decodeDiscoveryOutboxClaims(payload, err, "", leaseSeconds, limit)
}

func (repository *DiscoveryRepository) ClaimOutboxTopic(ctx context.Context, topic, worker, leaseToken string, leaseSeconds, limit int) ([]DiscoveryOutboxEvent, error) {
	if !validDiscoveryRepository(repository, ctx) || topic != "discovery-jobs" || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 10 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionClaimOutboxTopicSQL, topic, worker, leaseToken, leaseSeconds, limit)
	return decodeDiscoveryOutboxClaims(payload, err, topic, leaseSeconds, limit)
}

func decodeDiscoveryOutboxClaims(payload json.RawMessage, err error, expectedTopic string, leaseSeconds, limit int) ([]DiscoveryOutboxEvent, error) {
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []DiscoveryOutboxEvent `json:"items"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validProductID(item.OrganizationID) || !validProductID(item.WorkspaceID) || !validProductID(item.EnvironmentID) || !validProductID(item.ID) || !stringIn(item.Topic, "discovery-jobs", "runtime-events", "projection-work") || expectedTopic != "" && item.Topic != expectedTopic || len(item.DeterministicKey) < 16 || len(item.DeterministicKey) > 256 || item.PayloadVersion < 1 || item.PayloadVersion > 32 || !discoveryValidJSONObject(item.Payload, 65536) || len(item.PayloadDigest) != sha256.Size || item.Attempt < 1 || item.Attempt > 100 || !validLeaseExpiration(item.LeaseExpiresAt, leaseSeconds) {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

func (repository *DiscoveryRepository) AcknowledgeOutbox(ctx context.Context, scope domain.Scope, id, worker, leaseToken, providerAck string) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(id) || len(worker) < 1 || len(leaseToken) < 16 || len(providerAck) < 1 || len(providerAck) > 512 {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryAckOutboxSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, providerAck)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		ID          string    `json:"id"`
		PublishedAt time.Time `json:"published_at"`
		ProviderAck string    `json:"provider_ack"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.ProviderAck != providerAck || !validPastServerTime(result.PublishedAt) {
		return ErrRepositoryUnavailable
	}
	return nil
}

type SensorTokenIssue struct {
	SensorID, TokenID string
	Salt, TokenHash   []byte
	ExpiresAt         time.Time
}
type SensorTokenRecord struct {
	ID        string    `json:"id"`
	SensorID  string    `json:"sensor_id"`
	Audience  string    `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (repository *DiscoveryRepository) IssueSensorToken(ctx context.Context, scope domain.Scope, input SensorTokenIssue) (SensorTokenRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.SensorID) || !validProductID(input.TokenID) || len(input.Salt) < 16 || len(input.Salt) > 64 || len(input.TokenHash) != 32 || input.ExpiresAt.Location() != time.UTC {
		return SensorTokenRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryIssueSensorTokenSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SensorID, input.TokenID, input.Salt, input.TokenHash, input.ExpiresAt)
	if err != nil {
		return SensorTokenRecord{}, discoveryProviderError(err)
	}
	var result SensorTokenRecord
	if decodeStrictDiscovery(payload, &result) != nil || !validIssuedRecord(result.ID, input.TokenID, result.SensorID, input.SensorID, result.Audience, "event-ingest", result.IssuedAt, result.ExpiresAt, input.ExpiresAt) {
		return SensorTokenRecord{}, ErrRepositoryUnavailable
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}

type GatewayEnrollment struct {
	DeviceID, EnrollmentID, CredentialID, Audience, KeyReference string
	TokenHash, Salt, PublicKey                                   []byte
	ExpiresAt                                                    time.Time
}
type GatewayCredentialRecord struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Audience  string    `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (repository *DiscoveryRepository) EnrollGateway(ctx context.Context, scope domain.Scope, input GatewayEnrollment) (GatewayCredentialRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.DeviceID) || !validProductID(input.EnrollmentID) || !validProductID(input.CredentialID) || input.Audience != "runtime-gateway" || len(input.TokenHash) != 32 || len(input.Salt) < 16 || len(input.Salt) > 64 || len(input.PublicKey) < 32 || len(input.PublicKey) > 4096 || !validOpaqueReference(input.KeyReference) || input.ExpiresAt.Location() != time.UTC {
		return GatewayCredentialRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayEnrollSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.DeviceID, input.EnrollmentID, input.CredentialID, input.TokenHash, input.Audience, input.KeyReference, input.PublicKey, input.ExpiresAt)
	if err != nil {
		return GatewayCredentialRecord{}, discoveryProviderError(err)
	}
	var result GatewayCredentialRecord
	if decodeStrictDiscovery(payload, &result) != nil || !validIssuedRecord(result.ID, input.CredentialID, result.DeviceID, input.DeviceID, result.Audience, "runtime-gateway", result.IssuedAt, result.ExpiresAt, input.ExpiresAt) {
		return GatewayCredentialRecord{}, ErrRepositoryUnavailable
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) AdvanceGatewayReplay(ctx context.Context, scope domain.Scope, deviceID string, expected, next int64) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deviceID) || expected < 0 || next <= expected {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayAdvanceSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deviceID, expected, next)
	if err != nil {
		return discoveryProviderError(err)
	}
	var value int64
	if decodeStrictDiscovery(payload, &value) != nil || value != next {
		return ErrRepositoryUnavailable
	}
	return nil
}

type GatewayCredentialRotation struct {
	DeviceID, CurrentCredentialID, ReplacementCredentialID, KeyReference string
	PublicKey                                                            []byte
	ExpiresAt                                                            time.Time
}

func (repository *DiscoveryRepository) RotateGatewayCredential(ctx context.Context, scope domain.Scope, input GatewayCredentialRotation) (GatewayCredentialRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.DeviceID) || !validProductID(input.CurrentCredentialID) || !validProductID(input.ReplacementCredentialID) || input.CurrentCredentialID == input.ReplacementCredentialID || !validOpaqueReference(input.KeyReference) || len(input.PublicKey) < 32 || len(input.PublicKey) > 4096 || input.ExpiresAt.Location() != time.UTC {
		return GatewayCredentialRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayRotateSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.DeviceID, input.CurrentCredentialID, input.ReplacementCredentialID, input.KeyReference, input.PublicKey, input.ExpiresAt)
	if err != nil {
		return GatewayCredentialRecord{}, discoveryProviderError(err)
	}
	var result GatewayCredentialRecord
	if decodeStrictDiscovery(payload, &result) != nil || !validIssuedRecord(result.ID, input.ReplacementCredentialID, result.DeviceID, input.DeviceID, result.Audience, "runtime-gateway", result.IssuedAt, result.ExpiresAt, input.ExpiresAt) {
		return GatewayCredentialRecord{}, ErrRepositoryUnavailable
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) RevokeGatewayCredential(ctx context.Context, scope domain.Scope, deviceID, credentialID string) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(deviceID) || !validProductID(credentialID) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayRevokeSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), deviceID, credentialID)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		ID        string    `json:"id"`
		RevokedAt time.Time `json:"revoked_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != credentialID || !validPastServerTime(result.RevokedAt) {
		return ErrRepositoryUnavailable
	}
	return nil
}

type GatewayPolicySubscription struct {
	DeviceID, PolicyID      string
	PolicyVersion           int64
	PolicyDigest, Signature []byte
	IssuedAt, ExpiresAt     time.Time
	Sequence                int64
}

func (repository *DiscoveryRepository) PutGatewayPolicySubscription(ctx context.Context, scope domain.Scope, input GatewayPolicySubscription) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.DeviceID) || !validProductID(input.PolicyID) || input.PolicyVersion < 1 || len(input.PolicyDigest) != 32 || len(input.Signature) < 32 || len(input.Signature) > 8192 || input.IssuedAt.Location() != time.UTC || input.ExpiresAt.Location() != time.UTC || !input.ExpiresAt.After(input.IssuedAt) || input.Sequence < 0 {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayPolicySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.DeviceID, input.PolicyID, input.PolicyVersion, input.PolicyDigest, input.Signature, input.IssuedAt, input.ExpiresAt, input.Sequence)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		PolicyID string `json:"policy_id"`
		Sequence int64  `json:"sequence"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.PolicyID != input.PolicyID || result.Sequence != input.Sequence {
		return ErrRepositoryUnavailable
	}
	return nil
}

type InventoryEvidence struct {
	ID              string    `json:"id"`
	IntegrationID   string    `json:"integration_id"`
	SnapshotID      string    `json:"snapshot_id"`
	EntityID        *string   `json:"entity_id"`
	FindingID       *string   `json:"finding_id"`
	ObjectReference string    `json:"object_reference"`
	Checksum        []byte    `json:"checksum"`
	MediaType       string    `json:"media_type"`
	SchemaVersion   string    `json:"schema_version"`
	ParserVersion   string    `json:"parser_version"`
	CollectedAt     time.Time `json:"collected_at"`
}

func (repository *DiscoveryRepository) GetInventoryEvidence(ctx context.Context, scope domain.Scope, id string) (InventoryEvidence, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(id) {
		return InventoryEvidence{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryEvidenceGetSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		return InventoryEvidence{}, discoveryProviderError(err)
	}
	var result InventoryEvidence
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validProductID(result.IntegrationID) || !validProductID(result.SnapshotID) || len(result.Checksum) != 32 || !validS3ObjectReference(result.ObjectReference) || len(result.MediaType) < 1 || len(result.MediaType) > 128 || len(result.SchemaVersion) < 1 || len(result.SchemaVersion) > 64 || len(result.ParserVersion) < 1 || len(result.ParserVersion) > 64 || !validPastServerTime(result.CollectedAt) || !validEvidenceSubject(result.EntityID, result.FindingID) {
		return InventoryEvidence{}, ErrRepositoryUnavailable
	}
	result.CollectedAt = result.CollectedAt.UTC()
	return result, nil
}

type SensorTokenRotation struct {
	SensorID, CurrentTokenID, ReplacementTokenID string
	Salt, TokenHash                              []byte
	ExpiresAt                                    time.Time
}

func (repository *DiscoveryRepository) RotateSensorToken(ctx context.Context, scope domain.Scope, input SensorTokenRotation) (SensorTokenRecord, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.SensorID) || !validProductID(input.CurrentTokenID) || !validProductID(input.ReplacementTokenID) || len(input.Salt) < 16 || len(input.Salt) > 64 || len(input.TokenHash) != 32 || input.ExpiresAt.Location() != time.UTC {
		return SensorTokenRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoverySensorRotateSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SensorID, input.CurrentTokenID, input.ReplacementTokenID, input.Salt, input.TokenHash, input.ExpiresAt)
	if err != nil {
		return SensorTokenRecord{}, discoveryProviderError(err)
	}
	var result SensorTokenRecord
	if decodeStrictDiscovery(payload, &result) != nil || !validIssuedRecord(result.ID, input.ReplacementTokenID, result.SensorID, input.SensorID, result.Audience, "event-ingest", result.IssuedAt, result.ExpiresAt, input.ExpiresAt) {
		return SensorTokenRecord{}, ErrRepositoryUnavailable
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.ExpiresAt = result.ExpiresAt.UTC()
	return result, nil
}
func (repository *DiscoveryRepository) RevokeSensorToken(ctx context.Context, scope domain.Scope, sensorID, tokenID string) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(sensorID) || !validProductID(tokenID) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoverySensorRevokeSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sensorID, tokenID)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		ID        string    `json:"id"`
		RevokedAt time.Time `json:"revoked_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != tokenID || !validPastServerTime(result.RevokedAt) {
		return ErrRepositoryUnavailable
	}
	return nil
}

type SensorHeartbeat struct {
	SensorID                string
	Sequence, DroppedEvents int64
	Status                  string
	Metadata                json.RawMessage
}

func (repository *DiscoveryRepository) RecordSensorHeartbeat(ctx context.Context, scope domain.Scope, input SensorHeartbeat) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.SensorID) || input.Sequence < 0 || input.DroppedEvents < 0 || !stringIn(input.Status, "healthy", "degraded") || !discoveryValidJSONObject(input.Metadata, 16384) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoverySensorHeartbeatSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SensorID, input.Sequence, input.Status, input.DroppedEvents, input.Metadata)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		SensorID   string    `json:"sensor_id"`
		Sequence   int64     `json:"sequence"`
		ObservedAt time.Time `json:"observed_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.SensorID != input.SensorID || result.Sequence != input.Sequence || !validPastServerTime(result.ObservedAt) {
		return ErrRepositoryUnavailable
	}
	return nil
}

type RuntimeBatchCreate struct {
	SensorID, BatchID, JobID, OutboxID, IdempotencyKey string
	PayloadDigest                                      []byte
	EventCount                                         int
	ObjectReference, MediaType, SchemaVersion          string
	PayloadBytes                                       int64
}
type RuntimeBatchResult struct {
	BatchID  string `json:"batch_id"`
	Replayed bool   `json:"replayed"`
}

func (repository *DiscoveryRepository) CreateRuntimeBatch(ctx context.Context, scope domain.Scope, input RuntimeBatchCreate) (RuntimeBatchResult, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.SensorID) || !validProductID(input.BatchID) || !validProductID(input.JobID) || !validProductID(input.OutboxID) || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 || len(input.PayloadDigest) != 32 || input.EventCount < 1 || input.EventCount > 1000 || !validS3ObjectReference(input.ObjectReference) || input.PayloadBytes < 1 || input.PayloadBytes > 64<<20 || len(input.MediaType) < 1 || len(input.MediaType) > 128 || len(input.SchemaVersion) < 1 || len(input.SchemaVersion) > 64 {
		return RuntimeBatchResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryRuntimeBatchSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SensorID, input.BatchID, input.JobID, input.OutboxID, input.IdempotencyKey, input.PayloadDigest, input.EventCount, input.ObjectReference, input.PayloadBytes, input.MediaType, input.SchemaVersion)
	if err != nil {
		return RuntimeBatchResult{}, discoveryProviderError(err)
	}
	var result RuntimeBatchResult
	if decodeStrictDiscovery(payload, &result) != nil || result.BatchID != input.BatchID {
		return RuntimeBatchResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

type RuntimeStageCompletion struct {
	BatchID, Stage, ResultReference string
	InputDigest                     []byte
	Succeeded                       bool
}

func (repository *DiscoveryRepository) CompleteRuntimeStage(ctx context.Context, scope domain.Scope, input RuntimeStageCompletion) error {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.BatchID) || !stringIn(input.Stage, "archive", "index", "correlate", "risk", "graph", "complete") || len(input.InputDigest) != 32 || input.ResultReference != "" && !validS3ObjectReference(input.ResultReference) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryRuntimeStageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.BatchID, input.Stage, input.InputDigest, input.Succeeded, input.ResultReference)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		BatchID string `json:"batch_id"`
		Stage   string `json:"stage"`
		State   string `json:"state"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.BatchID != input.BatchID || result.Stage != input.Stage || result.State != map[bool]string{true: "succeeded", false: "failed"}[input.Succeeded] {
		return ErrRepositoryUnavailable
	}
	return nil
}

type DiscoveryJobLease struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	AuthorityID    string    `json:"authority_id"`
	Attempt        int       `json:"attempt"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}
type DiscoveryScheduleLease struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	ID             string    `json:"id"`
	IntegrationID  string    `json:"integration_id"`
	NextRunAt      time.Time `json:"next_run_at"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}
type ProjectionWorkLease struct {
	OrganizationID string    `json:"organization_id"`
	WorkspaceID    string    `json:"workspace_id"`
	EnvironmentID  string    `json:"environment_id"`
	SnapshotID     string    `json:"snapshot_id"`
	Kind           string    `json:"kind"`
	Version        string    `json:"version"`
	InputDigest    []byte    `json:"input_digest"`
	Attempt        int       `json:"attempt"`
	AvailableAt    time.Time `json:"available_at"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

func (repository *DiscoveryRepository) ClaimDiscoveryJobs(ctx context.Context, worker, token, kind string, seconds, limit int) ([]DiscoveryJobLease, error) {
	if !validClaimInput(repository, ctx, worker, token, seconds, limit) || !stringIn(kind, "discovery", "runtime", "projection") {
		return nil, ErrRepositoryOperation
	}
	var envelope struct {
		Items []DiscoveryJobLease `json:"items"`
	}
	if err := repository.claimTyped(ctx, postgresDiscoveryClaimJobsSQL, &envelope, worker, token, seconds, limit, kind); err != nil {
		return nil, err
	}
	if envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.AuthorityID) || item.Kind != kind || item.Attempt < 1 || !validLeaseExpiration(item.LeaseExpiresAt, seconds) {
			return nil, ErrRepositoryUnavailable
		}
		if item.Attempt > 100 {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}
func (repository *DiscoveryRepository) ClaimDiscoverySchedules(ctx context.Context, worker, token string, seconds, limit int) ([]DiscoveryScheduleLease, error) {
	if !validClaimInput(repository, ctx, worker, token, seconds, limit) {
		return nil, ErrRepositoryOperation
	}
	var envelope struct {
		Items []DiscoveryScheduleLease `json:"items"`
	}
	if err := repository.claimTyped(ctx, postgresDiscoveryClaimSchedulesSQL, &envelope, worker, token, seconds, limit); err != nil {
		return nil, err
	}
	if envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.IntegrationID) || item.NextRunAt.IsZero() || !validLeaseExpiration(item.LeaseExpiresAt, seconds) {
			return nil, ErrRepositoryUnavailable
		}
		item.NextRunAt = item.NextRunAt.UTC()
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}
func (repository *DiscoveryRepository) ClaimProjectionWork(ctx context.Context, worker, token string, seconds, limit int) ([]ProjectionWorkLease, error) {
	if !validClaimInput(repository, ctx, worker, token, seconds, limit) {
		return nil, ErrRepositoryOperation
	}
	var envelope struct {
		Items []ProjectionWorkLease `json:"items"`
	}
	if err := repository.claimTyped(ctx, postgresDiscoveryClaimProjectionSQL, &envelope, worker, token, seconds, limit); err != nil {
		return nil, err
	}
	if envelope.Items == nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.SnapshotID) || !stringIn(item.Kind, "risk", "graph", "search") || len(item.Version) < 1 || len(item.InputDigest) != 32 || item.Attempt < 1 || !validLeaseExpiration(item.LeaseExpiresAt, seconds) {
			return nil, ErrRepositoryUnavailable
		}
		if len(item.Version) > 64 || item.Attempt > 100 {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return envelope.Items, nil
}

type DiscoveryScheduleCompletion struct {
	ID, Worker, LeaseToken, Outcome string
	NextRunAt                       time.Time
}
type DiscoveryScheduleCompletionResult struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	NextRunAt time.Time `json:"next_run_at"`
	Version   int64     `json:"version"`
}

func (repository *DiscoveryRepository) CompleteDiscoverySchedule(ctx context.Context, scope domain.Scope, input DiscoveryScheduleCompletion) (DiscoveryScheduleCompletionResult, error) {
	if !validTransitionInput(repository, ctx, scope, input.ID, input.Worker, input.LeaseToken) || !stringIn(input.Outcome, "advanced", "released", "disabled") || input.NextRunAt.Location() != time.UTC {
		return DiscoveryScheduleCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryCompleteScheduleSQL, input.ID, input.Worker, input.LeaseToken, input.Outcome, input.NextRunAt)
	if err != nil {
		return DiscoveryScheduleCompletionResult{}, err
	}
	var result DiscoveryScheduleCompletionResult
	expectedState := "enabled"
	if input.Outcome == "disabled" {
		expectedState = "disabled"
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || result.State != expectedState || !result.NextRunAt.Equal(input.NextRunAt) || result.Version < 1 {
		return DiscoveryScheduleCompletionResult{}, ErrRepositoryUnavailable
	}
	result.NextRunAt = result.NextRunAt.UTC()
	return result, nil
}

type DiscoveryJobCompletion struct {
	ID, Worker, LeaseToken, Outcome, LastErrorCode, LastError string
	ResultDigest                                              []byte
	RetryAfterSeconds                                         int
}
type WorkCompletionResult struct {
	ID          string     `json:"id"`
	SnapshotID  string     `json:"snapshot_id"`
	Kind        string     `json:"kind"`
	State       string     `json:"state"`
	Attempt     int        `json:"attempt"`
	CompletedAt *time.Time `json:"completed_at"`
}

func (repository *DiscoveryRepository) FinishDiscoveryJob(ctx context.Context, scope domain.Scope, input DiscoveryJobCompletion) (WorkCompletionResult, error) {
	if !validTransitionInput(repository, ctx, scope, input.ID, input.Worker, input.LeaseToken) || !stringIn(input.Outcome, "succeeded", "retryable", "failed", "cancelled") || (len(input.ResultDigest) != 0 && len(input.ResultDigest) != 32) || (input.Outcome == "succeeded" && input.LastError != "") || (input.Outcome != "succeeded" && (len(input.LastError) < 1 || len(input.LastError) > 1024)) || input.RetryAfterSeconds < 0 || input.RetryAfterSeconds > 3600 {
		return WorkCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryFinishJobSQL, input.ID, input.Worker, input.LeaseToken, input.Outcome, input.ResultDigest, input.LastError, input.RetryAfterSeconds)
	if err != nil {
		return WorkCompletionResult{}, err
	}
	var result WorkCompletionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ID || !validCompletionState(input.Outcome, result.State) || result.Attempt < 1 || result.Attempt > 100 || (result.State == "retryable") != (result.CompletedAt == nil) || result.CompletedAt != nil && !validPastServerTime(*result.CompletedAt) {
		return WorkCompletionResult{}, ErrRepositoryUnavailable
	}
	if result.CompletedAt != nil {
		completedAt := result.CompletedAt.UTC()
		result.CompletedAt = &completedAt
	}
	return result, nil
}

type ProjectionWorkCompletion struct {
	SnapshotID, Kind, Version, Worker, LeaseToken, Outcome, DriverReceipt, LastError string
	DriverDigest                                                                     []byte
	RetryAfterSeconds                                                                int
}

func (repository *DiscoveryRepository) FinishProjectionWork(ctx context.Context, scope domain.Scope, input ProjectionWorkCompletion) (WorkCompletionResult, error) {
	if !validTransitionInput(repository, ctx, scope, input.SnapshotID, input.Worker, input.LeaseToken) || !stringIn(input.Kind, "risk", "graph", "search") || len(input.Version) < 1 || len(input.Version) > 64 || !stringIn(input.Outcome, "succeeded", "retryable", "failed", "cancelled") || (input.Outcome == "succeeded" && input.LastError != "") || (input.Outcome != "succeeded" && (len(input.LastError) < 1 || len(input.LastError) > 1024)) || input.RetryAfterSeconds < 0 || input.RetryAfterSeconds > 3600 {
		return WorkCompletionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryFinishProjectionSQL, input.SnapshotID, input.Kind, input.Version, input.Worker, input.LeaseToken, input.Outcome, input.LastError, input.RetryAfterSeconds)
	if err != nil {
		return WorkCompletionResult{}, err
	}
	var result WorkCompletionResult
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID || result.Kind != input.Kind || !validCompletionState(input.Outcome, result.State) || result.Attempt < 1 || result.Attempt > 100 || result.CompletedAt != nil {
		return WorkCompletionResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
func (repository *DiscoveryRepository) claimTyped(ctx context.Context, statement string, destination any, args ...any) error {
	if !validDiscoveryRepository(repository, ctx) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, statement, args...)
	if err != nil {
		return discoveryProviderError(err)
	}
	if decodeStrictDiscovery(payload, destination) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validLeaseExpiration(value time.Time, leaseSeconds int) bool {
	now := time.Now()
	return !value.IsZero() && value.After(now) && !value.After(now.Add(time.Duration(leaseSeconds)*time.Second+5*time.Second))
}

func validPastServerTime(value time.Time) bool {
	return !value.IsZero() && !value.After(time.Now().Add(5*time.Second))
}

func validRetryAvailability(value time.Time, retrySeconds int) bool {
	now := time.Now()
	return value.After(now) && !value.After(now.Add(time.Duration(retrySeconds)*time.Second+5*time.Second))
}

func validIssuedRecord(id, expectedID, parentID, expectedParentID, audience, expectedAudience string, issuedAt, expiresAt, expectedExpiresAt time.Time) bool {
	return id == expectedID && parentID == expectedParentID && audience == expectedAudience && validPastServerTime(issuedAt) && expiresAt.Equal(expectedExpiresAt) && expiresAt.After(time.Now()) && expiresAt.After(issuedAt)
}

func validEvidenceSubject(entityID, findingID *string) bool {
	if (entityID == nil) == (findingID == nil) {
		return false
	}
	if entityID != nil {
		return validProductID(*entityID)
	}
	return validProductID(*findingID)
}

func validS3ObjectReference(value string) bool {
	if len(value) < 8 || len(value) > 1024 {
		return false
	}
	parts := s3ObjectReferencePattern.FindStringSubmatch(value)
	if len(parts) != 3 || strings.Contains(parts[1], "..") || strings.Contains(parts[1], ".-") || strings.Contains(parts[1], "-.") {
		return false
	}
	for _, segment := range strings.Split(parts[2], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validCompletionState(requested, returned string) bool {
	if requested == "retryable" {
		return returned == "retryable" || returned == "failed"
	}
	return returned == requested
}
func (repository *DiscoveryRepository) CompleteDiscoveryJob(ctx context.Context, scope domain.Scope, id, worker, token string, resultDigest []byte, retryable bool, lastError string) error {
	if !validTransitionInput(repository, ctx, scope, id, worker, token) || (len(resultDigest) != 0 && len(resultDigest) != 32) || retryable && (len(lastError) < 1 || len(lastError) > 1024) || !retryable && lastError != "" {
		return ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryCompleteJobSQL, id, worker, token, resultDigest, retryable, lastError)
	if err != nil {
		return err
	}
	var result struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	decodeErr := decodeStrictDiscovery(payload, &result)
	validState := result.State == "succeeded"
	if retryable {
		validState = stringIn(result.State, "retryable", "failed")
	}
	if decodeErr != nil || result.ID != id || !validState {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (repository *DiscoveryRepository) RetryOutbox(ctx context.Context, scope domain.Scope, id, worker, token string, retrySeconds int, lastError string) error {
	if !validTransitionInput(repository, ctx, scope, id, worker, token) || retrySeconds < 1 || retrySeconds > 3600 || len(lastError) < 1 || len(lastError) > 1024 {
		return ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryRetryOutboxSQL, id, worker, token, retrySeconds, lastError)
	if err != nil {
		return err
	}
	var result struct {
		ID          string    `json:"id"`
		AvailableAt time.Time `json:"available_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validRetryAvailability(result.AvailableAt, retrySeconds) {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (repository *DiscoveryRepository) CompleteProjectionWork(ctx context.Context, scope domain.Scope, snapshotID, kind, version, worker, token string, succeeded bool) error {
	if !validTransitionInput(repository, ctx, scope, snapshotID, worker, token) || !stringIn(kind, "risk", "graph", "search") || len(version) < 1 || len(version) > 64 {
		return ErrRepositoryOperation
	}
	payload, err := repository.scopedTransition(ctx, scope, postgresDiscoveryCompleteProjectionSQL, snapshotID, kind, version, worker, token, succeeded)
	if err != nil {
		return err
	}
	var result struct {
		SnapshotID string `json:"snapshot_id"`
		Kind       string `json:"kind"`
		State      string `json:"state"`
	}
	decodeErr := decodeStrictDiscovery(payload, &result)
	validState := result.State == "succeeded"
	if !succeeded {
		validState = stringIn(result.State, "retryable", "failed")
	}
	if decodeErr != nil || result.SnapshotID != snapshotID || result.Kind != kind || !validState {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (repository *DiscoveryRepository) scopedTransition(ctx context.Context, scope domain.Scope, statement string, args ...any) (json.RawMessage, error) {
	full := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}
	full = append(full, args...)
	payload, err := repository.database.QueryJSON(ctx, statement, full...)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	return payload, nil
}
func validClaimInput(repository *DiscoveryRepository, ctx context.Context, worker, token string, seconds, limit int) bool {
	return validDiscoveryRepository(repository, ctx) && len(worker) >= 1 && len(worker) <= 128 && len(token) >= 16 && len(token) <= 128 && seconds >= 5 && seconds <= 900 && limit >= 1 && limit <= 100
}
func validLeaseScope(organization, workspace, environment string) bool {
	return validProductID(organization) && validProductID(workspace) && validProductID(environment)
}
func validTransitionInput(repository *DiscoveryRepository, ctx context.Context, scope domain.Scope, id, worker, token string) bool {
	return validDiscoveryRepository(repository, ctx) && scope.Validate() == nil && validProductID(id) && len(worker) >= 1 && len(worker) <= 128 && len(token) >= 16 && len(token) <= 128
}

func CanonicalDiscoveryID(scope domain.Scope, kind, sourceNativeID string) (string, error) {
	if scope.Validate() != nil || len(kind) < 1 || len(kind) > 64 || len(sourceNativeID) < 1 || len(sourceNativeID) > 1024 {
		return "", ErrRepositoryOperation
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), kind, sourceNativeID}, "\x1f")))
	hexValue := hex.EncodeToString(digest[:])
	return fmt.Sprintf("pid_%s-%s-4%s-8%s-%s", hexValue[:8], hexValue[8:12], hexValue[13:16], hexValue[17:20], hexValue[20:32]), nil
}

func CanonicalDiscoveryRelationshipID(scope domain.Scope, integrationID, source, kind, sourceNativeID string) (string, error) {
	if scope.Validate() != nil || !validProductID(integrationID) || len(source) < 1 || len(source) > 64 || len(kind) < 1 || len(kind) > 64 || len(sourceNativeID) < 1 || len(sourceNativeID) > 1024 {
		return "", ErrRepositoryOperation
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID, source, sourceNativeID}, "\x1f")))
	hexValue := hex.EncodeToString(digest[:])
	return fmt.Sprintf("pid_%s-%s-4%s-8%s-%s", hexValue[:8], hexValue[8:12], hexValue[13:16], hexValue[17:20], hexValue[20:32]), nil
}

func validDiscoveryRepository(repository *DiscoveryRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}
func validIntegrationCreate(value IntegrationCreate) bool {
	return validProductID(value.ID) && len(value.Kind) >= 1 && len(value.Kind) <= 64 && len(value.ConnectorVersion) >= 1 && len(value.ConnectorVersion) <= 64 && len(value.DisplayName) >= 1 && len(value.DisplayName) <= 128 && validReferenceOnlyJSON(value.Configuration) && (value.CredentialReference == "" || validOpaqueReference(value.CredentialReference))
}
func validOpaqueReference(value string) bool {
	return len(value) >= 12 && len(value) <= 512 && opaqueReferencePattern.MatchString(value)
}
func validDiscoveryIntegration(value DiscoveryIntegration) bool {
	return validProductID(value.ID) && len(value.Kind) >= 1 && len(value.Kind) <= 64 && len(value.ConnectorVersion) >= 1 && len(value.ConnectorVersion) <= 64 && len(value.DisplayName) >= 1 && len(value.DisplayName) <= 128 && stringIn(value.State, "pending", "authorizing", "active", "degraded", "disabled", "deleted") && value.Version > 0 && validPastServerTime(value.CreatedAt) && !value.UpdatedAt.Before(value.CreatedAt) && validPastServerTime(value.UpdatedAt)
}
func validSyncRequest(value SyncRequest) bool {
	return validProductID(value.IntegrationID) && validProductID(value.SyncID) && validProductID(value.JobID) && validProductID(value.OutboxID) && len(value.IdempotencyKey) >= 16 && len(value.IdempotencyKey) <= 128 && len(value.RequestDigest) == 32 && stringIn(value.TriggerKind, "manual", "schedule", "retry") && len(value.ParserVersion) >= 1 && len(value.ParserVersion) <= 64 && len(value.ToolVersion) >= 1 && len(value.ToolVersion) <= 64
}
func validCompleteSnapshot(value CompleteSnapshot) bool {
	return validProductID(value.IntegrationID) && validProductID(value.SyncID) && validProductID(value.SnapshotID) && value.Generation > 0 && len(value.Source) >= 1 && len(value.Source) <= 64 && value.CursorProvider == value.Source && validS3ObjectReference(value.ManifestReference) && len(value.ManifestChecksum) == 32 && value.CollectedAt.Location() == time.UTC && validPastServerTime(value.CollectedAt) && len(value.CursorValue) >= 1 && len(value.CursorValue) <= 4096 && validJSONArray(value.Entities, 16<<20) && validJSONArray(value.Relationships, 16<<20) && validJSONArray(value.Evidence, 16<<20)
}
func validReferenceOnlyJSON(value json.RawMessage) bool {
	if !discoveryValidJSONObject(value, 16384) {
		return false
	}
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return false
	}
	return referenceTreeSafe(decoded)
}
func referenceTreeSafe(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if referenceOnlyKeyPattern.MatchString(key) || !referenceTreeSafe(child) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !referenceTreeSafe(child) {
				return false
			}
		}
	}
	return true
}
func discoveryValidJSONObject(value json.RawMessage, limit int) bool {
	return len(value) > 0 && len(value) <= limit && json.Valid(value) && value[0] == '{'
}
func validJSONArray(value json.RawMessage, limit int) bool {
	return len(value) > 0 && len(value) <= limit && json.Valid(value) && value[0] == '['
}
func decodeStrictDiscovery(payload json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrRepositoryUnavailable
	}
	return nil
}
func discoveryProviderError(err error) error {
	if err == nil {
		return nil
	}
	if err == ErrRepositoryNotFound || err == ErrRepositoryConflict || err == ErrRepositoryOperation {
		return err
	}
	return errors.Join(ErrRepositoryUnavailable, err)
}
