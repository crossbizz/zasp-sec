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
	postgresDiscoveryReadySQL              = `SELECT to_jsonb(zasp_discovery_readiness($1,$2))`
	postgresDiscoveryCreateIntegrationSQL  = `SELECT zasp_discovery_create_integration($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NULLIF($9,''))`
	postgresDiscoveryRequestSyncSQL        = `SELECT zasp_discovery_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresDiscoveryApplySnapshotSQL      = `SELECT zasp_discovery_apply_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb)`
	postgresDiscoveryEntityPageSQL         = `SELECT zasp_discovery_entity_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresDiscoveryClaimOutboxSQL        = `SELECT zasp_discovery_claim_outbox($1,$2,$3,$4)`
	postgresDiscoveryAckOutboxSQL          = `SELECT zasp_discovery_ack_outbox($1,$2,$3,$4,$5,$6,$7)`
	postgresDiscoveryIssueSensorTokenSQL   = `SELECT zasp_discovery_issue_sensor_token($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryGatewayEnrollSQL      = `SELECT zasp_discovery_gateway_enroll($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresDiscoveryGatewayAdvanceSQL     = `SELECT zasp_discovery_gateway_advance_replay($1,$2,$3,$4,$5,$6)`
	postgresDiscoveryGatewayRotateSQL      = `SELECT zasp_discovery_gateway_rotate($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryGatewayRevokeSQL      = `SELECT zasp_discovery_gateway_revoke($1,$2,$3,$4,$5)`
	postgresDiscoveryGatewayPolicySQL      = `SELECT zasp_discovery_put_gateway_policy($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	postgresDiscoveryClaimJobsSQL          = `SELECT zasp_discovery_claim_jobs($1,$2,$3,$4,$5)`
	postgresDiscoveryClaimSchedulesSQL     = `SELECT zasp_discovery_claim_schedules($1,$2,$3,$4)`
	postgresDiscoveryClaimProjectionSQL    = `SELECT zasp_discovery_claim_projection_work($1,$2,$3,$4)`
	postgresDiscoveryCompleteJobSQL        = `SELECT zasp_discovery_complete_job($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryRetryOutboxSQL        = `SELECT zasp_discovery_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresDiscoveryCompleteProjectionSQL = `SELECT zasp_discovery_complete_projection($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoveryEvidenceGetSQL        = `SELECT zasp_discovery_evidence_get($1,$2,$3,$4)`
	postgresDiscoverySensorRotateSQL       = `SELECT zasp_discovery_sensor_rotate($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresDiscoverySensorRevokeSQL       = `SELECT zasp_discovery_sensor_revoke($1,$2,$3,$4,$5)`
	postgresDiscoverySensorHeartbeatSQL    = `SELECT zasp_discovery_sensor_heartbeat($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`
	postgresDiscoveryRuntimeBatchSQL       = `SELECT zasp_discovery_create_runtime_batch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresDiscoveryRuntimeStageSQL       = `SELECT zasp_discovery_complete_runtime_stage($1,$2,$3,$4,$5,$6,$7,$8)`
)

var referenceOnlyKeyPattern = regexp.MustCompile(`(?i)(secret|password|token|credential|private.?key|session)`)

type IntegrationRepository interface {
	CreateIntegration(context.Context, RequestIdentity, IntegrationCreate) (DiscoveryIntegration, error)
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
}

type RuntimeAuthorityRepository interface {
	IssueSensorToken(context.Context, domain.Scope, SensorTokenIssue) (SensorTokenRecord, error)
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

type DiscoveryRepository struct{ database JSONDatabase }

func NewDiscoveryRepository(database JSONDatabase) (*DiscoveryRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	payload, err := database.QueryJSON(context.Background(), postgresDiscoveryReadySQL, migrations.ProductionDiscovery().Checksum(), migrations.ProductionDiscoverySemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	return &DiscoveryRepository{database: database}, nil
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
	if decodeStrictDiscovery(payload, &result) != nil || !validDiscoveryIntegration(result) {
		return DiscoveryIntegration{}, ErrRepositoryUnavailable
	}
	result.CreatedAt = result.CreatedAt.UTC()
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
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryRequestSyncSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IntegrationID, input.SyncID, input.JobID, input.OutboxID, input.IdempotencyKey, input.RequestDigest, input.TriggerKind, input.ParserVersion, input.ToolVersion)
	if err != nil {
		return SyncRequestResult{}, discoveryProviderError(err)
	}
	var result SyncRequestResult
	if decodeStrictDiscovery(payload, &result) != nil || !validProductID(result.SyncID) || !validProductID(result.JobID) || !validProductID(result.OutboxID) || result.State != "queued" {
		return SyncRequestResult{}, ErrRepositoryUnavailable
	}
	return result, nil
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
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != input.SnapshotID || result.DiscoveredCount < 0 || result.ChangedCount < 0 || result.RemovedCount < 0 || result.CommittedAt.IsZero() {
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
		if !validProductID(item.ID) || item.ID <= last || len(item.Kind) < 1 || len(item.Kind) > 64 || len(item.DisplayName) < 1 || len(item.DisplayName) > 256 || item.State != "active" || item.Version < 1 || item.FirstSeenAt.IsZero() || item.LastSeenAt.Before(item.FirstSeenAt) || !discoveryValidJSONObject(item.StableFields, 65536) {
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
		if !validProductID(item.OrganizationID) || !validProductID(item.WorkspaceID) || !validProductID(item.EnvironmentID) || !validProductID(item.ID) || !stringIn(item.Topic, "discovery-jobs", "runtime-events", "projection-work") || len(item.DeterministicKey) < 16 || item.PayloadVersion < 1 || item.PayloadVersion > 32 || !discoveryValidJSONObject(item.Payload, 65536) || len(item.PayloadDigest) != sha256.Size || item.Attempt < 1 || item.LeaseExpiresAt.IsZero() {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.ProviderAck != providerAck || result.PublishedAt.IsZero() {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.TokenID || result.SensorID != input.SensorID || result.Audience != "event-ingest" || result.IssuedAt.IsZero() || !result.ExpiresAt.After(result.IssuedAt) {
		return SensorTokenRecord{}, ErrRepositoryUnavailable
	}
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
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.DeviceID) || !validProductID(input.EnrollmentID) || !validProductID(input.CredentialID) || input.Audience != "runtime-gateway" || len(input.TokenHash) != 32 || len(input.Salt) < 16 || len(input.PublicKey) < 32 || !strings.HasPrefix(input.KeyReference, "ref:") || input.ExpiresAt.Location() != time.UTC {
		return GatewayCredentialRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayEnrollSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.DeviceID, input.EnrollmentID, input.CredentialID, input.TokenHash, input.Audience, input.KeyReference, input.PublicKey, input.ExpiresAt)
	if err != nil {
		return GatewayCredentialRecord{}, discoveryProviderError(err)
	}
	var result GatewayCredentialRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.CredentialID || result.DeviceID != input.DeviceID || result.Audience != "runtime-gateway" {
		return GatewayCredentialRecord{}, ErrRepositoryUnavailable
	}
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
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.DeviceID) || !validProductID(input.CurrentCredentialID) || !validProductID(input.ReplacementCredentialID) || input.CurrentCredentialID == input.ReplacementCredentialID || !strings.HasPrefix(input.KeyReference, "ref:") || len(input.PublicKey) < 32 || len(input.PublicKey) > 4096 || input.ExpiresAt.Location() != time.UTC {
		return GatewayCredentialRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryGatewayRotateSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.DeviceID, input.CurrentCredentialID, input.ReplacementCredentialID, input.KeyReference, input.PublicKey, input.ExpiresAt)
	if err != nil {
		return GatewayCredentialRecord{}, discoveryProviderError(err)
	}
	var result GatewayCredentialRecord
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ReplacementCredentialID || result.DeviceID != input.DeviceID || result.Audience != "runtime-gateway" {
		return GatewayCredentialRecord{}, ErrRepositoryUnavailable
	}
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != credentialID || result.RevokedAt.IsZero() {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || !validProductID(result.IntegrationID) || !validProductID(result.SnapshotID) || len(result.Checksum) != 32 || !strings.HasPrefix(result.ObjectReference, "s3://") || result.CollectedAt.IsZero() || (result.EntityID == nil) == (result.FindingID == nil) {
		return InventoryEvidence{}, ErrRepositoryUnavailable
	}
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.ReplacementTokenID || result.SensorID != input.SensorID || result.Audience != "event-ingest" {
		return SensorTokenRecord{}, ErrRepositoryUnavailable
	}
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != tokenID || result.RevokedAt.IsZero() {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.SensorID != input.SensorID || result.Sequence != input.Sequence || result.ObservedAt.IsZero() {
		return ErrRepositoryUnavailable
	}
	return nil
}

type RuntimeBatchCreate struct {
	SensorID, BatchID, JobID, OutboxID, IdempotencyKey string
	PayloadDigest                                      []byte
	EventCount                                         int
}
type RuntimeBatchResult struct {
	BatchID  string `json:"batch_id"`
	Replayed bool   `json:"replayed"`
}

func (repository *DiscoveryRepository) CreateRuntimeBatch(ctx context.Context, scope domain.Scope, input RuntimeBatchCreate) (RuntimeBatchResult, error) {
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.SensorID) || !validProductID(input.BatchID) || !validProductID(input.JobID) || !validProductID(input.OutboxID) || len(input.IdempotencyKey) < 16 || len(input.PayloadDigest) != 32 || input.EventCount < 1 || input.EventCount > 1000 {
		return RuntimeBatchResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresDiscoveryRuntimeBatchSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input.SensorID, input.BatchID, input.JobID, input.OutboxID, input.IdempotencyKey, input.PayloadDigest, input.EventCount)
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
	if !validDiscoveryRepository(repository, ctx) || scope.Validate() != nil || !validProductID(input.BatchID) || !stringIn(input.Stage, "archive", "index", "correlate", "risk", "graph", "complete") || len(input.InputDigest) != 32 || len(input.ResultReference) > 1024 {
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
	if len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for _, item := range envelope.Items {
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.AuthorityID) || item.Kind != kind || item.Attempt < 1 || item.LeaseExpiresAt.IsZero() {
			return nil, ErrRepositoryUnavailable
		}
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
	if len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for _, item := range envelope.Items {
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.ID) || !validProductID(item.IntegrationID) || item.NextRunAt.IsZero() || item.LeaseExpiresAt.IsZero() {
			return nil, ErrRepositoryUnavailable
		}
	}
	if err := repository.claimTyped(ctx, postgresDiscoveryClaimSchedulesSQL, &envelope, worker, token, seconds, limit); err != nil {
		return nil, err
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
	if len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	for _, item := range envelope.Items {
		if !validLeaseScope(item.OrganizationID, item.WorkspaceID, item.EnvironmentID) || !validProductID(item.SnapshotID) || !stringIn(item.Kind, "risk", "graph", "search") || len(item.Version) < 1 || len(item.InputDigest) != 32 || item.Attempt < 1 || item.LeaseExpiresAt.IsZero() {
			return nil, ErrRepositoryUnavailable
		}
	}
	if err := repository.claimTyped(ctx, postgresDiscoveryClaimProjectionSQL, &envelope, worker, token, seconds, limit); err != nil {
		return nil, err
	}
	return envelope.Items, nil
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.State != map[bool]string{true: "retryable", false: "succeeded"}[retryable] {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != id || result.AvailableAt.IsZero() {
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
	if decodeStrictDiscovery(payload, &result) != nil || result.SnapshotID != snapshotID || result.Kind != kind || result.State != map[bool]string{true: "succeeded", false: "failed"}[succeeded] {
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

func validDiscoveryRepository(repository *DiscoveryRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}
func validIntegrationCreate(value IntegrationCreate) bool {
	return validProductID(value.ID) && len(value.Kind) >= 1 && len(value.Kind) <= 64 && len(value.ConnectorVersion) >= 1 && len(value.ConnectorVersion) <= 64 && len(value.DisplayName) >= 1 && len(value.DisplayName) <= 128 && validReferenceOnlyJSON(value.Configuration) && (value.CredentialReference == "" || strings.HasPrefix(value.CredentialReference, "ref:"))
}
func validDiscoveryIntegration(value DiscoveryIntegration) bool {
	return validProductID(value.ID) && len(value.Kind) >= 1 && len(value.Kind) <= 64 && len(value.ConnectorVersion) >= 1 && len(value.DisplayName) >= 1 && stringIn(value.State, "pending", "authorizing", "active", "degraded", "disabled", "deleted") && value.Version > 0 && !value.CreatedAt.IsZero() && !value.UpdatedAt.Before(value.CreatedAt)
}
func validSyncRequest(value SyncRequest) bool {
	return validProductID(value.IntegrationID) && validProductID(value.SyncID) && validProductID(value.JobID) && validProductID(value.OutboxID) && len(value.IdempotencyKey) >= 16 && len(value.IdempotencyKey) <= 128 && len(value.RequestDigest) == 32 && stringIn(value.TriggerKind, "manual", "schedule", "retry") && len(value.ParserVersion) >= 1 && len(value.ParserVersion) <= 64 && len(value.ToolVersion) >= 1 && len(value.ToolVersion) <= 64
}
func validCompleteSnapshot(value CompleteSnapshot) bool {
	return validProductID(value.IntegrationID) && validProductID(value.SyncID) && validProductID(value.SnapshotID) && value.Generation > 0 && len(value.Source) >= 1 && len(value.Source) <= 64 && strings.HasPrefix(value.ManifestReference, "s3://") && len(value.ManifestChecksum) == 32 && value.CollectedAt.Location() == time.UTC && len(value.CursorProvider) >= 1 && len(value.CursorProvider) <= 64 && len(value.CursorValue) >= 1 && len(value.CursorValue) <= 4096 && validJSONArray(value.Entities, 16<<20) && validJSONArray(value.Relationships, 16<<20) && validJSONArray(value.Evidence, 16<<20)
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
