package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresExecutionPublicSyncDetailSQL     = `SELECT zasp_execution_sync_detail($1,$2,$3,$4,$5)`
	postgresExecutionPublicSyncHistorySQL    = `SELECT zasp_execution_sync_history($1,$2,$3,$4,$5,$6,$7)`
	postgresExecutionPublicScheduleDetailSQL = `SELECT zasp_execution_schedule_detail($1,$2,$3,$4)`
	postgresExecutionPublicFreshnessSQL      = `SELECT zasp_execution_last_good_freshness($1,$2,$3,$4)`
	postgresExecutionPublicRequestSyncSQL    = `SELECT zasp_execution_public_request_sync($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	postgresExecutionPublicPutScheduleSQL    = `SELECT zasp_execution_public_put_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	postgresExecutionPublicDeleteScheduleSQL = `SELECT zasp_execution_public_delete_schedule($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
)

var publicIntegrationSyncFields = []string{"id", "integration_id", "trigger_kind", "status", "attempt", "requested_at", "started_at", "completed_at", "discovered_count", "changed_count", "removed_count", "snapshot_id", "last_error_code", "retry_at"}
var publicIntegrationScheduleFields = []string{"integration_id", "cadence_seconds", "state", "time_zone", "next_run_at", "version", "created_at", "updated_at"}

type IntegrationSync struct {
	ID              string     `json:"id"`
	IntegrationID   string     `json:"integration_id"`
	TriggerKind     string     `json:"trigger_kind"`
	Status          string     `json:"status"`
	Attempt         int        `json:"attempt"`
	RequestedAt     time.Time  `json:"requested_at"`
	StartedAt       *time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	DiscoveredCount int        `json:"discovered_count"`
	ChangedCount    int        `json:"changed_count"`
	RemovedCount    int        `json:"removed_count"`
	SnapshotID      *string    `json:"snapshot_id"`
	LastErrorCode   *string    `json:"last_error_code"`
	RetryAt         *time.Time `json:"retry_at"`
}

type IntegrationSyncRecord struct {
	Value   IntegrationSync
	Version int64
}

type integrationSyncRecordEnvelope struct {
	Body    IntegrationSync `json:"body"`
	Version int64           `json:"version"`
}

type PublicSyncRequest struct {
	IntegrationID, IdempotencyKey, SyncID, JobID, OutboxID string
	ExpectedVersion                                        int64
	RequestDigest                                          []byte
	ParserVersion, ToolVersion                             string
	AuditID, CorrelationID, ReceiptID                      string
}

type PublicSchedulePut struct {
	IntegrationID, IdempotencyKey     string
	ExpectedVersion                   int64
	CadenceSeconds                    int
	State                             string
	AuditID, CorrelationID, ReceiptID string
}

type PublicScheduleDelete struct {
	IntegrationID, IdempotencyKey     string
	ExpectedVersion                   int64
	AuditID, CorrelationID, ReceiptID string
}

type IntegrationSyncMutationResult struct {
	IntegrationSyncRecord
	AuditID, CorrelationID, ReceiptID string
	Replayed                          bool
}

type IntegrationScheduleMutationResult struct {
	Value                             IntegrationSchedule
	Version                           int64
	AuditID, CorrelationID, ReceiptID string
	Replayed                          bool
}

type integrationSyncMutationEnvelope struct {
	Body          json.RawMessage `json:"body"`
	Version       int64           `json:"version"`
	AuditID       string          `json:"audit_id"`
	CorrelationID string          `json:"correlation_id"`
	ReceiptID     string          `json:"receipt_id"`
	Replayed      bool            `json:"replayed"`
}

type integrationScheduleMutationEnvelope struct {
	Body          json.RawMessage `json:"body"`
	Version       int64           `json:"version"`
	AuditID       string          `json:"audit_id"`
	CorrelationID string          `json:"correlation_id"`
	ReceiptID     string          `json:"receipt_id"`
	Replayed      bool            `json:"replayed"`
}

type IntegrationSyncPage struct {
	Items           []IntegrationSync
	NextRequestedAt *time.Time
	NextID          string
}

type integrationSyncPageEnvelope struct {
	Items           []IntegrationSync `json:"items"`
	NextRequestedAt *time.Time        `json:"next_requested_at"`
	NextID          *string           `json:"next_id"`
}

type IntegrationSchedule struct {
	IntegrationID  string     `json:"integration_id"`
	CadenceSeconds int        `json:"cadence_seconds"`
	State          string     `json:"state"`
	TimeZone       string     `json:"time_zone"`
	NextRunAt      *time.Time `json:"next_run_at"`
	Version        int64      `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type IntegrationLastGoodSnapshot struct {
	SnapshotID      string    `json:"snapshot_id"`
	CollectedAt     time.Time `json:"collected_at"`
	DiscoveredCount int       `json:"discovered_count"`
	ChangedCount    int       `json:"changed_count"`
	RemovedCount    int       `json:"removed_count"`
}

type IntegrationProjectionStatus struct {
	State         string     `json:"state"`
	SnapshotID    *string    `json:"snapshot_id"`
	CompletedAt   *time.Time `json:"completed_at"`
	LastErrorCode *string    `json:"last_error_code"`
}

type IntegrationProjectionStatuses struct {
	Risk   IntegrationProjectionStatus `json:"risk"`
	Graph  IntegrationProjectionStatus `json:"graph"`
	Search IntegrationProjectionStatus `json:"search"`
}

type IntegrationFreshness struct {
	IntegrationID string                        `json:"integration_id"`
	Version       int64                         `json:"version"`
	LastGood      *IntegrationLastGoodSnapshot  `json:"last_good"`
	LatestSync    *IntegrationSync              `json:"latest_sync"`
	Projections   IntegrationProjectionStatuses `json:"projections"`
	UpdatedAt     time.Time                     `json:"updated_at"`
}

func (repository *DiscoveryRepository) RequestIntegrationSync(ctx context.Context, identity RequestIdentity, input PublicSyncRequest) (IntegrationSyncMutationResult, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validPublicSyncRequest(input) {
		return IntegrationSyncMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicRequestSyncSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.IntegrationID, input.IdempotencyKey, input.ExpectedVersion, input.SyncID, input.JobID, input.OutboxID, input.RequestDigest, input.ParserVersion, input.ToolVersion,
		input.AuditID, input.CorrelationID, input.ReceiptID,
	)
	if err != nil {
		return IntegrationSyncMutationResult{}, discoveryProviderError(err)
	}
	var envelope integrationSyncMutationEnvelope
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed", "version") || decodeStrictDiscovery(payload, &envelope) != nil || !exactJSONFields(envelope.Body, publicIntegrationSyncFields...) {
		return IntegrationSyncMutationResult{}, ErrRepositoryUnavailable
	}
	var body IntegrationSync
	if decodeStrictDiscovery(envelope.Body, &body) != nil || envelope.Version < 1 || !validPublicIntegrationSync(body, input.IntegrationID, body.ID) || !envelope.Replayed && body.ID != input.SyncID || !validPublicMutationIdentity(identity, envelope.AuditID, envelope.CorrelationID, envelope.ReceiptID) || !envelope.Replayed && (envelope.AuditID != input.AuditID || envelope.CorrelationID != input.CorrelationID || envelope.ReceiptID != input.ReceiptID) {
		return IntegrationSyncMutationResult{}, ErrRepositoryUnavailable
	}
	canonicalizePublicIntegrationSync(&body)
	return IntegrationSyncMutationResult{IntegrationSyncRecord: IntegrationSyncRecord{Value: body, Version: envelope.Version}, AuditID: envelope.AuditID, CorrelationID: envelope.CorrelationID, ReceiptID: envelope.ReceiptID, Replayed: envelope.Replayed}, nil
}

func (repository *DiscoveryRepository) PutIntegrationSchedule(ctx context.Context, identity RequestIdentity, input PublicSchedulePut) (IntegrationScheduleMutationResult, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validPublicSchedulePut(input) {
		return IntegrationScheduleMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicPutScheduleSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.IntegrationID, input.IdempotencyKey, input.ExpectedVersion, input.CadenceSeconds, input.State, input.AuditID, input.CorrelationID, input.ReceiptID,
	)
	return decodeIntegrationScheduleMutation(identity, input.IntegrationID, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID, payload, err)
}

func (repository *DiscoveryRepository) DeleteIntegrationSchedule(ctx context.Context, identity RequestIdentity, input PublicScheduleDelete) (IntegrationScheduleMutationResult, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || !validRequestIdentity(identity, false) || !validPublicScheduleDelete(input) {
		return IntegrationScheduleMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicDeleteScheduleSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.IntegrationID, input.IdempotencyKey, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID,
	)
	return decodeIntegrationScheduleMutation(identity, input.IntegrationID, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID, payload, err)
}

func decodeIntegrationScheduleMutation(identity RequestIdentity, integrationID string, expectedVersion int64, auditID, correlationID, receiptID string, payload json.RawMessage, err error) (IntegrationScheduleMutationResult, error) {
	if err != nil {
		return IntegrationScheduleMutationResult{}, discoveryProviderError(err)
	}
	var envelope integrationScheduleMutationEnvelope
	if !exactJSONFields(payload, "audit_id", "body", "correlation_id", "receipt_id", "replayed", "version") || decodeStrictDiscovery(payload, &envelope) != nil || !exactJSONFields(envelope.Body, publicIntegrationScheduleFields...) {
		return IntegrationScheduleMutationResult{}, ErrRepositoryUnavailable
	}
	var body IntegrationSchedule
	if decodeStrictDiscovery(envelope.Body, &body) != nil || !validPublicIntegrationSchedule(body, integrationID) || envelope.Version != body.Version || !envelope.Replayed && envelope.Version != expectedVersion+1 || !validPublicMutationIdentity(identity, envelope.AuditID, envelope.CorrelationID, envelope.ReceiptID) || !envelope.Replayed && (envelope.AuditID != auditID || envelope.CorrelationID != correlationID || envelope.ReceiptID != receiptID) {
		return IntegrationScheduleMutationResult{}, ErrRepositoryUnavailable
	}
	canonicalizePublicIntegrationSchedule(&body)
	return IntegrationScheduleMutationResult{Value: body, Version: envelope.Version, AuditID: envelope.AuditID, CorrelationID: envelope.CorrelationID, ReceiptID: envelope.ReceiptID, Replayed: envelope.Replayed}, nil
}

func (repository *DiscoveryRepository) GetIntegrationSync(ctx context.Context, scope domain.Scope, integrationID, syncID string) (IntegrationSyncRecord, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) || !validProductID(syncID) {
		return IntegrationSyncRecord{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicSyncDetailSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID, syncID)
	if err != nil {
		return IntegrationSyncRecord{}, discoveryProviderError(err)
	}
	var result integrationSyncRecordEnvelope
	if !exactJSONFields(payload, "body", "version") || decodeStrictDiscovery(payload, &result) != nil || !exactJSONFields(extractJSONField(payload, "body"), publicIntegrationSyncFields...) || result.Version < 1 || !validPublicIntegrationSync(result.Body, integrationID, syncID) {
		return IntegrationSyncRecord{}, ErrRepositoryUnavailable
	}
	canonicalizePublicIntegrationSync(&result.Body)
	return IntegrationSyncRecord{Value: result.Body, Version: result.Version}, nil
}

func (repository *DiscoveryRepository) ListIntegrationSyncs(ctx context.Context, scope domain.Scope, integrationID string, beforeRequestedAt *time.Time, beforeID string, limit int) (IntegrationSyncPage, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) || limit < 1 || limit > 100 || beforeRequestedAt == nil != (beforeID == "") || beforeRequestedAt != nil && (beforeRequestedAt.IsZero() || beforeRequestedAt.Location() != time.UTC) || beforeID != "" && !validProductID(beforeID) {
		return IntegrationSyncPage{}, ErrRepositoryOperation
	}
	var beforeIDValue any
	if beforeID != "" {
		beforeIDValue = beforeID
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicSyncHistorySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID, beforeRequestedAt, beforeIDValue, limit)
	if err != nil {
		return IntegrationSyncPage{}, discoveryProviderError(err)
	}
	var envelope integrationSyncPageEnvelope
	if !exactJSONFields(payload, "items", "next_id", "next_requested_at") || decodeStrictDiscovery(payload, &envelope) != nil || len(envelope.Items) > limit || envelope.NextRequestedAt == nil != (envelope.NextID == nil) {
		return IntegrationSyncPage{}, ErrRepositoryUnavailable
	}
	seen := make(map[string]struct{}, len(envelope.Items))
	for index := range envelope.Items {
		item := &envelope.Items[index]
		if !exactJSONArrayObjectFields(extractJSONField(payload, "items"), index, publicIntegrationSyncFields...) || !validPublicIntegrationSync(*item, integrationID, item.ID) {
			return IntegrationSyncPage{}, ErrRepositoryUnavailable
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return IntegrationSyncPage{}, ErrRepositoryUnavailable
		}
		seen[item.ID] = struct{}{}
		canonicalizePublicIntegrationSync(item)
		if beforeRequestedAt != nil && !syncHistoryTupleBefore(item.RequestedAt, item.ID, *beforeRequestedAt, beforeID) {
			return IntegrationSyncPage{}, ErrRepositoryUnavailable
		}
		if index > 0 {
			previous := envelope.Items[index-1]
			if !syncHistoryTupleBefore(item.RequestedAt, item.ID, previous.RequestedAt, previous.ID) {
				return IntegrationSyncPage{}, ErrRepositoryUnavailable
			}
		}
	}
	nextID := ""
	if envelope.NextID != nil {
		if !validProductID(*envelope.NextID) || envelope.NextRequestedAt == nil || envelope.NextRequestedAt.IsZero() || envelope.NextRequestedAt.Location() != time.UTC || len(envelope.Items) != limit || len(envelope.Items) == 0 {
			return IntegrationSyncPage{}, ErrRepositoryUnavailable
		}
		nextID = *envelope.NextID
		next := envelope.NextRequestedAt.UTC()
		envelope.NextRequestedAt = &next
		last := envelope.Items[len(envelope.Items)-1]
		if nextID != last.ID || !next.Equal(last.RequestedAt) {
			return IntegrationSyncPage{}, ErrRepositoryUnavailable
		}
	}
	return IntegrationSyncPage{Items: envelope.Items, NextRequestedAt: envelope.NextRequestedAt, NextID: nextID}, nil
}

func syncHistoryTupleBefore(requestedAt time.Time, id string, beforeRequestedAt time.Time, beforeID string) bool {
	return requestedAt.Before(beforeRequestedAt) || requestedAt.Equal(beforeRequestedAt) && id < beforeID
}

func (repository *DiscoveryRepository) GetIntegrationSchedule(ctx context.Context, scope domain.Scope, integrationID string) (IntegrationSchedule, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) {
		return IntegrationSchedule{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicScheduleDetailSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID)
	if err != nil {
		return IntegrationSchedule{}, discoveryProviderError(err)
	}
	var result IntegrationSchedule
	if !exactJSONFields(payload, publicIntegrationScheduleFields...) || decodeStrictDiscovery(payload, &result) != nil || !validPublicIntegrationSchedule(result, integrationID) {
		return IntegrationSchedule{}, ErrRepositoryUnavailable
	}
	canonicalizePublicIntegrationSchedule(&result)
	return result, nil
}

func (repository *DiscoveryRepository) GetIntegrationFreshness(ctx context.Context, scope domain.Scope, integrationID string) (IntegrationFreshness, error) {
	if !validDiscoveryPublicRepository(repository, ctx) || scope.Validate() != nil || !validProductID(integrationID) {
		return IntegrationFreshness{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresExecutionPublicFreshnessSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID)
	if err != nil {
		return IntegrationFreshness{}, discoveryProviderError(err)
	}
	var result IntegrationFreshness
	if !validExactFreshnessPayload(payload) || decodeStrictDiscovery(payload, &result) != nil || !validPublicIntegrationFreshness(result, integrationID) {
		return IntegrationFreshness{}, ErrRepositoryUnavailable
	}
	result.UpdatedAt = result.UpdatedAt.UTC()
	if result.LastGood != nil {
		result.LastGood.CollectedAt = result.LastGood.CollectedAt.UTC()
	}
	if result.LatestSync != nil {
		canonicalizePublicIntegrationSync(result.LatestSync)
	}
	canonicalizeProjectionStatus(&result.Projections.Risk)
	canonicalizeProjectionStatus(&result.Projections.Graph)
	canonicalizeProjectionStatus(&result.Projections.Search)
	return result, nil
}

func validDiscoveryPublicRepository(repository *DiscoveryRepository, ctx context.Context) bool {
	return repository != nil && isDiscoveryExecutionSchema(repository.schema) && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validPublicSyncRequest(value PublicSyncRequest) bool {
	return validProductID(value.IntegrationID) && validProductID(value.SyncID) && validProductID(value.JobID) && validProductID(value.OutboxID) && validPublicIdempotency(value.IdempotencyKey) && value.ExpectedVersion > 0 && value.ExpectedVersion <= 1000000 && len(value.RequestDigest) == sha256.Size && executionVersionPattern.MatchString(value.ParserVersion) && executionVersionPattern.MatchString(value.ToolVersion) && validProductID(value.AuditID) && validProductID(value.CorrelationID) && (value.ReceiptID == "" || validProductID(value.ReceiptID))
}

func validPublicSchedulePut(value PublicSchedulePut) bool {
	return validProductID(value.IntegrationID) && validPublicIdempotency(value.IdempotencyKey) && value.ExpectedVersion >= 0 && value.ExpectedVersion <= 1000000 && value.CadenceSeconds >= 300 && value.CadenceSeconds <= 2678400 && stringIn(value.State, "enabled", "disabled") && validProductID(value.AuditID) && validProductID(value.CorrelationID) && (value.ReceiptID == "" || validProductID(value.ReceiptID))
}

func validPublicScheduleDelete(value PublicScheduleDelete) bool {
	return validProductID(value.IntegrationID) && validPublicIdempotency(value.IdempotencyKey) && value.ExpectedVersion > 0 && value.ExpectedVersion <= 1000000 && validProductID(value.AuditID) && validProductID(value.CorrelationID) && (value.ReceiptID == "" || validProductID(value.ReceiptID))
}

func validPublicIdempotency(value string) bool {
	return len(value) >= 16 && len(value) <= 128 && workflowKeyPattern.MatchString(value)
}

func validPublicMutationIdentity(identity RequestIdentity, auditID, correlationID, receiptID string) bool {
	return validRequestIdentity(identity, false) && validProductID(auditID) && validProductID(correlationID) && validMutationReceiptIdentity(identity, receiptID)
}

func validPublicIntegrationSync(value IntegrationSync, expectedIntegrationID, expectedSyncID string) bool {
	if !validProductID(value.ID) || value.ID != expectedSyncID || value.IntegrationID != expectedIntegrationID || !stringIn(value.TriggerKind, "manual", "schedule", "retry") || !stringIn(value.Status, "queued", "running", "succeeded", "failed", "cancelled") || value.Attempt < 0 || value.Attempt > 100 || !validPublicTime(value.RequestedAt) || !validOptionalPublicTime(value.StartedAt) || !validOptionalPublicTime(value.CompletedAt) || !validOptionalPublicTime(value.RetryAt) || value.DiscoveredCount < 0 || value.ChangedCount < 0 || value.RemovedCount < 0 {
		return false
	}
	if value.SnapshotID != nil && !validProductID(*value.SnapshotID) || value.LastErrorCode != nil && !stringIn(*value.LastErrorCode, "retryable", "rate_limited", "denied", "revoked", "malformed", "partial", "terminal", "cancelled", "outcome_unknown") {
		return false
	}
	if value.StartedAt != nil && value.StartedAt.Before(value.RequestedAt) || value.CompletedAt != nil && value.StartedAt != nil && value.CompletedAt.Before(*value.StartedAt) || value.RetryAt != nil && value.RetryAt.Before(value.RequestedAt) {
		return false
	}
	switch value.Status {
	case "queued":
		if value.CompletedAt != nil || value.SnapshotID != nil {
			return false
		}
		if value.Attempt == 0 {
			return value.StartedAt == nil && value.LastErrorCode == nil && value.RetryAt == nil
		}
		return value.StartedAt != nil && value.LastErrorCode != nil && value.RetryAt != nil
	case "running":
		return value.Attempt > 0 && value.StartedAt != nil && value.CompletedAt == nil && value.SnapshotID == nil && value.LastErrorCode == nil && value.RetryAt == nil
	case "succeeded":
		return value.Attempt > 0 && value.StartedAt != nil && value.CompletedAt != nil && value.SnapshotID != nil && value.LastErrorCode == nil && value.RetryAt == nil
	case "failed", "cancelled":
		return value.Attempt > 0 && value.CompletedAt != nil && value.LastErrorCode != nil
	default:
		return false
	}
}

func validPublicIntegrationSchedule(value IntegrationSchedule, integrationID string) bool {
	return value.IntegrationID == integrationID && value.CadenceSeconds >= 300 && value.CadenceSeconds <= 2678400 && stringIn(value.State, "enabled", "disabled", "deleted") && value.TimeZone == "UTC" && value.Version > 0 && validPublicTime(value.CreatedAt) && validPublicTime(value.UpdatedAt) && !value.UpdatedAt.Before(value.CreatedAt) && validOptionalPublicTime(value.NextRunAt) && (value.State == "enabled") == (value.NextRunAt != nil)
}

func validPublicIntegrationFreshness(value IntegrationFreshness, integrationID string) bool {
	if value.IntegrationID != integrationID || value.Version < 1 || !validPublicTime(value.UpdatedAt) || value.LastGood != nil && (!validProductID(value.LastGood.SnapshotID) || !validPublicTime(value.LastGood.CollectedAt) || value.LastGood.DiscoveredCount < 0 || value.LastGood.ChangedCount < 0 || value.LastGood.RemovedCount < 0) || value.LatestSync != nil && !validPublicIntegrationSync(*value.LatestSync, integrationID, value.LatestSync.ID) {
		return false
	}
	return validProjectionStatus(value.Projections.Risk) && validProjectionStatus(value.Projections.Graph) && validProjectionStatus(value.Projections.Search)
}

func validProjectionStatus(value IntegrationProjectionStatus) bool {
	if !stringIn(value.State, "current", "pending", "degraded", "unavailable") || value.SnapshotID != nil && !validProductID(*value.SnapshotID) || !validOptionalPublicTime(value.CompletedAt) || value.LastErrorCode != nil && !stringIn(*value.LastErrorCode, "retryable", "rate_limited", "denied", "revoked", "malformed", "partial", "terminal", "cancelled", "outcome_unknown") {
		return false
	}
	switch value.State {
	case "current":
		return value.SnapshotID != nil && value.CompletedAt != nil && value.LastErrorCode == nil
	case "pending":
		return value.SnapshotID != nil && value.CompletedAt == nil && (value.LastErrorCode == nil || *value.LastErrorCode == "retryable")
	case "degraded":
		if value.SnapshotID == nil || value.LastErrorCode == nil {
			return false
		}
		return *value.LastErrorCode == "outcome_unknown" && value.CompletedAt == nil || stringIn(*value.LastErrorCode, "terminal", "cancelled") && value.CompletedAt != nil
	case "unavailable":
		return value.SnapshotID == nil && value.CompletedAt == nil && value.LastErrorCode == nil
	default:
		return false
	}
}

func validPublicTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func validOptionalPublicTime(value *time.Time) bool {
	return value == nil || validPublicTime(*value)
}

func canonicalizePublicIntegrationSync(value *IntegrationSync) {
	value.RequestedAt = value.RequestedAt.UTC()
	canonicalizeTimePointer(&value.StartedAt)
	canonicalizeTimePointer(&value.CompletedAt)
	canonicalizeTimePointer(&value.RetryAt)
}

func canonicalizePublicIntegrationSchedule(value *IntegrationSchedule) {
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	canonicalizeTimePointer(&value.NextRunAt)
}

func canonicalizeProjectionStatus(value *IntegrationProjectionStatus) {
	canonicalizeTimePointer(&value.CompletedAt)
}

func canonicalizeTimePointer(value **time.Time) {
	if *value != nil {
		instant := (*value).UTC()
		*value = &instant
	}
}

func exactJSONFields(payload json.RawMessage, expected ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || len(object) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	wanted := append([]string(nil), expected...)
	sort.Strings(wanted)
	for index := range wanted {
		if actual[index] != wanted[index] {
			return false
		}
	}
	return true
}

func extractJSONField(payload json.RawMessage, field string) json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil {
		return nil
	}
	return object[field]
}

func exactJSONArrayObjectFields(payload json.RawMessage, index int, expected ...string) bool {
	var items []json.RawMessage
	return json.Unmarshal(payload, &items) == nil && index >= 0 && index < len(items) && exactJSONFields(items[index], expected...)
}

func validExactFreshnessPayload(payload json.RawMessage) bool {
	if !exactJSONFields(payload, "integration_id", "last_good", "latest_sync", "projections", "updated_at", "version") {
		return false
	}
	lastGood := extractJSONField(payload, "last_good")
	if string(lastGood) != "null" && !exactJSONFields(lastGood, "changed_count", "collected_at", "discovered_count", "removed_count", "snapshot_id") {
		return false
	}
	latest := extractJSONField(payload, "latest_sync")
	if string(latest) != "null" && !exactJSONFields(latest, publicIntegrationSyncFields...) {
		return false
	}
	projections := extractJSONField(payload, "projections")
	if !exactJSONFields(projections, "graph", "risk", "search") {
		return false
	}
	for _, kind := range []string{"risk", "graph", "search"} {
		if !exactJSONFields(extractJSONField(projections, kind), "completed_at", "last_error_code", "snapshot_id", "state") {
			return false
		}
	}
	return true
}
