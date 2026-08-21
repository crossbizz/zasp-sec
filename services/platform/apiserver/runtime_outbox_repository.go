package apiserver

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const RuntimeOutboxTopic = "runtime-events"

const (
	postgresRuntimeDataPlaneOutboxReadySQL = `SELECT jsonb_build_object('ready',zasp_runtime_data_plane_readiness($1,$2) AND zasp_discovery_principal_ready($3))`
	postgresRuntimeGatewayOutboxReadySQL   = `SELECT jsonb_build_object('ready',zasp_runtime_gateway_reconciliation_readiness($1,$2) AND zasp_discovery_principal_ready($3))`
	postgresRuntimeOutboxReadySQL          = `SELECT jsonb_build_object('ready',zasp_runtime_ingest_reconciliation_readiness($1,$2) AND zasp_discovery_principal_ready($3))`
	postgresSecurityAgentOutboxReadySQL    = `SELECT jsonb_build_object('ready',zasp_security_agent_readiness($1,$2) AND zasp_discovery_principal_ready($3))`
	postgresRuntimeClaimOutboxSQL          = `SELECT zasp_runtime_claim_outbox($1,$2,$3,$4,$5)`
	postgresRuntimeHeartbeatOutboxSQL      = `SELECT zasp_runtime_heartbeat_outbox($1,$2,$3,$4,$5)`
	postgresRuntimeAckOutboxSQL            = `SELECT zasp_runtime_ack_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresRuntimeRetryOutboxSQL          = `SELECT zasp_runtime_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9)`
)

type RuntimeOutboxRepository struct {
	database    JSONDatabase
	readySQL    string
	checksum    string
	fingerprint string
}

func NewRuntimeOutboxRepository(database JSONDatabase) (*RuntimeOutboxRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	repository := &RuntimeOutboxRepository{database: database}
	switch version {
	case RuntimeDataPlaneSchemaVersion:
		repository.readySQL, repository.checksum, repository.fingerprint = postgresRuntimeDataPlaneOutboxReadySQL, migrations.ProductionRuntimeDataPlane().Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()
	case RuntimeGatewayReconciliationSchemaVersion:
		repository.readySQL, repository.checksum, repository.fingerprint = postgresRuntimeGatewayOutboxReadySQL, migrations.ProductionRuntimeGatewayReconciliation().Checksum(), migrations.ProductionRuntimeGatewayReconciliationSemanticFingerprint()
	case RuntimeIngestReconciliationSchemaVersion:
		repository.readySQL, repository.checksum, repository.fingerprint = postgresRuntimeOutboxReadySQL, migrations.ProductionRuntimeIngestReconciliation().Checksum(), migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint()
	case SecurityAgentExecutionSchemaVersion:
		repository.readySQL, repository.checksum, repository.fingerprint = postgresSecurityAgentOutboxReadySQL, migrations.ProductionSecurityAgentExecution().Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint()
	default:
		return nil, ErrRepositoryConfiguration
	}
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *RuntimeOutboxRepository) Ready(ctx context.Context) error {
	if !validRuntimeOutboxRepository(repository, ctx) {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, repository.readySQL, repository.checksum, repository.fingerprint, DiscoveryDatabaseAuthorityOutbox)
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || decodeStrictDiscovery(payload, &result) != nil || !result.Ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *RuntimeOutboxRepository) ClaimOutboxTopic(ctx context.Context, topic, worker, leaseToken string, leaseSeconds, limit int) ([]DiscoveryOutboxEvent, error) {
	if !validRuntimeOutboxRepository(repository, ctx) || topic != RuntimeOutboxTopic || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 10 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimeClaimOutboxSQL, topic, worker, leaseToken, leaseSeconds, limit)
	return decodeDiscoveryOutboxClaims(payload, err, topic, leaseSeconds, limit)
}

func (repository *RuntimeOutboxRepository) HeartbeatOutboxTopic(ctx context.Context, topic, worker, leaseToken string, leaseSeconds, expectedCount int) (OutboxLeaseHeartbeatResult, error) {
	if !validRuntimeOutboxRepository(repository, ctx) || topic != RuntimeOutboxTopic || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || leaseSeconds < 5 || leaseSeconds > 900 || expectedCount < 1 || expectedCount > 10 {
		return OutboxLeaseHeartbeatResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimeHeartbeatOutboxSQL, topic, worker, leaseToken, leaseSeconds, expectedCount)
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

func (repository *RuntimeOutboxRepository) AcknowledgeOutboxTopic(ctx context.Context, topic string, scope domain.Scope, id, worker, leaseToken, providerAck string) (OutboxLeaseTransitionResult, error) {
	if !validRuntimeOutboxRepository(repository, ctx) || topic != RuntimeOutboxTopic || scope.Validate() != nil || !validProductID(id) || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || !outboxProviderAckPattern.MatchString(providerAck) {
		return OutboxLeaseTransitionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimeAckOutboxSQL, topic, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, providerAck)
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

func (repository *RuntimeOutboxRepository) RetryOutboxTopic(ctx context.Context, topic string, scope domain.Scope, id, worker, leaseToken string, retrySeconds int, code string) (OutboxLeaseTransitionResult, error) {
	if !validRuntimeOutboxRepository(repository, ctx) || topic != RuntimeOutboxTopic || scope.Validate() != nil || !validProductID(id) || len(worker) < 1 || len(worker) > 128 || len(leaseToken) < 16 || len(leaseToken) > 128 || retrySeconds < 1 || retrySeconds > 3600 || code != "queue_publish_unknown" {
		return OutboxLeaseTransitionResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimeRetryOutboxSQL, topic, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id, worker, leaseToken, retrySeconds, code)
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

func validRuntimeOutboxRepository(repository *RuntimeOutboxRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && repository.readySQL != "" && len(repository.checksum) == 64 && len(repository.fingerprint) == 64 && ctx != nil && ctx.Err() == nil
}

var _ TopicOutboxRepository = (*RuntimeOutboxRepository)(nil)
