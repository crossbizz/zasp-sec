package runtimeevent

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const productionCorrelationRoutingReadySQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_correlation_routing_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
const productionCorrelationClaimV2SQL = `SELECT zasp_runtime_claim_correlation_v2($1,$2,$3,$4)`
const productionSandboxRoutingReadySQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_sandbox_binding_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
const productionCorrelationClaimV3SQL = `SELECT zasp_runtime_claim_correlation_v3($1,$2,$3,$4)`

// NewPostgresCorrelationPipelineRepository declares immutable v1/v2 reader
// capability. The legacy constructor and non-correlation stages are unchanged.
func NewPostgresCorrelationPipelineRepository(database ProductionIngestDatabase) (*PostgresProductionPipelineRepository, error) {
	repository, err := NewPostgresProductionPipelineRepository(database, ProductionPipelineAuthorityCorrelation)
	if err != nil {
		return nil, err
	}
	repository.correlationV2 = true
	return repository, nil
}

// Sandbox-capable readers pre-stage on healthy49 and drain v1/v2/v3 on50.
// Historical constructors retain their original immutable capabilities.
func NewPostgresSandboxCorrelationPipelineRepository(database ProductionIngestDatabase) (*PostgresProductionPipelineRepository, error) {
	repository, err := NewPostgresCorrelationPipelineRepository(database)
	if err != nil {
		return nil, err
	}
	repository.correlationV3 = true
	return repository, nil
}

// Resolve on every claim, even when process readiness is cached. Only a missing
// routing function can try independently pinned healthy48 authority. On49 that
// predecessor wrapper itself depends on routing readiness, so missing49 authority
// cannot authorize the fallback. Never downgrade after a claim error.
func (repository *PostgresProductionPipelineRepository) correlationClaimStatement(ctx context.Context) (string, error) {
	if !validProductionPipelineRepository(repository, ctx) || !repository.correlationV2 || repository.authority != ProductionPipelineAuthorityCorrelation {
		return "", ErrProductionPipelineUnavailable
	}
	if repository.correlationV3 {
		return repository.sandboxClaimStatement(ctx)
	}
	metadata := migrations.ProductionRuntimeCorrelationRouting()
	payload, err := safeProductionQuery(repository.database, ctx, productionCorrelationRoutingReadySQL, metadata.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint(), string(repository.authority))
	statement := productionCorrelationClaimV2SQL
	var provider *pgconn.PgError
	if ctx.Err() == nil && errors.As(err, &provider) && provider.Code == "42883" {
		payload, err = safeProductionQuery(repository.database, ctx, productionCandidateReadyV48SQL, migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), migrations.ProductionRuntimeCandidateAuthority().Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(repository.authority))
		statement = productionPipelineClaimStageSQL
	}
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &result, "ready") || !result.Ready {
		return "", ErrProductionPipelineUnavailable
	}
	return statement, nil
}

func (repository *PostgresProductionPipelineRepository) sandboxClaimStatement(ctx context.Context) (string, error) {
	metadata := migrations.ProductionRuntimeSandboxBinding()
	payload, err := safeProductionQuery(repository.database, ctx, productionSandboxRoutingReadySQL, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint(), string(repository.authority))
	statement := productionCorrelationClaimV3SQL
	var provider *pgconn.PgError
	if ctx.Err() == nil && errors.As(err, &provider) && provider.Code == "42883" {
		prior := migrations.ProductionRuntimeCorrelationRouting()
		payload, err = safeProductionQuery(repository.database, ctx, productionCorrelationRoutingReadySQL, prior.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint(), string(repository.authority))
		statement = productionCorrelationClaimV2SQL
	}
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &result, "ready") || !result.Ready {
		return "", ErrProductionPipelineUnavailable
	}
	return statement, nil
}
