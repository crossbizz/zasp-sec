package runtimeevent

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const productionProjectionClaimV2SQL = `SELECT zasp_runtime_claim_projection_v2($1,$2,$3,$4)`
const productionCompletionClaimV2SQL = `SELECT zasp_runtime_claim_completion_v2($1,$2,$3,$4)`

// NewPostgresSandboxSessionPipelineRepository declares the upgraded session
// worker capability on schema50 without changing historical constructors.
// Pre-stage binaries with their v1 configuration before enabling this reader.
func NewPostgresSandboxSessionPipelineRepository(database ProductionIngestDatabase, authority ProductionPipelineAuthority) (*PostgresProductionPipelineRepository, error) {
	if authority != ProductionPipelineAuthorityProjection && authority != ProductionPipelineAuthorityCoordinator {
		return nil, ErrProductionPipeline
	}
	repository, err := NewPostgresProductionPipelineRepository(database, authority)
	if err != nil {
		return nil, err
	}
	repository.sessionV2 = true
	return repository, nil
}

func (repository *PostgresProductionPipelineRepository) sessionClaimStatement(ctx context.Context) (string, error) {
	if !validProductionPipelineRepository(repository, ctx) || !repository.sessionV2 || (repository.stage != RuntimeStageProject && repository.stage != RuntimeStageComplete) {
		return "", ErrProductionPipelineUnavailable
	}
	metadata := migrations.ProductionRuntimeSandboxBinding()
	payload, err := safeProductionQuery(repository.database, ctx, productionSandboxRoutingReadySQL, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint(), string(repository.authority))
	statement := productionProjectionClaimV2SQL
	if repository.stage == RuntimeStageComplete {
		statement = productionCompletionClaimV2SQL
	}
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &result, "ready") || !result.Ready {
		return "", ErrProductionPipelineUnavailable
	}
	return statement, nil
}
