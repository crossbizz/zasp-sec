package runtimeevent

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const productionPrecisionReadySQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
const productionPreciseFinishSessionSQL = `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`

func (repository *PostgresProductionPipelineRepository) requirePrecisionReady(ctx context.Context) error {
	metadata := migrations.ProductionRuntimePrecision()
	payload, err := safeProductionQuery(repository.database, ctx, productionPrecisionReadySQL, metadata.Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint(), string(repository.authority))
	var ready struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &ready, "ready") || !ready.Ready {
		return ErrProductionPipelineUnavailable
	}
	return nil
}
