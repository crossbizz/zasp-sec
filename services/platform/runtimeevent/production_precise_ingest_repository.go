package runtimeevent

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func NewPostgresPreciseProductionIngestRepository(database ProductionIngestDatabase) (*PostgresProductionIngestRepository, error) {
	repository, err := NewPostgresProductionIngestRepository(database)
	if err != nil {
		return nil, err
	}
	repository.precision = true
	return repository, nil
}

func (repository *PostgresProductionIngestRepository) ReadyPrecision(ctx context.Context) error {
	if !validProductionRepository(repository, ctx) || !repository.precision {
		return ErrProductionIngestUnavailable
	}
	metadata := migrations.ProductionRuntimePrecision()
	payload, err := safeProductionQuery(repository.database, ctx, `SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_discovery_principal_ready('zasp_runtime_ingest'))`, metadata.Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint())
	var ready struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &ready, "ready") || !ready.Ready {
		return ErrProductionIngestUnavailable
	}
	return nil
}

func (repository *PostgresProductionIngestRepository) acceptsReserveSchema(request IngestReserveRequest) bool {
	return validReserveRequest(request) && (request.SchemaVersion == productionRuntimeSchema || repository.precision)
}
