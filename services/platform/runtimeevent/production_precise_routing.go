package runtimeevent

import "context"

func (repository *PostgresProductionPipelineRepository) ReadyPrecision(ctx context.Context) error {
	if !validProductionPipelineRepository(repository, ctx) || !repository.precision {
		return ErrProductionPipelineUnavailable
	}
	return repository.requirePrecisionReady(ctx)
}

// NewPostgresPrecisePipelineRepository fixes the worker's supported release at
// construction. Historical constructors never negotiate precision implicitly.
func NewPostgresPrecisePipelineRepository(database ProductionIngestDatabase, authority ProductionPipelineAuthority) (*PostgresProductionPipelineRepository, error) {
	repository, err := NewPostgresProductionPipelineRepository(database, authority)
	if err != nil {
		return nil, err
	}
	repository.precision = true
	return repository, nil
}

func preciseStageClaimSQL(stage RuntimeStage) string {
	switch stage {
	case RuntimeStageArchive:
		return `SELECT zasp_runtime_claim_archive_v2($1,$2,$3,$4)`
	case RuntimeStageIndex:
		return `SELECT zasp_runtime_claim_index_v2($1,$2,$3,$4)`
	case RuntimeStageCorrelate:
		return `SELECT zasp_runtime_claim_correlation_v4($1,$2,$3,$4)`
	case RuntimeStageProject:
		return `SELECT zasp_runtime_claim_projection_v3($1,$2,$3,$4)`
	case RuntimeStageComplete:
		return `SELECT zasp_runtime_claim_completion_v3($1,$2,$3,$4)`
	default:
		return ""
	}
}

func preciseStageVersionSupported(stage RuntimeStage, version string) bool {
	switch stage {
	case RuntimeStageArchive:
		return version == "runtime-archive-v1" || version == "runtime-archive-v2"
	case RuntimeStageIndex:
		return version == "runtime-index-v1" || version == "runtime-index-v2"
	case RuntimeStageCorrelate:
		return version == "runtime-correlation-v1" || version == "runtime-correlation-v2" || version == "runtime-correlation-v3" || version == "runtime-correlation-v4"
	case RuntimeStageProject:
		return version == "runtime-projection-v1" || version == "runtime-projection-v2" || version == "runtime-projection-v3"
	case RuntimeStageComplete:
		return version == "runtime-complete-v1" || version == "runtime-complete-v2" || version == "runtime-complete-v3"
	default:
		return false
	}
}
