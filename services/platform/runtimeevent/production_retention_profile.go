package runtimeevent

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// NewPostgresRetentionRuntimePipelineRepository explicitly selects the compiled
// successor. The original receipt codecs and all principal/lease arguments stay
// on their existing path; historical constructors never select this profile.
func NewPostgresRetentionRuntimePipelineRepository(database ProductionIngestDatabase, authority ProductionPipelineAuthority, pin string) (*PostgresProductionPipelineRepository, error) {
	if nilProductionDatabase(database) || !migrations.IsRetentionProfileChecksum(pin) || authority != ProductionPipelineAuthorityCoordinator && authority != ProductionPipelineAuthorityIndex {
		return nil, ErrProductionPipeline
	}
	return NewPostgresPrecisePipelineRepository(&retentionRuntimeDatabase{current: currentRuntimeDatabase{database: database, authority: string(authority)}, pin: pin, purpose: retentionRuntimePurpose(authority)}, authority)
}

func retentionRuntimePurpose(authority ProductionPipelineAuthority) string {
	if authority == ProductionPipelineAuthorityIndex {
		return "runtime-index"
	}
	return "runtime-coordinator"
}

type retentionRuntimeDatabase struct {
	current      currentRuntimeDatabase
	pin, purpose string
}

const retentionRuntimeReadySQL = `SELECT jsonb_build_object('ready',zasp_authorization80_runtime.ready($1,$2) AND zasp_retention_v1.caller_ready($3,$4))`

func (d *retentionRuntimeDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || nilProductionDatabase(d.current.database) || !migrations.IsRetentionProfileChecksum(d.pin) {
		return nil, ErrProductionPipelineUnavailable
	}
	readiness := false
	switch q {
	case productionPrecisionReadySQL, productionSandboxRoutingReadySQL, productionCandidateReadySQL, productionCandidateReadyV48SQL,
		`SELECT jsonb_build_object('ready',zasp_production_runtime_sessions_readiness($1,$2) AND zasp_runtime_principal_ready($3))`,
		`SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_discovery_principal_ready('zasp_runtime_ingest'))`:
		readiness = true
	default:
		if _, ok := currentRuntimeQueries[q]; !ok {
			return nil, ErrProductionPipelineUnavailable
		}
	}
	raw, err := safeProductionQuery(d.current.database, ctx, retentionRuntimeReadySQL, migrations.AuthorizationRuntimeProfileChecksum(), d.current.authority, d.purpose, d.pin)
	var ready struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(raw, 16<<10, &ready, "ready") || !ready.Ready {
		return nil, ErrProductionPipelineUnavailable
	}
	if readiness {
		return raw, nil
	}
	switch q {
	case productionPipelineFinishStageSQL:
		if d.current.authority == string(ProductionPipelineAuthorityIndex) {
			return d.current.database.QueryJSON(ctx, `SELECT zasp_retention_v1.current_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, args...)
		}
		return d.current.QueryJSON(ctx, q, args...)
	case productionPipelineFinishSessionSQL:
		return d.current.database.QueryJSON(ctx, `SELECT zasp_retention_v1.current_finish_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...)
	case `SELECT zasp_runtime_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`:
		return d.current.database.QueryJSON(ctx, `SELECT zasp_retention_v1.current_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...)
	case productionPreciseFinishSessionSQL:
		return d.current.database.QueryJSON(ctx, `SELECT zasp_retention_v1.current_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...)
	default:
		return d.current.QueryJSON(ctx, q, args...)
	}
}
