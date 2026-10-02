package runtimeevent

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These constructors fix the database contract, independently of the admitted
// payload/receipt versions. Historical constructors never choose this profile.
func NewPostgresCurrentRuntimePipelineRepository(database ProductionIngestDatabase, authority ProductionPipelineAuthority) (*PostgresProductionPipelineRepository, error) {
	if nilProductionDatabase(database) {
		return nil, ErrProductionPipeline
	}
	return NewPostgresPrecisePipelineRepository(&currentRuntimeDatabase{database: database, authority: string(authority)}, authority)
}

func NewPostgresCurrentRuntimeIngestRepository(database ProductionIngestDatabase) (*PostgresProductionIngestRepository, error) {
	if nilProductionDatabase(database) {
		return nil, ErrProductionIngest
	}
	return NewPostgresPreciseProductionIngestRepository(&currentRuntimeDatabase{database: database, authority: "zasp_runtime_ingest"})
}

// A closed query adapter lets the already-tested codec/version branches retain
// their validation without making a broad public-to-private SQL rewrite. Every
// allowed query has one literal destination; unknown queries fail closed.
type currentRuntimeDatabase struct {
	database  ProductionIngestDatabase
	authority string
}

// This preflight binds the application pin and registered ingest login. It is
// only used immediately before a native operation with full entry/exit gates;
// public health checks continue to call Ready/ReadyPrecision.
func (repository *PostgresProductionIngestRepository) intakePreflight(ctx context.Context) error {
	if !validProductionRepository(repository, ctx) {
		return ErrProductionIngestUnavailable
	}
	database, current := repository.database.(*currentRuntimeDatabase)
	if !current {
		return repository.Ready(ctx)
	}
	if database.authority != "zasp_runtime_ingest" || nilProductionDatabase(database.database) {
		return ErrProductionIngestUnavailable
	}
	payload, err := safeProductionQuery(database.database, ctx, `SELECT jsonb_build_object('matched',zasp_authorization80_runtime.ingest_profile_identity($1))`, migrations.AuthorizationRuntimeProfileChecksum())
	var result struct {
		Matched bool `json:"matched"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &result, "matched") || !result.Matched {
		return ErrProductionIngestUnavailable
	}
	return nil
}

// Historical optional budget/API readiness is not exported by this adapter.
// Its fixed current gate verifies full ancestry under the runtime login itself.
func (d *currentRuntimeDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d == nil || nilProductionDatabase(d.database) || ctx == nil || ctx.Err() != nil {
		return nil, ErrProductionPipelineUnavailable
	}
	switch q {
	case productionPrecisionReadySQL, productionSandboxRoutingReadySQL, productionCandidateReadySQL, productionCandidateReadyV48SQL,
		`SELECT jsonb_build_object('ready',zasp_production_runtime_sessions_readiness($1,$2) AND zasp_runtime_principal_ready($3))`,
		`SELECT jsonb_build_object('ready',zasp_production_runtime_precision_readiness($1,$2) AND zasp_discovery_principal_ready('zasp_runtime_ingest'))`:
		return d.database.QueryJSON(ctx, `SELECT jsonb_build_object('ready',zasp_authorization80_runtime.ready($1,$2))`, migrations.AuthorizationRuntimeProfileChecksum(), d.authority)
	}
	target, ok := currentRuntimeQueries[q]
	if !ok {
		return nil, ErrProductionPipelineUnavailable
	}
	return d.database.QueryJSON(ctx, target, args...)
}

var currentRuntimeQueries = map[string]string{
	productionIngestAuthenticateSQL:                            `SELECT zasp_authorization80_runtime.runtime_authenticate_sensor($1,$2,'event-ingest')`,
	productionIngestReserveSQL:                                 `SELECT zasp_authorization80_runtime.runtime_reserve_batch_v17($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,$10)`,
	productionIngestFinalizeSQL:                                `SELECT zasp_authorization80_runtime.runtime_finalize_batch_v17($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
	productionIngestHeartbeatSQL:                               `SELECT zasp_authorization80_runtime.runtime_sensor_heartbeat($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9)`,
	productionLookupAcceptanceSQL:                              `SELECT zasp_authorization80_runtime.runtime_lookup_acceptance($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
	`SELECT zasp_runtime_claim_reconciliation_v2($1,$2,$3,$4)`: `SELECT zasp_authorization80_runtime.runtime_claim_reconciliation_v2($1,$2,$3,$4)`,
	productionIngestReleaseReconciliationSQL:                   `SELECT zasp_authorization80_runtime.runtime_release_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
	productionIngestFinishReconciliationSQL:                    `SELECT zasp_authorization80_runtime.runtime_finish_reconciliation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
	productionIngestQuarantineReconciliationSQL:                `SELECT zasp_authorization80_runtime.runtime_quarantine_reconciliation($1,$2,$3,$4,$5,$6,$7)`,
	productionPipelineClaimDeliverySQL:                         `SELECT zasp_authorization80_runtime.runtime_claim_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
	productionPipelineHeartbeatDeliverySQL:                     `SELECT zasp_authorization80_runtime.runtime_heartbeat_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
	productionPipelineReleaseDeliverySQL:                       `SELECT zasp_authorization80_runtime.runtime_release_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
	productionPipelineAckDeliverySQL:                           `SELECT zasp_authorization80_runtime.runtime_ack_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
	`SELECT zasp_runtime_claim_archive_v2($1,$2,$3,$4)`:        `SELECT zasp_authorization80_runtime.runtime_claim_archive_v2($1,$2,$3,$4)`,
	`SELECT zasp_runtime_claim_index_v2($1,$2,$3,$4)`:          `SELECT zasp_authorization80_runtime.runtime_claim_index_v2($1,$2,$3,$4)`,
	`SELECT zasp_runtime_claim_correlation_v4($1,$2,$3,$4)`:    `SELECT zasp_authorization80_runtime.runtime_claim_correlation_v4($1,$2,$3,$4)`,
	`SELECT zasp_runtime_claim_projection_v3($1,$2,$3,$4)`:     `SELECT zasp_authorization80_runtime.runtime_claim_projection_v3($1,$2,$3,$4)`,
	`SELECT zasp_runtime_claim_completion_v3($1,$2,$3,$4)`:     `SELECT zasp_authorization80_runtime.runtime_claim_completion_v3($1,$2,$3,$4)`,
	productionPipelineHeartbeatStageSQL:                        `SELECT zasp_authorization80_runtime.runtime_heartbeat_stage($1,$2,$3,$4,$5,$6,$7,$8)`,
	productionPipelineFinishStageSQL:                           `SELECT zasp_authorization80_runtime.runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
	productionPipelineFinishSessionSQL:                         `SELECT zasp_authorization80_runtime.runtime_finish_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
	`SELECT zasp_runtime_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`: `SELECT zasp_authorization80_runtime.runtime_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
	productionPreciseFinishSessionSQL:   `SELECT zasp_authorization80_runtime.runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
	productionCandidateFreezeSQL:        `SELECT zasp_authorization80_runtime.runtime_freeze_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
	productionSandboxCandidateFreezeSQL: `SELECT zasp_authorization80_runtime.runtime_freeze_sandbox_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
	`SELECT zasp_runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`: `SELECT zasp_authorization80_runtime.runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
}
