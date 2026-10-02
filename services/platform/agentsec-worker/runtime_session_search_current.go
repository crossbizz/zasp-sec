package main

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func newCurrentPostgresRuntimeSessionSearchAuthority(database recoveryJSONDatabase) (*postgresRuntimeSessionSearchAuthority, error) {
	if nilWorkerDependency(database) {
		return nil, errRuntimeUnavailable
	}
	return newPrecisePostgresRuntimeSessionSearchAuthority(&currentSearchDatabase{database: database})
}

type currentSearchDatabase struct{ database recoveryJSONDatabase }

func (d *currentSearchDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	switch q {
	case `SELECT to_jsonb(zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_runtime_index_worker'))`:
		return d.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_authorization80_runtime.ready($1,$2))`, migrations.AuthorizationRuntimeProfileChecksum(), "zasp_runtime_index_worker")
	case `SELECT COALESCE(zasp_runtime_precise_search_claim($1,$2,$3),'null'::jsonb)`:
		q = `SELECT COALESCE(zasp_authorization80_runtime.runtime_precise_search_claim($1,$2,$3),'null'::jsonb)`
	case `SELECT zasp_runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`:
		q = `SELECT zasp_authorization80_runtime.runtime_sandbox_search_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	case `SELECT zasp_runtime_sandbox_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`:
		q = `SELECT zasp_authorization80_runtime.runtime_sandbox_search_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	default:
		return nil, errRuntimeUnavailable
	}
	return d.database.QueryJSON(ctx, q, args...)
}
