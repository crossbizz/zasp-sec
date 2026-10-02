package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func NewCurrentRuntimeOutboxRepository(database JSONDatabase) (*RuntimeOutboxRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	return NewPreciseRuntimeOutboxRepository(&currentRuntimeOutboxDatabase{JSONDatabase: database})
}

type currentRuntimeOutboxDatabase struct{ JSONDatabase }

func (d *currentRuntimeOutboxDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	switch q {
	case postgresPreciseRuntimeOutboxReadySQL:
		return d.JSONDatabase.QueryJSON(ctx, `SELECT to_jsonb(zasp_authorization80_runtime.ready($1,$2))`, migrations.AuthorizationRuntimeProfileChecksum(), DiscoveryDatabaseAuthorityOutbox)
	case `SELECT zasp_runtime_claim_outbox_v2($1,$2,$3,$4,$5)`:
		q = `SELECT zasp_authorization80_runtime.runtime_claim_outbox_v2($1,$2,$3,$4,$5)`
	case postgresRuntimeHeartbeatOutboxSQL:
		q = `SELECT zasp_authorization80_runtime.runtime_heartbeat_outbox($1,$2,$3,$4,$5)`
	case postgresRuntimeAckOutboxSQL:
		q = `SELECT zasp_authorization80_runtime.runtime_ack_outbox($1,$2,$3,$4,$5,$6,$7,$8)`
	case postgresRuntimeRetryOutboxSQL:
		q = `SELECT zasp_authorization80_runtime.runtime_retry_outbox($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	default:
		return nil, ErrRepositoryUnavailable
	}
	return d.JSONDatabase.QueryJSON(ctx, q, args...)
}
