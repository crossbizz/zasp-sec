package authorization

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewCurrentMaintenanceWorkerExecutor admits the same complete projection
// selection as API/CLI factories while retaining the original native worker
// and approval-origin execution. It does not add a connector operation, issue
// connector tasks, authorize maintenance effects or modify compensation.
func NewCurrentMaintenanceWorkerExecutor(ctx context.Context, pool *pgxpool.Pool, checker Checker, store, model string, key *WorkerKey, approvalPin, connectorPin string) (*WorkerExecutor, error) {
	if _, err := NewCurrentMaintenanceProjectionRepository(ctx, pool, approvalPin, connectorPin); err != nil {
		return nil, err
	}
	if approvalPin != "" {
		return NewApprovalOriginWorkerExecutor(ctx, pool, checker, store, model, key, approvalPin)
	}
	return NewWorkerExecutor(pool, checker, store, model, key)
}
