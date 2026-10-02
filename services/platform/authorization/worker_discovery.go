package authorization

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Discovery uses the registered discovery worker, never a Temporal executor
// identity. Its FGA task is the native sync ID, not the orchestration job ID.
func NewWorkerDiscovery(pool *pgxpool.Pool, checker Checker, storeID, modelID string, key *WorkerKey) (*WorkerExecutor, error) {
	e, err := NewWorkerExecutor(pool, checker, storeID, modelID, key)
	if err != nil {
		return nil, err
	}
	e.discovery = true
	return e, nil
}

func (e *WorkerExecutor) PrepareDiscovery72(ctx context.Context, request json.RawMessage) error {
	if e == nil || !e.discovery || e.adapter || e.pool == nil || e.key == nil || e.key.purpose != WorkerForward || ctx == nil || len(request) > 4096 || !json.Valid(request) {
		return ErrInvalid
	}
	_, err := e.pool.Exec(ctx, `SELECT zasp_authorization80_worker.prepare_discovery72($1::jsonb)`, request)
	return workerDatabaseError(err)
}

func discoveryWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: WorkerForward, discovery: true, source: `SELECT zasp_authorization80_worker.discovery72_source($1,$2::jsonb)`, statement: `SELECT zasp_authorization80_worker.discovery72_execute($1::jsonb)`, limit: 4096, current: true}
	switch operation {
	case "discovery72.prepare_page", "discovery72.guard_page", "discovery72.prepare_apply", "discovery72.commit_apply":
	case "discovery72.record_page":
		s.purpose, s.current, s.limit = CapturedCompensation, false, (64<<20)+65536
	case "discovery72.settle", "discovery72.finish", "discovery72.replay_page", "discovery72.replay_apply":
		s.purpose, s.current = CapturedCompensation, false
	default:
		return workerOperationSpec{}, false
	}
	s.phase = string(operation)[len("discovery72."):]
	return s, true
}

func discoveryWorkerCheckShape(f workerFacts) bool {
	if f.TaskID == "" || f.TaskID == f.RunID || f.TargetKind != "integration" || f.TargetID == "" || f.DefinitionID != "" || f.TestID != "" || f.TriggerKind != "manual" && f.TriggerKind != "schedule" || len(f.Checks) != 2 {
		return false
	}
	return f.Checks[0].Kind == "integration" && f.Checks[0].ID == f.TargetID && f.Checks[0].Permission == "manage_workflows" && f.Checks[1].Kind == "integration" && f.Checks[1].ID == f.TargetID && f.Checks[1].Permission == "view"
}
