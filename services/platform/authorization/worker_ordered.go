package authorization

import (
	"context"
	"encoding/json"
)

// The admitted finding/attack-path planner has exactly five native resources,
// each checked for its grantor and task. No other family uses this wrapper.
func checkOrderedPlanningRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if len(requests) != 10 {
		return Revision{}, ErrInvalid
	}
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}

// Preparation derives an immutable delegation from an actual admitted native
// start. It does not load a planner body or grant authority from caller targets.
func (e *WorkerExecutor) PrepareOrdered68(ctx context.Context, request json.RawMessage) error {
	if e == nil || e.key == nil || e.pool == nil || e.adapter || e.discovery || ctx == nil || e.key.purpose != WorkerForward || len(request) > 4096 || !json.Valid(request) {
		return ErrInvalid
	}
	_, err := e.pool.Exec(ctx, `SELECT zasp_authorization80_worker.prepare_ordered68($1::jsonb)`, request)
	return workerDatabaseError(err)
}

func orderedWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: WorkerForward, source: `SELECT zasp_authorization80_worker.planning68_source($1,$2::jsonb)`, statement: `SELECT zasp_temporal68.plan($1::jsonb)`, current: true, limit: 524288}
	switch operation {
	case "ordered68.planning.state", "ordered68.planning.load", "ordered68.planning.prepare", "ordered68.planning.start", "ordered68.planning.result", "ordered68.planning.settle", "ordered68.planning.artifacts", "ordered68.planning.admit":
	case "ordered68.planning.recovery", "ordered68.planning.reconcile", "ordered68.planning.late_usage":
		s.purpose, s.current, s.limit = CapturedCompensation, false, 131072
	default:
		return workerOperationSpec{}, false
	}
	s.phase = string(operation)[len("ordered68.planning."):]
	switch s.phase {
	case "state":
		s.statement, s.limit = `SELECT zasp_temporal68.status($1::jsonb)->'planning'`, 524288
	case "recovery":
		s.statement, s.limit = `SELECT zasp_authorization80_worker.planning68_recovery($1::jsonb)`, 4096
	}
	return s, true
}

// This is the retained finding/attack-path ordered planner shape only. Runtime
// ancestry has a separate implementation gate, never a smaller fallback set.
func orderedWorkerCheckShape(f workerFacts) bool {
	if f.TaskID != "" || f.TriggerKind != "finding" && f.TriggerKind != "attack_path" || f.TargetKind != "agent" && f.TargetKind != "tool" || len(f.Checks) != 5 {
		return false
	}
	want := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}, {"test", f.TestID, "view"}, {f.TargetKind, f.TargetID, "view"}, {f.TriggerKind, f.TriggerID, "view"}}
	for i, target := range f.Checks {
		if target.ID == "" || [3]string{target.Kind, target.ID, target.Permission} != want[i] {
			return false
		}
	}
	return true
}
