package authorization

import (
	"context"
	"encoding/json"
)

// ExecuteWithApprovalOrigin consumes an ORIGINAL opaque native planning
// decision. The supplementary wrapper authenticates it before the original
// plan runs in the same transaction and only captures its new enqueue.
// Ordinary Execute, legacy plans, compensation and other families are intact.
// An inactive/unregistered supplementary module refuses; this method does not
// create an API grant, issue a new worker proof or enable a runtime profile.
func (e *WorkerExecutor) ExecuteWithApprovalOrigin(ctx context.Context, d WorkerDecision) (json.RawMessage, error) {
	statement, ok := approvalOriginStatement(d.operation)
	spec, supported := workerOperation(d.operation)
	if e == nil || e.key == nil || e.pool == nil || ctx == nil || ctx.Err() != nil || !ok || !supported || e.adapter || e.discovery || e.key.purpose != WorkerForward || spec.purpose != WorkerForward || len(d.envelope) == 0 || len(d.request) > spec.limit || !json.Valid(d.request) {
		return nil, ErrInvalid
	}
	return e.executeWorkerStatement(ctx, d, statement)
}
func approvalOriginStatement(op WorkerOperation) (string, bool) {
	switch op {
	case "finding.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('finding78',$1::jsonb)`, true
	case "test74.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('test74',$1::jsonb)`, true
	case "ordered68.planning.admit":
		return `SELECT zasp_approval_maintenance.admit_with_origin('ordered68',$1::jsonb)`, true
	default:
		return "", false
	}
}
