package authorization

import (
	"context"
	"encoding/json"
)

// ExecuteOrderedTestDispatchReadback uses the original dispatch decision. Its
// fixed native entry validates that proof before returning a read-only linked
// projection. The decision must be executed normally after artifact readback;
// neither this method nor its result grants a send permit.
func (e *WorkerExecutor) ExecuteOrderedTestDispatchReadback(ctx context.Context, decision WorkerDecision) (json.RawMessage, error) {
	if e == nil || e.key == nil || e.pool == nil || ctx == nil || ctx.Err() != nil || e.adapter || e.discovery || e.key.purpose != WorkerForward || decision.operation != "ordered68.linked.dispatch" || len(decision.envelope) == 0 || len(decision.request) == 0 || len(decision.request) > 131072 {
		return nil, ErrInvalid
	}
	var q struct {
		Operation string          `json:"operation"`
		Payload   json.RawMessage `json:"payload"`
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(decision.request, &q) != nil || q.Operation != "dispatch" || json.Unmarshal(q.Payload, &payload) != nil || payload == nil || len(payload) != 0 {
		return nil, ErrInvalid
	}
	return e.executeWorkerStatement(ctx, decision, `SELECT zasp_authorization80_worker.ordered68_dispatch_readback($1::jsonb)`)
}
