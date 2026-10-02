package authorization

import "testing"

// A lifecycle mapping must never turn retained observation or cancellation
// into a fresh forward grant, nor select an arbitrary sibling SQL operation.
func TestOrderedLifecycleOperationPurpose(t *testing.T) {
	for _, phase := range []string{"inspect", "message", "stop"} {
		s, ok := workerOperation(WorkerOperation("ordered69." + phase))
		if !ok || s.purpose != CapturedCompensation || s.current || s.bindRequest || s.adapter || s.discovery || s.limit != 4096 || s.phase != phase || s.source != `SELECT zasp_authorization80_worker.ordered69_source($1,$2::jsonb)` || s.statement != `SELECT zasp_authorization80_worker.ordered69_`+phase+`($1::jsonb)` {
			t.Errorf("missing captured lifecycle boundary: %s", phase)
		}
	}
	for _, op := range []WorkerOperation{"ordered69.apply", "ordered69.inspect_message", "ordered69.inspect.extra", "ordered69.sql", "ordered69", "ordered69.cleanup"} {
		if _, ok := workerOperation(op); ok {
			t.Errorf("unknown lifecycle operation accepted: %s", op)
		}
	}
}
