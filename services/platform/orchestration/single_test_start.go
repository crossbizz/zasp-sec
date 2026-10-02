package orchestration

import (
	"context"
	"errors"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

func SingleTestWorkflowID(r RunRef) (string, error) {
	if !r.valid() {
		return "", ErrInvalid
	}
	return "security-agent-test/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.RunID, nil
}

func (e *TemporalEngine) StartSingleTest(ctx context.Context, q StartRequest) error {
	if e == nil || ctx == nil || !q.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := SingleTestWorkflowID(q.Ref)
	run, err := e.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: e.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true}, "SingleTestWorkflow", q)
	if bounded.Err() != nil {
		return ErrUnavailable
	}
	if err == nil {
		if run == nil || run.GetID() != id || run.GetRunID() == "" {
			return ErrUnavailable
		}
		return nil
	}
	var already *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &already) || already.RunId == "" {
		return ErrUnavailable
	}
	iterator := e.client.GetWorkflowHistory(bounded, id, already.RunId, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if iterator == nil || !iterator.HasNext() {
		return ErrUnavailable
	}
	event, err := iterator.Next()
	if err != nil || bounded.Err() != nil || event == nil {
		return ErrUnavailable
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	if a == nil {
		return ErrUnavailable
	}
	if a.GetWorkflowType().GetName() == "SingleTestCleanupWorkflow" {
		return e.verifySingleTestCleanupChain(bounded, id, already.RunId, q, a)
	}
	var original StartRequest
	if converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &original) != nil {
		return ErrUnavailable
	}
	if original != q || a.GetWorkflowType().GetName() != "SingleTestWorkflow" || a.GetTaskQueue().GetName() != e.queue || a.GetOriginalExecutionRunId() != already.RunId || a.GetContinuedExecutionRunId() != "" || a.GetFirstExecutionRunId() != already.RunId {
		return ErrConflict
	}
	return nil
}

// A continued run is accepted only with the original business start and the
// server-recorded predecessor close event. Missing history is a repair gate.
func (e *TemporalEngine) verifySingleTestCleanupChain(ctx context.Context, id, run string, q StartRequest, a *historypb.WorkflowExecutionStartedEventAttributes) error {
	first, previous := a.GetFirstExecutionRunId(), a.GetContinuedExecutionRunId()
	if a.GetOriginalExecutionRunId() != run || first == "" || first == run || previous == "" || previous == run || a.GetTaskQueue().GetName() != e.queue {
		return ErrConflict
	}
	var continuation SingleTestCleanupContinuation
	dc := converter.GetDefaultDataConverter()
	if dc.FromPayloads(a.Input, &continuation) != nil || !continuation.valid() || continuation.Start != q {
		return ErrConflict
	}
	read := func(r string, filter enumspb.HistoryEventFilterType) (*historypb.HistoryEvent, error) {
		it := e.client.GetWorkflowHistory(ctx, id, r, false, filter)
		if it == nil || !it.HasNext() {
			return nil, ErrUnavailable
		}
		v, err := it.Next()
		if err != nil || v == nil || ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		return v, nil
	}
	root, err := read(first, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if err != nil {
		return err
	}
	original := root.GetWorkflowExecutionStartedEventAttributes()
	var input StartRequest
	if original == nil || original.GetWorkflowType().GetName() != "SingleTestWorkflow" || original.GetTaskQueue().GetName() != e.queue || original.GetOriginalExecutionRunId() != first || original.GetFirstExecutionRunId() != first || original.GetContinuedExecutionRunId() != "" || dc.FromPayloads(original.Input, &input) != nil || input != q {
		return ErrConflict
	}
	check := func(event *historypb.HistoryEvent, next string) bool {
		closed := event.GetWorkflowExecutionContinuedAsNewEventAttributes()
		var value SingleTestCleanupContinuation
		return closed != nil && closed.GetWorkflowType().GetName() == "SingleTestCleanupWorkflow" && closed.GetTaskQueue().GetName() == e.queue && closed.GetNewExecutionRunId() != "" && (next == "" || closed.GetNewExecutionRunId() == next) && dc.FromPayloads(closed.Input, &value) == nil && value == continuation
	}
	rootClose, err := read(first, enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT)
	if err != nil {
		return err
	}
	if !check(rootClose, "") {
		return ErrConflict
	}
	previousClose := rootClose
	if previous != first {
		previousClose, err = read(previous, enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT)
		if err != nil {
			return err
		}
	}
	if !check(previousClose, run) {
		return ErrConflict
	}
	return nil
}

// The caller resolves the owned child through SQL first. This only wakes the
// existing identity; it cannot start a run or authorize an effect.
func (e *TemporalEngine) WakeSingleTest(ctx context.Context, q StartRequest) error {
	if e == nil || ctx == nil || !q.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := SingleTestWorkflowID(q.Ref)
	if err := e.client.SignalWorkflow(bounded, id, "", "single-test-wake", nil); err != nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// Cancellation targets only the already accepted logical workflow. Its SQL
// decision has already fenced fresh IO; this RPC does not discharge any debt.
func (e *TemporalEngine) CancelSingleTest(ctx context.Context, q StartRequest) error {
	if e == nil || ctx == nil || !q.valid() {
		return ErrInvalid
	}
	canceller, ok := e.client.(interface {
		CancelWorkflow(context.Context, string, string) error
	})
	if !ok {
		return ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := SingleTestWorkflowID(q.Ref)
	if err := canceller.CancelWorkflow(bounded, id, ""); err != nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
