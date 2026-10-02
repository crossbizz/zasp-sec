package orchestration

import (
	"context"
	"errors"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

type TemporalClient interface {
	ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error)
	SignalWorkflow(context.Context, string, string, string, interface{}) error
	GetWorkflowHistory(context.Context, string, string, bool, enumspb.HistoryEventFilterType) client.HistoryEventIterator
}
type TemporalEngine struct {
	client  TemporalClient
	queue   string
	timeout time.Duration
}

func NewTemporalEngine(c TemporalClient, queue string, timeout time.Duration) (*TemporalEngine, error) {
	if c == nil || queue == "" || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &TemporalEngine{c, queue, timeout}, nil
}
func (e *TemporalEngine) Start(ctx context.Context, r StartRequest) error {
	if ctx == nil || e == nil || !r.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := WorkflowID(r.Ref)
	_, err := e.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: e.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true}, "SecurityAgentWorkflow", r)
	if bounded.Err() != nil {
		return ErrUnavailable
	}
	if err == nil {
		return nil
	}
	var started *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &started) {
		return ErrUnavailable
	}
	// The first history event is immutable; memo/search attributes are not.
	// Bind the exact rejected execution, never a later execution with this ID.
	if started.RunId == "" {
		return ErrUnavailable
	}
	iterator := e.client.GetWorkflowHistory(bounded, id, started.RunId, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if iterator == nil || !iterator.HasNext() {
		return ErrUnavailable
	}
	event, err := iterator.Next()
	if err != nil || bounded.Err() != nil || event == nil || event.GetWorkflowExecutionStartedEventAttributes() == nil {
		return ErrUnavailable
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	if a.GetWorkflowType().GetName() == "SecurityAgentCleanupWorkflow" {
		return e.verifyOrderedCleanupChain(bounded, id, started.RunId, r, a)
	}
	var original StartRequest
	if converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &original) != nil {
		return ErrUnavailable
	}
	if original != r || a.GetWorkflowType().GetName() != "SecurityAgentWorkflow" || a.GetTaskQueue().GetName() != e.queue || a.GetOriginalExecutionRunId() != started.RunId || a.GetFirstExecutionRunId() != started.RunId || a.GetContinuedExecutionRunId() != "" {
		return ErrConflict
	}
	return nil
}

// Cleanup carries the same logical admission, but has a different payload.
// Authenticate its immutable root and server-recorded predecessor before the
// outbox may acknowledge a replay. No mutable memo can establish this binding.
func (e *TemporalEngine) verifyOrderedCleanupChain(ctx context.Context, id, run string, q StartRequest, a *historypb.WorkflowExecutionStartedEventAttributes) error {
	first, previous := a.GetFirstExecutionRunId(), a.GetContinuedExecutionRunId()
	if a.GetOriginalExecutionRunId() != run || first == "" || first == run || previous == "" || previous == run || a.GetTaskQueue().GetName() != e.queue {
		return ErrConflict
	}
	dc := converter.GetDefaultDataConverter()
	var continuation SecurityAgentCleanupContinuation
	if dc.FromPayloads(a.GetInput(), &continuation) != nil || !continuation.valid() || continuation.Start != q {
		return ErrConflict
	}
	read := func(execution string, filter enumspb.HistoryEventFilterType) (*historypb.HistoryEvent, error) {
		it := e.client.GetWorkflowHistory(ctx, id, execution, false, filter)
		if it == nil || !it.HasNext() {
			return nil, ErrUnavailable
		}
		event, err := it.Next()
		if err != nil || ctx.Err() != nil || event == nil {
			return nil, ErrUnavailable
		}
		return event, nil
	}
	root, err := read(first, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if err != nil {
		return err
	}
	original := root.GetWorkflowExecutionStartedEventAttributes()
	var input StartRequest
	if original == nil || original.GetWorkflowType().GetName() != "SecurityAgentWorkflow" || original.GetTaskQueue().GetName() != e.queue || original.GetOriginalExecutionRunId() != first || original.GetFirstExecutionRunId() != first || original.GetContinuedExecutionRunId() != "" || dc.FromPayloads(original.GetInput(), &input) != nil || input != q {
		return ErrConflict
	}
	check := func(event *historypb.HistoryEvent, next string) bool {
		closed := event.GetWorkflowExecutionContinuedAsNewEventAttributes()
		var input SecurityAgentCleanupContinuation
		return closed != nil && closed.GetWorkflowType().GetName() == "SecurityAgentCleanupWorkflow" && closed.GetTaskQueue().GetName() == e.queue && closed.GetNewExecutionRunId() != "" && (next == "" || closed.GetNewExecutionRunId() == next) && dc.FromPayloads(closed.GetInput(), &input) == nil && input == continuation
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
func (e *TemporalEngine) Notify(ctx context.Context, m Message) error {
	if ctx == nil || e == nil || !m.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := WorkflowID(m.Ref)
	// Signals only wake the workflow. The Activity must read the committed
	// decision by ID and revalidate authority; duplicate hints carry no effect.
	if err := e.client.SignalWorkflow(bounded, id, "", "product-decision", m); err != nil {
		return ErrUnavailable
	}
	return nil
}
