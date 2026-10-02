package orchestration

import (
	"context"
	"errors"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
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
	if !iterator.HasNext() {
		return ErrUnavailable
	}
	event, err := iterator.Next()
	if err != nil || event.GetWorkflowExecutionStartedEventAttributes() == nil {
		return ErrUnavailable
	}
	var original StartRequest
	if converter.GetDefaultDataConverter().FromPayloads(event.GetWorkflowExecutionStartedEventAttributes().GetInput(), &original) != nil {
		return ErrUnavailable
	}
	if original != r {
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
