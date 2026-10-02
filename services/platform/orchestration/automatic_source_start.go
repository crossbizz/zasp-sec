package orchestration

import (
	"context"
	"errors"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

// Acceptance is distinct from execution completion. A retained completed
// execution owns its source identity too; unavailable history cannot prove it.
type AutomaticSourceStarter struct {
	client  discoveryStartClient
	queue   string
	timeout time.Duration
}

func NewAutomaticSourceStarter(c discoveryStartClient, queue string, timeout time.Duration) (*AutomaticSourceStarter, error) {
	if c == nil || queue == "" || strings.TrimSpace(queue) != queue || len(queue) > 255 || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &AutomaticSourceStarter{c, queue, timeout}, nil
}

func (s *AutomaticSourceStarter) Start(ctx context.Context, ref AutomaticSourceRef) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !ref.Valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	id, _ := AutomaticSourceWorkflowID(ref)
	q := AutomaticSourceStart{Ref: ref}
	run, err := s.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: s.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true}, "AutomaticSourceWorkflow", q)
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
	a, current, err := s.startedInput(bounded, id, already.RunId, ref)
	if err != nil {
		return err
	}
	first := a.GetFirstExecutionRunId()
	if first == already.RunId {
		if a.GetContinuedExecutionRunId() != "" || current != q {
			return ErrConflict
		}
		return nil
	}
	previous := a.GetContinuedExecutionRunId()
	if previous == "" || previous == already.RunId {
		return ErrConflict
	}
	root, original, err := s.startedInput(bounded, id, first, ref)
	if err != nil {
		return err
	}
	if root.GetFirstExecutionRunId() != first || root.GetContinuedExecutionRunId() != "" || original != q {
		return ErrConflict
	}
	// Bind the exact current segment to the immutable predecessor close event.
	// Three bounded history reads suffice, independent of the number of pages.
	it := s.client.GetWorkflowHistory(bounded, id, previous, false, enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT)
	if it == nil || !it.HasNext() {
		return ErrUnavailable
	}
	event, err := it.Next()
	if err != nil || bounded.Err() != nil || event == nil {
		return ErrUnavailable
	}
	closed := event.GetWorkflowExecutionContinuedAsNewEventAttributes()
	if closed == nil {
		return ErrConflict
	}
	var continued AutomaticSourceStart
	if converter.GetDefaultDataConverter().FromPayloads(closed.GetInput(), &continued) != nil {
		return ErrUnavailable
	}
	if closed.GetNewExecutionRunId() != already.RunId || closed.GetWorkflowType().GetName() != "AutomaticSourceWorkflow" || closed.GetTaskQueue().GetName() != s.queue || continued != current {
		return ErrConflict
	}
	return nil
}

func (s *AutomaticSourceStarter) startedInput(ctx context.Context, id, run string, ref AutomaticSourceRef) (*historypb.WorkflowExecutionStartedEventAttributes, AutomaticSourceStart, error) {
	var q AutomaticSourceStart
	d, err := s.client.DescribeWorkflowExecution(ctx, id, run)
	if err != nil || ctx.Err() != nil || d == nil || d.WorkflowExecutionInfo == nil {
		return nil, q, ErrUnavailable
	}
	i := d.WorkflowExecutionInfo
	if i.GetExecution().GetWorkflowId() != id || i.GetExecution().GetRunId() != run || i.GetFirstRunId() == "" || i.GetType().GetName() != "AutomaticSourceWorkflow" || i.GetTaskQueue() != s.queue {
		return nil, q, ErrConflict
	}
	it := s.client.GetWorkflowHistory(ctx, id, run, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if it == nil || !it.HasNext() {
		return nil, q, ErrUnavailable
	}
	event, err := it.Next()
	if err != nil || ctx.Err() != nil || event == nil {
		return nil, q, ErrUnavailable
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	if a == nil || event.GetEventId() != 1 {
		return nil, q, ErrUnavailable
	}
	if converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &q) != nil {
		return nil, q, ErrUnavailable
	}
	if a.GetOriginalExecutionRunId() != run || a.GetFirstExecutionRunId() != i.GetFirstRunId() || a.GetWorkflowType().GetName() != "AutomaticSourceWorkflow" || a.GetTaskQueue().GetName() != s.queue || q.Ref != ref || (q.After != "" && !validID(q.After)) {
		return nil, q, ErrConflict
	}
	return a, q, nil
}
