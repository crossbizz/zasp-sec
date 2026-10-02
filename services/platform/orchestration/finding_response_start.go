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

type FindingResponseStarter struct {
	client  discoveryStartClient
	queue   string
	timeout time.Duration
}

func NewFindingResponseStarter(c discoveryStartClient, queue string, timeout time.Duration) (*FindingResponseStarter, error) {
	if c == nil || queue == "" || strings.TrimSpace(queue) != queue || len(queue) > 255 || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &FindingResponseStarter{client: c, queue: queue, timeout: timeout}, nil
}

func FindingResponseWorkflowID(r RunRef) (string, error) {
	if !r.valid() {
		return "", ErrInvalid
	}
	return "security-agent-finding/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.RunID, nil
}

func (s *FindingResponseStarter) Start(ctx context.Context, q StartRequest) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !q.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	id, _ := FindingResponseWorkflowID(q.Ref)
	run, err := s.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: s.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true}, "FindingResponseWorkflow", q)
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
	return s.verifyChain(bounded, id, already.RunId, q)
}

// Read the exact execution named by AlreadyStarted. Both its description and
// immutable history must agree; a missing/retained-away event is a repair gate.
func (s *FindingResponseStarter) started(ctx context.Context, id, run string) (*historypb.WorkflowExecutionStartedEventAttributes, error) {
	d, err := s.client.DescribeWorkflowExecution(ctx, id, run)
	if err != nil || ctx.Err() != nil || d == nil || d.WorkflowExecutionInfo == nil {
		return nil, ErrUnavailable
	}
	i := d.WorkflowExecutionInfo
	if i.GetExecution().GetWorkflowId() != id || i.GetExecution().GetRunId() != run || i.GetFirstRunId() == "" || i.GetTaskQueue() != s.queue {
		return nil, ErrConflict
	}
	event, err := s.history(ctx, id, run, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if err != nil {
		return nil, err
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	if a == nil {
		return nil, ErrUnavailable
	}
	if a.GetOriginalExecutionRunId() != run || a.GetFirstExecutionRunId() != i.GetFirstRunId() || a.GetWorkflowType().GetName() != i.GetType().GetName() || a.GetTaskQueue().GetName() != s.queue {
		return nil, ErrConflict
	}
	return a, nil
}

func (s *FindingResponseStarter) history(ctx context.Context, id, run string, filter enumspb.HistoryEventFilterType) (*historypb.HistoryEvent, error) {
	it := s.client.GetWorkflowHistory(ctx, id, run, false, filter)
	if it == nil || !it.HasNext() {
		return nil, ErrUnavailable
	}
	event, err := it.Next()
	if err != nil || event == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return event, nil
}

func (s *FindingResponseStarter) verifyChain(ctx context.Context, id, run string, q StartRequest) error {
	a, err := s.started(ctx, id, run)
	if err != nil {
		return err
	}
	first := a.GetFirstExecutionRunId()
	dc := converter.GetDefaultDataConverter()
	var expected FindingResponseCleanupContinuation
	if run != first {
		if dc.FromPayloads(a.Input, &expected) != nil || !expected.valid() || expected.Start != q {
			return ErrConflict
		}
	}
	seen := map[string]bool{}
	// The RPC deadline bounds long chains. Traversal follows server-recorded
	// predecessors and verifies every forward close link, including the root.
	for {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if seen[run] || a.GetFirstExecutionRunId() != first {
			return ErrConflict
		}
		seen[run] = true
		if run == first {
			var input StartRequest
			if a.GetWorkflowType().GetName() != "FindingResponseWorkflow" || a.GetContinuedExecutionRunId() != "" || dc.FromPayloads(a.Input, &input) != nil || input != q {
				return ErrConflict
			}
			return nil
		}
		var continuation FindingResponseCleanupContinuation
		previous := a.GetContinuedExecutionRunId()
		if a.GetWorkflowType().GetName() != "FindingResponseCleanupWorkflow" || previous == "" || previous == run || dc.FromPayloads(a.Input, &continuation) != nil || continuation != expected {
			return ErrConflict
		}
		closed, err := s.history(ctx, id, previous, enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT)
		if err != nil {
			return err
		}
		link := closed.GetWorkflowExecutionContinuedAsNewEventAttributes()
		var next FindingResponseCleanupContinuation
		if link == nil || link.GetNewExecutionRunId() != run || link.GetWorkflowType().GetName() != "FindingResponseCleanupWorkflow" || link.GetTaskQueue().GetName() != s.queue || dc.FromPayloads(link.Input, &next) != nil || next != expected {
			return ErrConflict
		}
		a, err = s.started(ctx, id, previous)
		if err != nil {
			return err
		}
		run = previous
	}
}

// Wakes carry no authority; the product decision is already committed in SQL.
func (s *FindingResponseStarter) Wake(ctx context.Context, q StartRequest) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !q.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	id, _ := FindingResponseWorkflowID(q.Ref)
	if err := s.client.SignalWorkflow(bounded, id, "", "finding-response-wake", nil); err != nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// Cancel never starts a run or treats an RPC response as cleanup evidence.
func (s *FindingResponseStarter) Cancel(ctx context.Context, q StartRequest) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !q.valid() {
		return ErrInvalid
	}
	canceller, ok := s.client.(interface {
		CancelWorkflow(context.Context, string, string) error
	})
	if !ok {
		return ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	id, _ := FindingResponseWorkflowID(q.Ref)
	if err := canceller.CancelWorkflow(bounded, id, ""); err != nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
