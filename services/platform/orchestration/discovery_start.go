package orchestration

import (
	"context"
	"errors"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

// DiscoveryStarter is used only by the retained discovery SQS consumer. Tick
// workflows and desired-state repair persist the product outbox, never start.
type DiscoveryStarter struct {
	client  discoveryStartClient
	queue   string
	timeout time.Duration
}

type discoveryStartClient interface {
	TemporalClient
	DescribeWorkflowExecution(context.Context, string, string) (*workflowservice.DescribeWorkflowExecutionResponse, error)
}

func NewDiscoveryStarter(c discoveryStartClient, queue string, timeout time.Duration) (*DiscoveryStarter, error) {
	if c == nil || queue == "" || strings.TrimSpace(queue) != queue || len(queue) > 255 || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &DiscoveryStarter{c, queue, timeout}, nil
}

func (s *DiscoveryStarter) Start(ctx context.Context, q DiscoveryStart) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !q.valid() || q.Continuation == nil || q.Continuation.CheckpointVersion != 0 || q.Continuation.ReceiptDigest != "" || q.Continuation.Deadline.IsZero() || q.Continuation.Deadline.After(time.Now().Add(24*time.Hour)) {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	id, _ := DiscoveryWorkflowID(q)
	remaining := time.Until(q.Continuation.Deadline)
	if remaining < 0 {
		remaining = 0
	}
	run, err := s.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: s.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true, WorkflowExecutionTimeout: remaining + 5*time.Minute}, "DiscoveryWorkflow", q)
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
	// AlreadyStarted may name a Continue-As-New segment. Bind that exact run,
	// then its authoritative first execution, never a caller-supplied chain or
	// mutable memo. At most two descriptions and two first-event reads occur.
	a, original, err := s.startedInput(bounded, id, already.RunId, q)
	if err != nil {
		return err
	}
	first := a.GetFirstExecutionRunId()
	if first != already.RunId {
		if a.GetContinuedExecutionRunId() == "" || original.Continuation.CheckpointVersion < 1 || original.Continuation.CheckpointVersion > 10000 || !digestPattern.MatchString(original.Continuation.ReceiptDigest) {
			return ErrConflict
		}
		a, original, err = s.startedInput(bounded, id, first, q)
		if err != nil {
			return err
		}
	}
	if a.GetFirstExecutionRunId() != first || a.GetContinuedExecutionRunId() != "" || original.Continuation.CheckpointVersion != 0 || original.Continuation.ReceiptDigest != "" {
		return ErrConflict
	}
	return nil
}

func (s *DiscoveryStarter) startedInput(ctx context.Context, id, run string, q DiscoveryStart) (*historypb.WorkflowExecutionStartedEventAttributes, DiscoveryStart, error) {
	var original DiscoveryStart
	d, err := s.client.DescribeWorkflowExecution(ctx, id, run)
	if err != nil || ctx.Err() != nil || d == nil || d.WorkflowExecutionInfo == nil {
		return nil, original, ErrUnavailable
	}
	info := d.WorkflowExecutionInfo
	if info.GetExecution().GetWorkflowId() != id || info.GetExecution().GetRunId() != run || info.GetFirstRunId() == "" || info.GetType().GetName() != "DiscoveryWorkflow" || info.GetTaskQueue() != s.queue {
		return nil, original, ErrConflict
	}
	iterator := s.client.GetWorkflowHistory(ctx, id, run, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if iterator == nil || !iterator.HasNext() {
		return nil, original, ErrUnavailable
	}
	event, err := iterator.Next()
	if err != nil || ctx.Err() != nil || event == nil {
		return nil, original, ErrUnavailable
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	if a == nil {
		return nil, original, ErrUnavailable
	}
	if converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &original) != nil {
		return nil, original, ErrUnavailable
	}
	if a.GetOriginalExecutionRunId() != run || a.GetFirstExecutionRunId() != info.GetFirstRunId() || a.GetWorkflowType().GetName() != "DiscoveryWorkflow" || a.GetTaskQueue().GetName() != s.queue || original.Ref != q.Ref || original.IntegrationID != q.IntegrationID || original.InputDigest != q.InputDigest || original.Continuation == nil || !original.Continuation.Deadline.Equal(q.Continuation.Deadline) {
		return nil, original, ErrConflict
	}
	return a, original, nil
}
