package orchestration

import (
	"context"
	"errors"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	workflowservice "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"time"
	"unicode/utf8"
)

type SingleTestDescribeClient interface {
	DescribeWorkflowExecution(context.Context, string, string) (*workflowservice.DescribeWorkflowExecutionResponse, error)
}
type singleTestOriginalObserver struct {
	client  SingleTestDescribeClient
	timeout time.Duration
}

func NewSingleTestOriginalObserver(c SingleTestDescribeClient, timeout time.Duration) (SingleTestOriginalObserver, error) {
	if c == nil || timeout <= 0 || timeout > 5*time.Second {
		return nil, ErrInvalid
	}
	return &singleTestOriginalObserver{c, timeout}, nil
}
func (o *singleTestOriginalObserver) ObserveOriginal(ctx context.Context, q StartRequest) (SingleTestOriginalObservation, error) {
	empty := SingleTestOriginalObservation{}
	if o == nil || ctx == nil || !q.valid() {
		return empty, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	id, _ := SingleTestWorkflowID(q.Ref)
	v, err := o.client.DescribeWorkflowExecution(bounded, id, "")
	if bounded.Err() != nil {
		return empty, ErrUnavailable
	}
	var absent *serviceerror.NotFound
	if errors.As(err, &absent) {
		return SingleTestOriginalObservation{WorkflowID: id, Status: "absent", ObservedAt: time.Now().UTC()}, nil
	}
	if err != nil || v == nil || v.WorkflowExecutionInfo == nil {
		return empty, ErrUnavailable
	}
	info := v.WorkflowExecutionInfo
	execution := info.GetExecution()
	if execution.GetWorkflowId() != id || execution.GetRunId() == "" || len(execution.GetRunId()) > 256 || !utf8.ValidString(execution.GetRunId()) {
		return empty, ErrUnavailable
	}
	switch info.GetStatus() {
	case enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING:
		return empty, ErrConflict
	case enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED, enumspb.WORKFLOW_EXECUTION_STATUS_FAILED, enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED, enumspb.WORKFLOW_EXECUTION_STATUS_TERMINATED, enumspb.WORKFLOW_EXECUTION_STATUS_TIMED_OUT:
		run := execution.GetRunId()
		return SingleTestOriginalObservation{WorkflowID: id, RunID: &run, Status: "closed", ObservedAt: time.Now().UTC()}, nil
	default:
		return empty, ErrUnavailable
	}
}
func (e *TemporalEngine) StartSingleTestRecovery(ctx context.Context, r SingleTestRecoveryRef) error {
	if e == nil || ctx == nil || !r.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	id, _ := SingleTestRecoveryWorkflowID(r)
	run, err := e.client.ExecuteWorkflow(bounded, client.StartWorkflowOptions{ID: id, TaskQueue: e.queue, WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, WorkflowExecutionErrorWhenAlreadyStarted: true}, "SingleTestOperatorCleanupWorkflow", r)
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
	it := e.client.GetWorkflowHistory(bounded, id, already.RunId, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if it == nil || !it.HasNext() {
		return ErrUnavailable
	}
	event, err := it.Next()
	if err != nil || event == nil || bounded.Err() != nil {
		return ErrUnavailable
	}
	a := event.GetWorkflowExecutionStartedEventAttributes()
	var got SingleTestRecoveryRef
	if a == nil || converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &got) != nil {
		return ErrUnavailable
	}
	if a.GetWorkflowType().GetName() != "SingleTestOperatorCleanupWorkflow" || a.GetTaskQueue().GetName() != e.queue || got != r || a.GetOriginalExecutionRunId() != already.RunId {
		return ErrConflict
	}
	return nil
}
