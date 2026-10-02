package orchestration

import (
	"context"
	"errors"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	workflowservice "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"testing"
	"time"
)

type recoverySDK struct {
	client.Client
	result *workflowservice.DescribeWorkflowExecutionResponse
	err    error
	event  *historypb.HistoryEvent
	calls  int
}

func (s *recoverySDK) DescribeWorkflowExecution(ctx context.Context, id, run string) (*workflowservice.DescribeWorkflowExecutionResponse, error) {
	expected, _ := SingleTestWorkflowID(request().Ref)
	if _, ok := ctx.Deadline(); !ok || id != expected || run != "" {
		return nil, errors.New("unexpected describe boundary")
	}
	s.calls++
	return s.result, s.err
}
func (s *recoverySDK) ExecuteWorkflow(ctx context.Context, o client.StartWorkflowOptions, name any, args ...any) (client.WorkflowRun, error) {
	id, _ := SingleTestRecoveryWorkflowID(recoveryRef())
	if _, ok := ctx.Deadline(); !ok || o.ID != id || o.TaskQueue != "single-test" || name != "SingleTestOperatorCleanupWorkflow" || len(args) != 1 || args[0] != recoveryRef() || o.WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE || o.WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL {
		return nil, ErrInvalid
	}
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return discoveryStartedRun{id: id}, nil
}
func (s *recoverySDK) GetWorkflowHistory(context.Context, string, string, bool, enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	return &oneEvent{event: s.event}
}
func TestSingleTestRecoveryStartAndObserveContracts(t *testing.T) {
	id, _ := SingleTestWorkflowID(request().Ref)
	for _, tc := range []struct {
		name   string
		status enumspb.WorkflowExecutionStatus
		err    error
		want   error
		phase  string
	}{
		{"running", enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING, nil, ErrConflict, ""},
		{"closed", enumspb.WORKFLOW_EXECUTION_STATUS_FAILED, nil, nil, "closed"},
		{"absent", 0, serviceerror.NewNotFound("private detail"), nil, "absent"},
		{"continued", enumspb.WORKFLOW_EXECUTION_STATUS_CONTINUED_AS_NEW, nil, ErrUnavailable, ""},
		{"unknown", 0, nil, ErrUnavailable, ""},
		{"denied", 0, serviceerror.NewPermissionDenied("private detail", ""), ErrUnavailable, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &recoverySDK{err: tc.err, result: &workflowservice.DescribeWorkflowExecutionResponse{WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{Execution: &commonpb.WorkflowExecution{WorkflowId: id, RunId: "execution-0001"}, Status: tc.status}}}
			observer, err := NewSingleTestOriginalObserver(c, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			got, err := observer.ObserveOriginal(context.Background(), request())
			if !errors.Is(err, tc.want) || got.Status != tc.phase || c.calls != 1 {
				t.Fatal(got, err, c.calls)
			}
			if err == nil && (got.WorkflowID != id || got.ObservedAt.IsZero() || (got.RunID == nil) != (tc.phase == "absent")) {
				t.Fatal("unbound observation", got)
			}
		})
	}
	c := &recoverySDK{}
	e, _ := NewTemporalEngine(c, "single-test", time.Second)
	if err := e.StartSingleTestRecovery(context.Background(), recoveryRef()); err != nil {
		t.Fatal(err)
	}
	p, _ := converter.GetDefaultDataConverter().ToPayloads(recoveryRef())
	a := &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: "SingleTestOperatorCleanupWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "single-test"}, OriginalExecutionRunId: "execution-0001"}
	c.event = &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: a}}
	c.err = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "execution-0001")
	if err := e.StartSingleTestRecovery(context.Background(), recoveryRef()); err != nil {
		t.Fatal(err)
	}
	a.TaskQueue.Name = "other"
	if !errors.Is(e.StartSingleTestRecovery(context.Background(), recoveryRef()), ErrConflict) {
		t.Fatal("foreign recovery accepted")
	}
	c.event = nil
	if !errors.Is(e.StartSingleTestRecovery(context.Background(), recoveryRef()), ErrUnavailable) {
		t.Fatal("missing history acknowledged")
	}
}
