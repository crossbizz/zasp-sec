package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

// Only the external Temporal transport is controlled. The production adapter
// must decide whether the outbox can acknowledge an exact accepted identity.
type automaticStartBoundary struct {
	client.Client
	options      client.StartWorkflowOptions
	startErr     error
	nilRun       bool
	wrongRun     bool
	cancel       context.CancelFunc
	descriptions map[string]*workflowservice.DescribeWorkflowExecutionResponse
	starts       map[string]*historypb.HistoryEvent
	closes       map[string]*historypb.HistoryEvent
}

func (c *automaticStartBoundary) ExecuteWorkflow(ctx context.Context, options client.StartWorkflowOptions, name interface{}, args ...interface{}) (client.WorkflowRun, error) {
	if _, ok := ctx.Deadline(); !ok || name != "AutomaticSourceWorkflow" || len(args) != 1 {
		return nil, ErrInvalid
	}
	q, ok := args[0].(AutomaticSourceStart)
	if !ok || q.Ref != automaticRef() || q.After != "" || q.Retry {
		return nil, ErrInvalid
	}
	c.options = options
	if c.cancel != nil {
		c.cancel()
	}
	if c.startErr != nil || c.nilRun {
		return nil, c.startErr
	}
	id := options.ID
	if c.wrongRun {
		id = "foreign"
	}
	return discoveryStartedRun{id: id}, nil
}
func (c *automaticStartBoundary) DescribeWorkflowExecution(_ context.Context, id, run string) (*workflowservice.DescribeWorkflowExecutionResponse, error) {
	if id != c.options.ID {
		return nil, ErrConflict
	}
	return c.descriptions[run], nil
}
func (c *automaticStartBoundary) GetWorkflowHistory(_ context.Context, id, run string, _ bool, filter enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	if id != c.options.ID {
		return &oneEvent{}
	}
	if filter == enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT {
		return &oneEvent{event: c.closes[run]}
	}
	return &oneEvent{event: c.starts[run]}
}

func automaticStartFixture(t *testing.T, continued bool) *automaticStartBoundary {
	t.Helper()
	r := automaticRef()
	id := "automatic-source/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.EventID
	c := &automaticStartBoundary{descriptions: map[string]*workflowservice.DescribeWorkflowExecutionResponse{}, starts: map[string]*historypb.HistoryEvent{}, closes: map[string]*historypb.HistoryEvent{}}
	root := AutomaticSourceStart{Ref: r}
	for _, run := range []string{"execution-0001", "execution-0002"} {
		q, previous := root, ""
		if run == "execution-0002" {
			q.After = "pid_f0773000-0000-4000-8000-000000000100"
			q.Retry = true
			previous = "execution-0001"
		}
		payload, err := converter.GetDefaultDataConverter().ToPayloads(q)
		require.NoError(t, err)
		c.descriptions[run] = &workflowservice.DescribeWorkflowExecutionResponse{WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{Execution: &commonpb.WorkflowExecution{WorkflowId: id, RunId: run}, FirstRunId: "execution-0001", Type: &commonpb.WorkflowType{Name: "AutomaticSourceWorkflow"}, TaskQueue: "tests", Status: enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED}}
		c.starts[run] = &historypb.HistoryEvent{EventId: 1, Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: payload, WorkflowType: &commonpb.WorkflowType{Name: "AutomaticSourceWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "tests"}, OriginalExecutionRunId: run, FirstExecutionRunId: "execution-0001", ContinuedExecutionRunId: previous}}}
		if run == "execution-0002" {
			c.closes[previous] = &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionContinuedAsNewEventAttributes{WorkflowExecutionContinuedAsNewEventAttributes: &historypb.WorkflowExecutionContinuedAsNewEventAttributes{NewExecutionRunId: run, WorkflowType: &commonpb.WorkflowType{Name: "AutomaticSourceWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "tests"}, Input: payload}}}
		}
	}
	run := "execution-0001"
	if continued {
		run = "execution-0002"
	}
	c.startErr = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", run)
	return c
}

func TestAutomaticSourceStartAcknowledgesOnlyExactDurableAcceptance(t *testing.T) {
	for _, mode := range []string{"new", "completed", "continued", "nil_handle", "wrong_handle", "canceled_after_start", "ambiguous", "generic_conflict", "foreign_current", "foreign_root", "foreign_type", "foreign_queue", "wrong_described_run", "wrong_chain", "missing_root", "missing_close", "foreign_close", "missing_run_id"} {
		t.Run(mode, func(t *testing.T) {
			c := automaticStartFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "new":
				c.startErr = nil
			case "completed":
				c.startErr = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "execution-0001")
			case "nil_handle":
				c.startErr = nil
				c.nilRun = true
			case "wrong_handle":
				c.startErr = nil
				c.wrongRun = true
			case "canceled_after_start":
				c.startErr = nil
				c.cancel = cancel
			case "ambiguous":
				c.startErr = context.DeadlineExceeded
			case "generic_conflict":
				c.startErr = errors.New("conflict")
			case "foreign_current", "foreign_root":
				run := "execution-0002"
				if mode == "foreign_root" {
					run = "execution-0001"
				}
				q := AutomaticSourceStart{Ref: automaticRef()}
				q.Ref.EnvironmentID = "pid_f0773000-0000-4000-8000-000000000099"
				p, err := converter.GetDefaultDataConverter().ToPayloads(q)
				require.NoError(t, err)
				c.starts[run].GetWorkflowExecutionStartedEventAttributes().Input = p
			case "foreign_type":
				c.starts["execution-0002"].GetWorkflowExecutionStartedEventAttributes().WorkflowType.Name = "ForeignWorkflow"
			case "foreign_queue":
				c.descriptions["execution-0002"].WorkflowExecutionInfo.TaskQueue = "foreign"
			case "wrong_described_run":
				c.descriptions["execution-0002"].WorkflowExecutionInfo.Execution.RunId = "foreign"
			case "wrong_chain":
				c.descriptions["execution-0002"].WorkflowExecutionInfo.FirstRunId = "foreign"
			case "missing_root":
				delete(c.starts, "execution-0001")
			case "missing_close":
				delete(c.closes, "execution-0001")
			case "foreign_close":
				c.closes["execution-0001"].GetWorkflowExecutionContinuedAsNewEventAttributes().NewExecutionRunId = "foreign"
			case "missing_run_id":
				c.startErr = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "")
			}
			s, err := NewAutomaticSourceStarter(c, "tests", time.Second)
			require.NoError(t, err)
			err = s.Start(ctx, automaticRef())
			if mode == "new" || mode == "completed" || mode == "continued" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, c.options.WorkflowIDReusePolicy)
			require.Equal(t, enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, c.options.WorkflowIDConflictPolicy)
			require.True(t, c.options.WorkflowExecutionErrorWhenAlreadyStarted)
			require.Zero(t, c.options.WorkflowExecutionTimeout, "full fan-out must not expire after a fixed short Activity budget")
		})
	}
}
