package orchestration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

type discoveryStartBoundary struct {
	client.Client
	err            error
	options        client.StartWorkflowOptions
	original       DiscoveryStart
	workflowType   string
	continued      *DiscoveryStart
	firstRun       string
	describeErr    error
	descriptionRun string
	missingFirst   bool
}

func (c *discoveryStartBoundary) ExecuteWorkflow(ctx context.Context, o client.StartWorkflowOptions, name interface{}, args ...interface{}) (client.WorkflowRun, error) {
	if _, ok := ctx.Deadline(); !ok || name != "DiscoveryWorkflow" || len(args) != 1 {
		return nil, ErrInvalid
	}
	c.options = o
	if c.err != nil {
		return nil, c.err
	}
	return discoveryStartedRun{id: o.ID}, nil
}

type discoveryStartedRun struct {
	client.WorkflowRun
	id string
}

func (r discoveryStartedRun) GetID() string  { return r.id }
func (discoveryStartedRun) GetRunID() string { return "execution-0001" }
func (c *discoveryStartBoundary) GetWorkflowHistory(_ context.Context, id, run string, _ bool, _ enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	if id != c.options.ID || (run != "execution-0001" && run != "execution-0002") || (run == "execution-0001" && c.missingFirst) {
		return &oneEvent{}
	}
	original, previous := c.original, ""
	if run == "execution-0002" && c.continued != nil {
		original, previous = *c.continued, "execution-0001"
	}
	p, _ := converter.GetDefaultDataConverter().ToPayloads(original)
	first := c.firstRun
	if first == "" {
		first = "execution-0001"
	}
	return &oneEvent{event: &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: c.workflowType}, TaskQueue: &taskqueuepb.TaskQueue{Name: c.options.TaskQueue}, FirstExecutionRunId: first, OriginalExecutionRunId: run, ContinuedExecutionRunId: previous}}}}
}

func (c *discoveryStartBoundary) DescribeWorkflowExecution(_ context.Context, id, run string) (*workflowservice.DescribeWorkflowExecutionResponse, error) {
	if c.describeErr != nil {
		return nil, c.describeErr
	}
	if c.descriptionRun != "" {
		run = c.descriptionRun
	}
	first := c.firstRun
	if first == "" {
		first = "execution-0001"
	}
	return &workflowservice.DescribeWorkflowExecutionResponse{WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{Execution: &commonpb.WorkflowExecution{WorkflowId: id, RunId: run}, FirstRunId: first, Type: &commonpb.WorkflowType{Name: c.workflowType}, TaskQueue: c.options.TaskQueue}}, nil
}

func TestDiscoveryStartDeliveryVerifiesContinuedChain(t *testing.T) {
	for _, mode := range []string{"matching", "foreign_current", "foreign_first", "missing_first", "different_chain", "description_wrong_run", "description_unknown"} {
		t.Run(mode, func(t *testing.T) {
			start := discoveryStart()
			start.Continuation = &DiscoveryContinuation{Deadline: time.Now().UTC().Add(time.Hour)}
			continued := start
			continued.Continuation = &DiscoveryContinuation{Deadline: start.Continuation.Deadline, CheckpointVersion: 256, ReceiptDigest: strings.Repeat("a", 64)}
			c := &discoveryStartBoundary{original: start, continued: &continued, workflowType: "DiscoveryWorkflow", err: serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "execution-0002")}
			switch mode {
			case "foreign_current":
				continued.Ref.OrganizationID = "pid_99999999-0000-4000-8000-000000000001"
			case "foreign_first":
				c.original.InputDigest = strings.Repeat("f", 64)
			case "missing_first":
				c.missingFirst = true
			case "different_chain":
				c.firstRun = "execution-foreign"
			case "description_wrong_run":
				c.descriptionRun = "execution-foreign"
			case "description_unknown":
				c.describeErr = context.DeadlineExceeded
			}
			s, err := NewDiscoveryStarter(c, "discovery", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			err = s.Start(context.Background(), start)
			if mode == "matching" && err != nil {
				t.Fatal("matching continued execution not acknowledged", err)
			}
			if mode != "matching" && err == nil {
				t.Fatal("unverified continued execution acknowledged")
			}
		})
	}
}

func TestDiscoveryStartDeliveryMatchesHistoryAndOriginalBudget(t *testing.T) {
	start := discoveryStart()
	start.Continuation = &DiscoveryContinuation{Deadline: time.Now().UTC().Add(-time.Minute)}
	c := &discoveryStartBoundary{original: start, workflowType: "DiscoveryWorkflow"}
	s, err := NewDiscoveryStarter(c, "discovery", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(context.Background(), start); err != nil {
		t.Fatal("expired fresh-work budget must still allow evidence settlement", err)
	}
	id, _ := DiscoveryWorkflowID(start)
	if c.options.ID != id || c.options.WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE || c.options.WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL || !c.options.WorkflowExecutionErrorWhenAlreadyStarted || c.options.WorkflowExecutionTimeout <= 0 || c.options.WorkflowExecutionTimeout > 24*time.Hour+5*time.Minute {
		t.Fatal("unsafe start mapping", c.options)
	}
	c.err = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "execution-0001")
	if err = s.Start(context.Background(), start); err != nil {
		t.Fatal("matching duplicate", err)
	}
	c.original.InputDigest = strings.Repeat("f", 64)
	if err = s.Start(context.Background(), start); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign execution acknowledged", err)
	}
	c.original = start
	c.workflowType = "SecurityAgentWorkflow"
	if err = s.Start(context.Background(), start); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign workflow type acknowledged", err)
	}
	c.workflowType = "DiscoveryWorkflow"
	c.err = context.DeadlineExceeded
	if err = s.Start(context.Background(), start); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ambiguous start acknowledged", err)
	}
}
