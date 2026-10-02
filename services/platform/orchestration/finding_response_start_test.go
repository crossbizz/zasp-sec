package orchestration

import (
	"context"
	"strings"
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

type findingStartBoundary struct {
	client.Client
	options          client.StartWorkflowOptions
	input            StartRequest
	name             any
	err              error
	describeErr      error
	histories        map[string]*historypb.HistoryEvent
	descriptions     map[string]*workflowservice.DescribeWorkflowExecutionResponse
	wakeID, cancelID string
}

func (c *findingStartBoundary) ExecuteWorkflow(ctx context.Context, o client.StartWorkflowOptions, name any, args ...any) (client.WorkflowRun, error) {
	if _, ok := ctx.Deadline(); !ok || len(args) != 1 {
		return nil, ErrInvalid
	}
	c.options = o
	c.name = name
	c.input = args[0].(StartRequest)
	if c.err != nil {
		return nil, c.err
	}
	return discoveryStartedRun{id: o.ID}, nil
}
func (c *findingStartBoundary) GetWorkflowHistory(ctx context.Context, id, run string, longPoll bool, filter enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	if _, ok := ctx.Deadline(); !ok || id != c.options.ID || longPoll {
		return &oneEvent{}
	}
	return &oneEvent{event: c.histories[run+filter.String()]}
}
func (c *findingStartBoundary) DescribeWorkflowExecution(ctx context.Context, id, run string) (*workflowservice.DescribeWorkflowExecutionResponse, error) {
	if _, ok := ctx.Deadline(); !ok || id != c.options.ID {
		return nil, ErrInvalid
	}
	return c.descriptions[run], c.describeErr
}
func (c *findingStartBoundary) SignalWorkflow(ctx context.Context, id, run, signal string, payload any) error {
	if _, ok := ctx.Deadline(); !ok || run != "" || signal != "finding-response-wake" || payload != nil {
		return ErrInvalid
	}
	c.wakeID = id
	return c.err
}
func (c *findingStartBoundary) CancelWorkflow(ctx context.Context, id, run string) error {
	if _, ok := ctx.Deadline(); !ok || run != "" {
		return ErrInvalid
	}
	c.cancelID = id
	return c.err
}
func findingStartedEvent(t *testing.T, kind, run, first, previous string, input any) *historypb.HistoryEvent {
	p, err := converter.GetDefaultDataConverter().ToPayloads(input)
	require.NoError(t, err)
	return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: kind}, TaskQueue: &taskqueuepb.TaskQueue{Name: "finding"}, OriginalExecutionRunId: run, FirstExecutionRunId: first, ContinuedExecutionRunId: previous}}}
}
func findingContinuedEvent(t *testing.T, next string, input FindingResponseCleanupContinuation) *historypb.HistoryEvent {
	p, err := converter.GetDefaultDataConverter().ToPayloads(input)
	require.NoError(t, err)
	return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionContinuedAsNewEventAttributes{WorkflowExecutionContinuedAsNewEventAttributes: &historypb.WorkflowExecutionContinuedAsNewEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: "FindingResponseCleanupWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "finding"}, NewExecutionRunId: next}}}
}
func findingDescription(id, run, first, kind string) *workflowservice.DescribeWorkflowExecutionResponse {
	return &workflowservice.DescribeWorkflowExecutionResponse{WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{Execution: &commonpb.WorkflowExecution{WorkflowId: id, RunId: run}, FirstRunId: first, Type: &commonpb.WorkflowType{Name: kind}, TaskQueue: "finding"}}
}

func TestFindingResponseStarterExactMapping(t *testing.T) {
	q := request()
	c := &findingStartBoundary{}
	s, err := NewFindingResponseStarter(c, "finding", time.Second)
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background(), q))
	want := "security-agent-finding/v1/" + q.Ref.OrganizationID + "/" + q.Ref.WorkspaceID + "/" + q.Ref.EnvironmentID + "/" + q.Ref.RunID
	require.Equal(t, want, c.options.ID)
	require.Equal(t, "finding", c.options.TaskQueue)
	require.Equal(t, "FindingResponseWorkflow", c.name)
	require.Equal(t, q, c.input)
	require.Equal(t, enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE, c.options.WorkflowIDReusePolicy)
	require.Equal(t, enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL, c.options.WorkflowIDConflictPolicy)
	require.True(t, c.options.WorkflowExecutionErrorWhenAlreadyStarted)
	require.Zero(t, c.options.WorkflowExecutionTimeout, "cleanup debt cannot expire with business execution")
	c.options = client.StartWorkflowOptions{}
	require.NoError(t, s.Wake(context.Background(), q))
	require.Equal(t, want, c.wakeID)
	require.NoError(t, s.Cancel(context.Background(), q))
	require.Equal(t, want, c.cancelID)
	require.Empty(t, c.options.ID, "wake/cancel must never start a workflow")
	c.err = serviceerror.NewNotFound("unknown")
	require.ErrorIs(t, s.Wake(context.Background(), q), ErrUnavailable)
	require.ErrorIs(t, s.Cancel(context.Background(), q), ErrUnavailable)
	for _, queue := range []string{"", " finding", strings.Repeat("q", 256)} {
		_, err = NewFindingResponseStarter(c, queue, time.Second)
		require.ErrorIs(t, err, ErrInvalid)
	}
	_, err = NewFindingResponseStarter(c, "finding", 31*time.Second)
	require.ErrorIs(t, err, ErrInvalid)
	bad := q
	bad.InputDigest = "bad"
	require.ErrorIs(t, s.Start(context.Background(), bad), ErrInvalid)
	require.ErrorIs(t, s.Wake(context.Background(), bad), ErrInvalid)
	require.ErrorIs(t, s.Cancel(context.Background(), bad), ErrInvalid)
	_, err = FindingResponseWorkflowID(RunRef{})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestFindingResponseStarterVerifiesRoot(t *testing.T) {
	q := request()
	id, _ := FindingResponseWorkflowID(q.Ref)
	for _, mutation := range []string{"matching", "request", "type", "queue", "run", "first", "continued", "description_scope", "missing_history", "unavailable_description"} {
		t.Run(mutation, func(t *testing.T) {
			event := findingStartedEvent(t, "FindingResponseWorkflow", "root", "root", "", q)
			d := findingDescription(id, "root", "root", "FindingResponseWorkflow")
			c := &findingStartBoundary{err: serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "root"), histories: map[string]*historypb.HistoryEvent{"root" + enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT.String(): event}, descriptions: map[string]*workflowservice.DescribeWorkflowExecutionResponse{"root": d}}
			a := event.GetWorkflowExecutionStartedEventAttributes()
			switch mutation {
			case "request":
				altered := q
				altered.InputDigest = strings.Repeat("b", 64)
				a.Input, _ = converter.GetDefaultDataConverter().ToPayloads(altered)
			case "type":
				a.WorkflowType.Name = "SingleTestWorkflow"
			case "queue":
				a.TaskQueue.Name = "foreign"
			case "run":
				a.OriginalExecutionRunId = "foreign"
			case "first":
				a.FirstExecutionRunId = "foreign"
			case "continued":
				a.ContinuedExecutionRunId = "foreign"
			case "description_scope":
				d.WorkflowExecutionInfo.Execution.WorkflowId = "foreign"
			case "missing_history":
				c.histories = nil
			case "unavailable_description":
				c.describeErr = ErrUnavailable
			}
			s, err := NewFindingResponseStarter(c, "finding", time.Second)
			require.NoError(t, err)
			err = s.Start(context.Background(), q)
			if mutation == "matching" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestFindingResponseStarterVerifiesEveryCleanupLink(t *testing.T) {
	q := request()
	id, _ := FindingResponseWorkflowID(q.Ref)
	state := FindingResponseCleanupContinuation{Start: q, BusinessDeadline: time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC), Reason: "workflow_cancelled", Outcome: "cancelled"}
	all, closed := enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT.String(), enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT.String()
	for _, mutation := range []string{"matching", "standalone", "root_request", "root_queue", "missing_root", "missing_middle", "broken_first_link", "broken_last_link", "middle_type", "middle_request", "changed_deadline", "cycle"} {
		t.Run(mutation, func(t *testing.T) {
			c := &findingStartBoundary{err: serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "latest"), histories: map[string]*historypb.HistoryEvent{
				"root" + all:    findingStartedEvent(t, "FindingResponseWorkflow", "root", "root", "", q),
				"middle" + all:  findingStartedEvent(t, "FindingResponseCleanupWorkflow", "middle", "root", "root", state),
				"latest" + all:  findingStartedEvent(t, "FindingResponseCleanupWorkflow", "latest", "root", "middle", state),
				"root" + closed: findingContinuedEvent(t, "middle", state), "middle" + closed: findingContinuedEvent(t, "latest", state),
			}, descriptions: map[string]*workflowservice.DescribeWorkflowExecutionResponse{"root": findingDescription(id, "root", "root", "FindingResponseWorkflow"), "middle": findingDescription(id, "middle", "root", "FindingResponseCleanupWorkflow"), "latest": findingDescription(id, "latest", "root", "FindingResponseCleanupWorkflow")}}
			switch mutation {
			case "standalone":
				c.histories["latest"+all] = findingStartedEvent(t, "FindingResponseCleanupWorkflow", "latest", "latest", "", state)
			case "root_request":
				altered := q
				altered.DefinitionVersion++
				c.histories["root"+all] = findingStartedEvent(t, "FindingResponseWorkflow", "root", "root", "", altered)
			case "root_queue":
				c.histories["root"+all].GetWorkflowExecutionStartedEventAttributes().TaskQueue.Name = "foreign"
			case "missing_root":
				delete(c.histories, "root"+all)
			case "missing_middle":
				delete(c.histories, "middle"+all)
			case "broken_first_link":
				c.histories["root"+closed] = findingContinuedEvent(t, "foreign", state)
			case "broken_last_link":
				c.histories["middle"+closed] = findingContinuedEvent(t, "foreign", state)
			case "middle_type":
				c.histories["middle"+all] = findingStartedEvent(t, "SingleTestWorkflow", "middle", "root", "root", state)
			case "middle_request":
				altered := state
				altered.Start.DefinitionVersion++
				c.histories["middle"+all] = findingStartedEvent(t, "FindingResponseCleanupWorkflow", "middle", "root", "root", altered)
			case "changed_deadline":
				altered := state
				altered.BusinessDeadline = altered.BusinessDeadline.Add(time.Hour)
				c.histories["latest"+all] = findingStartedEvent(t, "FindingResponseCleanupWorkflow", "latest", "root", "middle", altered)
			case "cycle":
				c.histories["middle"+all] = findingStartedEvent(t, "FindingResponseCleanupWorkflow", "middle", "root", "latest", state)
			}
			s, err := NewFindingResponseStarter(c, "finding", time.Second)
			require.NoError(t, err)
			err = s.Start(context.Background(), q)
			if mutation == "matching" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
