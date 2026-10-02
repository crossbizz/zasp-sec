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
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

type singleTestStartBoundary struct {
	client.Client
	original            StartRequest
	options             client.StartWorkflowOptions
	err                 error
	kind, queue, wakeID string
	histories           map[string]*historypb.HistoryEvent
}

func (c *singleTestStartBoundary) CancelWorkflow(ctx context.Context, id, run string) error {
	if _, ok := ctx.Deadline(); !ok || run != "" {
		return ErrInvalid
	}
	c.wakeID = id
	return c.err
}

func TestSingleTestCancelNeverStartsOrTreatsNotFoundAsDelivered(t *testing.T) {
	q := request()
	c := &singleTestStartBoundary{}
	e, _ := NewTemporalEngine(c, "single-test", time.Second)
	id, _ := SingleTestWorkflowID(q.Ref)
	if err := e.CancelSingleTest(context.Background(), q); err != nil || c.wakeID != id || c.options.ID != "" {
		t.Fatal("exact existing cancellation", err, c.wakeID, c.options)
	}
	for _, failed := range []error{serviceerror.NewNotFound("closed or unavailable"), context.DeadlineExceeded} {
		c.err = failed
		if err := e.CancelSingleTest(context.Background(), q); !errors.Is(err, ErrUnavailable) || c.options.ID != "" {
			t.Fatal("ambiguous cancellation acknowledged/started", err, c.options)
		}
	}
}

func (c *singleTestStartBoundary) ExecuteWorkflow(ctx context.Context, o client.StartWorkflowOptions, name interface{}, args ...interface{}) (client.WorkflowRun, error) {
	if _, ok := ctx.Deadline(); !ok || name != "SingleTestWorkflow" || len(args) != 1 {
		return nil, ErrInvalid
	}
	c.options = o
	if c.err != nil {
		return nil, c.err
	}
	return discoveryStartedRun{id: o.ID}, nil
}
func (c *singleTestStartBoundary) GetWorkflowHistory(_ context.Context, id, run string, _ bool, filter enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	if c.histories != nil {
		return &oneEvent{event: c.histories[run+filter.String()]}
	}
	if id != c.options.ID || run != "execution-0001" {
		return &oneEvent{}
	}
	p, _ := converter.GetDefaultDataConverter().ToPayloads(c.original)
	return &oneEvent{event: &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: c.kind}, TaskQueue: &taskqueuepb.TaskQueue{Name: c.queue}, OriginalExecutionRunId: run, FirstExecutionRunId: run}}}}
}

func TestSingleTestStartVerifiesCleanupContinuationChain(t *testing.T) {
	q := request()
	s := SingleTestCleanupContinuation{Start: q, BusinessDeadline: time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC), Reason: "workflow_cancelled", Outcome: "cancelled"}
	startEvent := func(kind, run, first, previous string, input any) *historypb.HistoryEvent {
		p, _ := converter.GetDefaultDataConverter().ToPayloads(input)
		return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: kind}, TaskQueue: &taskqueuepb.TaskQueue{Name: "single-test"}, OriginalExecutionRunId: run, FirstExecutionRunId: first, ContinuedExecutionRunId: previous}}}
	}
	closeEvent := func(next string, input SingleTestCleanupContinuation) *historypb.HistoryEvent {
		p, _ := converter.GetDefaultDataConverter().ToPayloads(input)
		return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionContinuedAsNewEventAttributes{WorkflowExecutionContinuedAsNewEventAttributes: &historypb.WorkflowExecutionContinuedAsNewEventAttributes{NewExecutionRunId: next, Input: p, WorkflowType: &commonpb.WorkflowType{Name: "SingleTestCleanupWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "single-test"}}}}
	}
	all, closed := enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT.String(), enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT.String()
	c := &singleTestStartBoundary{err: serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "latest"), histories: map[string]*historypb.HistoryEvent{"latest" + all: startEvent("SingleTestCleanupWorkflow", "latest", "root", "middle", s), "root" + all: startEvent("SingleTestWorkflow", "root", "root", "", q), "root" + closed: closeEvent("middle", s), "middle" + closed: closeEvent("latest", s)}}
	e, _ := NewTemporalEngine(c, "single-test", time.Second)
	if err := e.StartSingleTest(context.Background(), q); err != nil {
		t.Fatal("legitimate cleanup chain replay", err)
	}
	for _, mutation := range []string{"standalone", "wrong_link", "changed_deadline", "missing_root", "foreign_start"} {
		t.Run(mutation, func(t *testing.T) {
			saved := c.histories
			c.histories = map[string]*historypb.HistoryEvent{}
			for k, v := range saved {
				c.histories[k] = v
			}
			defer func() { c.histories = saved }()
			switch mutation {
			case "standalone":
				c.histories["latest"+all] = startEvent("SingleTestCleanupWorkflow", "latest", "latest", "", s)
			case "wrong_link":
				c.histories["middle"+closed] = closeEvent("foreign", s)
			case "changed_deadline":
				altered := s
				altered.BusinessDeadline = altered.BusinessDeadline.Add(time.Hour)
				c.histories["latest"+all] = startEvent("SingleTestCleanupWorkflow", "latest", "root", "middle", altered)
			case "missing_root":
				delete(c.histories, "root"+all)
			case "foreign_start":
				foreign := q
				foreign.InputDigest = strings.Repeat("f", 64)
				c.histories["root"+all] = startEvent("SingleTestWorkflow", "root", "root", "", foreign)
			}
			if err := e.StartSingleTest(context.Background(), q); err == nil {
				t.Fatal("unproved continuation accepted")
			}
		})
	}
}
func (c *singleTestStartBoundary) SignalWorkflow(ctx context.Context, id, run, signal string, arg interface{}) error {
	if _, ok := ctx.Deadline(); !ok || run != "" || signal != "single-test-wake" || arg != nil {
		return ErrInvalid
	}
	c.wakeID = id
	return c.err
}
func TestSingleTestStartAndWakeIdentity(t *testing.T) {
	q := request()
	c := &singleTestStartBoundary{original: q, kind: "SingleTestWorkflow", queue: "single-test"}
	e, err := NewTemporalEngine(c, "single-test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := any(e).(interface {
		StartSingleTest(context.Context, StartRequest) error
		WakeSingleTest(context.Context, StartRequest) error
	})
	if !ok {
		t.Fatal("specialized start/wake boundary missing")
	}
	if err := s.StartSingleTest(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	want := "security-agent-test/v1/" + q.Ref.OrganizationID + "/" + q.Ref.WorkspaceID + "/" + q.Ref.EnvironmentID + "/" + q.Ref.RunID
	if c.options.ID != want || c.options.WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE || c.options.WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL || !c.options.WorkflowExecutionErrorWhenAlreadyStarted {
		t.Fatal("unsafe single-test identity", c.options)
	}
	c.err = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "execution-0001")
	if err := s.StartSingleTest(context.Background(), q); err != nil {
		t.Fatal("exact repeat", err)
	}
	c.kind = "SecurityAgentWorkflow"
	if err := s.StartSingleTest(context.Background(), q); !errors.Is(err, ErrConflict) {
		t.Fatal("ordered workflow impersonated specialized execution", err)
	}
	c.kind = "SingleTestWorkflow"
	c.queue = "foreign"
	if err := s.StartSingleTest(context.Background(), q); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign queue accepted", err)
	}
	c.queue = "single-test"
	c.original.InputDigest = strings.Repeat("f", 64)
	if err := s.StartSingleTest(context.Background(), q); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting input accepted")
	}
	c.original = q
	c.err = nil
	if err := s.WakeSingleTest(context.Background(), q); err != nil || c.wakeID != want {
		t.Fatal("wake must target exact existing identity", err, c.wakeID)
	}
	c.err = context.DeadlineExceeded
	if err := s.WakeSingleTest(context.Background(), q); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ambiguous signal acknowledged", err)
	}
}
