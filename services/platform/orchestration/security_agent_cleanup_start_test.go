package orchestration

import (
	"context"
	"errors"
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

type orderedCleanupStartBoundary struct {
	boundaryClient
	histories map[string]*historypb.HistoryEvent
}

func (c *orderedCleanupStartBoundary) GetWorkflowHistory(ctx context.Context, id, run string, long bool, filter enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	want, _ := WorkflowID(request().Ref)
	if _, ok := ctx.Deadline(); !ok || id != want || long {
		return &oneEvent{}
	}
	return &oneEvent{event: c.histories[run+filter.String()]}
}

// The business outbox can replay while the logical run is cleaning up. Only
// the immutable original request and server-linked cleanup chain justify Ack.
func TestOrderedStartVerifiesCleanupContinuation(t *testing.T) {
	q := request()
	s := SecurityAgentCleanupContinuation{Start: q, BusinessDeadline: time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC), Reason: "workflow_cancelled", Outcome: "cancelled"}
	start := func(kind, run, first, previous string, input any) *historypb.HistoryEvent {
		p, _ := converter.GetDefaultDataConverter().ToPayloads(input)
		return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p, WorkflowType: &commonpb.WorkflowType{Name: kind}, TaskQueue: &taskqueuepb.TaskQueue{Name: "ordered"}, OriginalExecutionRunId: run, FirstExecutionRunId: first, ContinuedExecutionRunId: previous}}}
	}
	close := func(next string, input SecurityAgentCleanupContinuation) *historypb.HistoryEvent {
		p, _ := converter.GetDefaultDataConverter().ToPayloads(input)
		return &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionContinuedAsNewEventAttributes{WorkflowExecutionContinuedAsNewEventAttributes: &historypb.WorkflowExecutionContinuedAsNewEventAttributes{NewExecutionRunId: next, Input: p, WorkflowType: &commonpb.WorkflowType{Name: "SecurityAgentCleanupWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "ordered"}}}}
	}
	all, closed := enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT.String(), enumspb.HISTORY_EVENT_FILTER_TYPE_CLOSE_EVENT.String()
	for _, mode := range []string{"valid", "first", "standalone", "foreign_scope", "changed_deadline", "changed_reason", "wrong_predecessor", "wrong_queue", "wrong_root_type", "missing_root", "missing_predecessor"} {
		t.Run(mode, func(t *testing.T) {
			c := &orderedCleanupStartBoundary{histories: map[string]*historypb.HistoryEvent{
				"latest" + all:  start("SecurityAgentCleanupWorkflow", "latest", "root", "middle", s),
				"root" + all:    start("SecurityAgentWorkflow", "root", "root", "", q),
				"root" + closed: close("middle", s), "middle" + closed: close("latest", s),
			}}
			c.startErr = serviceerror.NewWorkflowExecutionAlreadyStarted("already", "request", "latest")
			e, _ := NewTemporalEngine(c, "ordered", time.Second)
			switch mode {
			case "first":
				c.histories["latest"+all] = start("SecurityAgentCleanupWorkflow", "latest", "root", "root", s)
				c.histories["root"+closed] = close("latest", s)
			case "standalone":
				c.histories["latest"+all] = start("SecurityAgentCleanupWorkflow", "latest", "latest", "", s)
			case "foreign_scope":
				foreign := s
				foreign.Start.Ref.OrganizationID = testRef.WorkspaceID
				c.histories["latest"+all] = start("SecurityAgentCleanupWorkflow", "latest", "root", "middle", foreign)
			case "changed_deadline":
				changed := s
				changed.BusinessDeadline = changed.BusinessDeadline.Add(time.Second)
				c.histories["middle"+closed] = close("latest", changed)
			case "changed_reason":
				changed := s
				changed.Reason, changed.Outcome = "workflow_failed", "failed"
				c.histories["root"+closed] = close("middle", changed)
			case "wrong_predecessor":
				c.histories["middle"+closed] = close("foreign", s)
			case "wrong_queue":
				c.histories["latest"+all].GetWorkflowExecutionStartedEventAttributes().TaskQueue.Name = "other"
			case "wrong_root_type":
				c.histories["root"+all].GetWorkflowExecutionStartedEventAttributes().WorkflowType.Name = "SingleTestWorkflow"
			case "missing_root":
				delete(c.histories, "root"+all)
			case "missing_predecessor":
				delete(c.histories, "middle"+closed)
			}
			err := e.Start(context.Background(), q)
			if mode == "valid" || mode == "first" {
				if err != nil {
					t.Fatalf("accepted cleanup replay refused: %v", err)
				}
			} else if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unproven cleanup replay accepted: %v", err)
			}
		})
	}
}
