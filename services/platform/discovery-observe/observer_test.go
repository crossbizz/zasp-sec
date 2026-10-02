package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	schedulepb "go.temporal.io/api/schedule/v1"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	workflowpb "go.temporal.io/api/workflow/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type observerBoundary struct {
	t        *testing.T
	want     request
	schedule *workflowservice.DescribeScheduleResponse
	describe *workflowservice.DescribeWorkflowExecutionResponse
	history  *workflowservice.GetWorkflowExecutionHistoryResponse
	calls    []string
}

func (b *observerBoundary) DescribeSchedule(ctx context.Context, q *workflowservice.DescribeScheduleRequest, _ ...grpc.CallOption) (*workflowservice.DescribeScheduleResponse, error) {
	b.t.Helper()
	b.calls = append(b.calls, "schedule")
	if _, ok := ctx.Deadline(); !ok {
		b.t.Fatal("unbounded RPC")
	}
	id, _ := orchestration.DiscoveryScheduleID(b.want.Ref)
	if q.Namespace != b.want.Config.Namespace || q.ScheduleId != id {
		b.t.Fatal("foreign schedule request")
	}
	return b.schedule, nil
}
func (b *observerBoundary) DescribeWorkflowExecution(ctx context.Context, q *workflowservice.DescribeWorkflowExecutionRequest, _ ...grpc.CallOption) (*workflowservice.DescribeWorkflowExecutionResponse, error) {
	b.t.Helper()
	b.calls = append(b.calls, "describe")
	if _, ok := ctx.Deadline(); !ok {
		b.t.Fatal("unbounded RPC")
	}
	if q.Namespace != b.want.Config.Namespace || q.Execution.GetWorkflowId() != b.want.WorkflowID || q.Execution.GetRunId() != b.want.RunID {
		b.t.Fatal("foreign workflow request")
	}
	return b.describe, nil
}
func (b *observerBoundary) GetWorkflowExecutionHistory(ctx context.Context, q *workflowservice.GetWorkflowExecutionHistoryRequest, _ ...grpc.CallOption) (*workflowservice.GetWorkflowExecutionHistoryResponse, error) {
	b.t.Helper()
	b.calls = append(b.calls, "history")
	if _, ok := ctx.Deadline(); !ok {
		b.t.Fatal("unbounded RPC")
	}
	if q.Namespace != b.want.Config.Namespace || q.Execution.GetWorkflowId() != b.want.WorkflowID || q.Execution.GetRunId() != b.want.RunID || q.MaximumPageSize != 1 || q.WaitNewEvent || len(q.NextPageToken) != 0 {
		b.t.Fatal("history is not an exact bounded first-event read")
	}
	return b.history, nil
}
func observerRequest() request {
	return request{Format: "zasp-discovery-observation-request-v1", Config: runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "approved-test", TaskQueue: "agentsec-test", DiscoveryTaskQueue: "discovery-test", FGAURL: "http://127.0.0.1:8080", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/protected/fga-token", Timeout: 10 * time.Second}, Kind: "schedule", Ref: orchestration.DiscoveryScheduleRef{OrganizationID: "pid_10000001-0000-4000-8000-000000000001", WorkspaceID: "pid_10000002-0000-4000-8000-000000000002", EnvironmentID: "pid_10000003-0000-4000-8000-000000000003", ScheduleID: "pid_10000004-0000-4000-8000-000000000004", IntegrationID: "pid_10000005-0000-4000-8000-000000000005"}, Revision: 2}
}
func scheduleBoundary(t *testing.T) (request, *observerBoundary) {
	t.Helper()
	q := observerRequest()
	p, err := converter.GetDefaultDataConverter().ToPayloads(orchestration.DiscoveryScheduleStart{Ref: q.Ref, Revision: 2})
	if err != nil {
		t.Fatal(err)
	}
	b := &observerBoundary{t: t, want: q, schedule: &workflowservice.DescribeScheduleResponse{Schedule: &schedulepb.Schedule{Action: &schedulepb.ScheduleAction{Action: &schedulepb.ScheduleAction_StartWorkflow{StartWorkflow: &workflowpb.NewWorkflowExecutionInfo{WorkflowType: &commonpb.WorkflowType{Name: "DiscoveryScheduledWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "discovery-test"}, Input: p}}}, State: &schedulepb.ScheduleState{}}, Info: &schedulepb.ScheduleInfo{}, Memo: &commonpb.Memo{Fields: map[string]*commonpb.Payload{"must-not-output": {Data: []byte("canary-secret")}}}}}
	b.schedule.Schedule.Action.GetStartWorkflow().WorkflowId = "discovery-occurrence/v1/84a2699425b1bf532162de9719a0f50d48b829952ef0df4aaed24a4be3c3508a"
	b.schedule.Schedule.Spec = &schedulepb.ScheduleSpec{Interval: []*schedulepb.IntervalSpec{{Interval: durationpb.New(300 * time.Second), Phase: durationpb.New(0)}}}
	b.schedule.Schedule.Policies = &schedulepb.SchedulePolicies{OverlapPolicy: enumspb.SCHEDULE_OVERLAP_POLICY_ALLOW_ALL, CatchupWindow: durationpb.New(300 * time.Second)}
	return q, b
}

func TestObserverScheduleRejectsChangedCadenceOrPolicy(t *testing.T) {
	for _, mutate := range []func(*schedulepb.Schedule){
		func(s *schedulepb.Schedule) { s.Spec.Interval[0].Interval = durationpb.New(time.Minute) },
		func(s *schedulepb.Schedule) { s.Spec.Interval[0].Phase = durationpb.New(300 * time.Second) },
		func(s *schedulepb.Schedule) { s.Policies.OverlapPolicy = enumspb.SCHEDULE_OVERLAP_POLICY_SKIP },
		func(s *schedulepb.Schedule) { s.Policies.PauseOnFailure = true },
		func(s *schedulepb.Schedule) { s.Spec.CronString = []string{"* * * * *"} },
		func(s *schedulepb.Schedule) { s.Spec.Jitter = durationpb.New(time.Second) },
	} {
		q, b := scheduleBoundary(t)
		mutate(b.schedule.Schedule)
		if _, err := observe(context.Background(), q, b); !errors.Is(err, errRefused) {
			t.Fatal("changed schedule policy accepted")
		}
	}
}

func TestObserverConsumesOnlyBoundedFirstHistoryBatch(t *testing.T) {
	q, b := occurrenceBoundary(t)
	b.history.History.Events = append(b.history.History.Events, &historypb.HistoryEvent{EventId: 2, EventType: enumspb.EVENT_TYPE_WORKFLOW_TASK_SCHEDULED})
	if _, err := observe(context.Background(), q, b); err != nil {
		t.Fatal("valid first-event batch rejected")
	}
	for len(b.history.History.Events) <= 16 {
		b.history.History.Events = append(b.history.History.Events, &historypb.HistoryEvent{EventId: int64(len(b.history.History.Events) + 1)})
	}
	if _, err := observe(context.Background(), q, b); !errors.Is(err, errRefused) {
		t.Fatal("oversized batch accepted")
	}
}
func occurrenceBoundary(t *testing.T) (request, *observerBoundary) {
	t.Helper()
	q, b := scheduleBoundary(t)
	q.Kind = "occurrence"
	q.WorkflowID = "discovery-occurrence/v1/84a2699425b1bf532162de9719a0f50d48b829952ef0df4aaed24a4be3c3508a-2026-09-27T00:00:00Z"
	q.RunID = "00000000-0000-4000-8000-000000000001"
	b.want = q
	id, _ := orchestration.DiscoveryScheduleID(q.Ref)
	dc := converter.GetDefaultDataConverter()
	by, _ := dc.ToPayload(id)
	due, _ := dc.ToPayload(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC))
	b.describe = &workflowservice.DescribeWorkflowExecutionResponse{WorkflowExecutionInfo: &workflowpb.WorkflowExecutionInfo{Execution: &commonpb.WorkflowExecution{WorkflowId: q.WorkflowID, RunId: q.RunID}, Type: &commonpb.WorkflowType{Name: "DiscoveryScheduledWorkflow"}, TaskQueue: "discovery-test", Status: enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED}}
	b.history = &workflowservice.GetWorkflowExecutionHistoryResponse{History: &historypb.History{Events: []*historypb.HistoryEvent{{EventId: 1, EventType: enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED, EventTime: timestamppb.Now(), Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{WorkflowType: &commonpb.WorkflowType{Name: "DiscoveryScheduledWorkflow"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "discovery-test"}, OriginalExecutionRunId: q.RunID, FirstExecutionRunId: q.RunID, Input: b.schedule.Schedule.Action.GetStartWorkflow().Input, SearchAttributes: &commonpb.SearchAttributes{IndexedFields: map[string]*commonpb.Payload{"TemporalScheduledById": by, "TemporalScheduledStartTime": due}}}}}}}, NextPageToken: []byte("private-continuation-never-output")}
	return q, b
}
func TestObserverScheduleProducesOnlyBoundFacts(t *testing.T) {
	q, b := scheduleBoundary(t)
	o, err := observe(context.Background(), q, b)
	if err != nil {
		t.Fatalf("valid exact schedule refused: %v", err)
	}
	if o.Revision != 2 || o.TaskQueue != "discovery-test" || o.Kind != "schedule" || len(b.calls) != 1 {
		t.Fatal("wrong schedule facts")
	}
	raw, _ := json.Marshal(o)
	if strings.Contains(string(raw), "canary") || strings.Contains(string(raw), "protected") {
		t.Fatal("private response escaped projection")
	}
}
func TestObserverOccurrenceBindsActualFirstEvent(t *testing.T) {
	q, b := occurrenceBoundary(t)
	o, err := observe(context.Background(), q, b)
	if err != nil {
		t.Fatalf("valid occurrence refused: %v", err)
	}
	if o.Status != int32(enumspb.WORKFLOW_EXECUTION_STATUS_COMPLETED) || len(o.Executions) != 1 || o.Executions[0].RunID != q.RunID || strings.Join(b.calls, ",") != "describe,history" {
		t.Fatal("wrong actual occurrence facts")
	}
	raw, _ := json.Marshal(o)
	if strings.Contains(string(raw), "private-continuation") {
		t.Fatal("history token escaped")
	}
}
func TestObserverRejectsForeignOrUnboundedEvidence(t *testing.T) {
	for _, mutate := range []func(*request, *observerBoundary){
		func(q *request, b *observerBoundary) { q.Config.Namespace = "" },
		func(q *request, b *observerBoundary) { q.Revision = 0 },
		func(q *request, b *observerBoundary) { q.Kind = "list" },
		func(q *request, b *observerBoundary) {
			b.schedule.Schedule.Action.GetStartWorkflow().TaskQueue.Name = "foreign"
		},
		func(q *request, b *observerBoundary) {
			b.schedule.Schedule.Action.GetStartWorkflow().Input.Payloads[0].Data = []byte(`{"ref":{},"revision":2}`)
		},
		func(q *request, b *observerBoundary) {
			b.schedule.Memo.Fields["must-not-output"].Data = make([]byte, 262145)
		},
	} {
		q, b := scheduleBoundary(t)
		mutate(&q, b)
		if _, err := observe(context.Background(), q, b); !errors.Is(err, errRefused) {
			t.Fatal("invalid schedule accepted")
		}
	}
	for _, mutate := range []func(*observerBoundary){
		func(b *observerBoundary) { b.describe.WorkflowExecutionInfo.Execution.RunId = "foreign" },
		func(b *observerBoundary) { b.history.History.Events[0].EventId = 2 },
		func(b *observerBoundary) {
			b.history.History.Events[0].GetWorkflowExecutionStartedEventAttributes().SearchAttributes = nil
		},
		func(b *observerBoundary) {
			b.history.History.Events[0].GetWorkflowExecutionStartedEventAttributes().ContinuedExecutionRunId = "foreign"
		},
		func(b *observerBoundary) {
			b.history.History.Events = append(b.history.History.Events, b.history.History.Events[0])
		},
	} {
		q, b := occurrenceBoundary(t)
		mutate(b)
		if _, err := observe(context.Background(), q, b); !errors.Is(err, errRefused) {
			t.Fatal("invalid occurrence accepted")
		}
	}
	q, b := scheduleBoundary(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observe(ctx, q, b); !errors.Is(err, errRefused) || len(b.calls) != 0 {
		t.Fatal("cancelled observer performed RPC")
	}
}
