package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	schedulepb "go.temporal.io/api/schedule/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/converter"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

var errRefused = errors.New("discovery observation refused")

// The observer has no mutation or listing interface. It observes an exact
// scoped identity supplied after public product admission; it grants nothing.
type readService interface {
	DescribeSchedule(context.Context, *workflowservice.DescribeScheduleRequest, ...grpc.CallOption) (*workflowservice.DescribeScheduleResponse, error)
	DescribeWorkflowExecution(context.Context, *workflowservice.DescribeWorkflowExecutionRequest, ...grpc.CallOption) (*workflowservice.DescribeWorkflowExecutionResponse, error)
	GetWorkflowExecutionHistory(context.Context, *workflowservice.GetWorkflowExecutionHistoryRequest, ...grpc.CallOption) (*workflowservice.GetWorkflowExecutionHistoryResponse, error)
}

type request struct {
	Format     string                             `json:"format"`
	Config     runtimeservices.Config             `json:"config"`
	Kind       string                             `json:"kind"`
	Ref        orchestration.DiscoveryScheduleRef `json:"ref"`
	Revision   int64                              `json:"revision"`
	WorkflowID string                             `json:"workflow_id"`
	RunID      string                             `json:"run_id"`
}

type executionFact struct {
	WorkflowID  string    `json:"workflow_id"`
	RunID       string    `json:"run_id"`
	ScheduledAt time.Time `json:"scheduled_at"`
}
type observation struct {
	Format     string          `json:"format"`
	Kind       string          `json:"kind"`
	ScheduleID string          `json:"schedule_id"`
	Revision   int64           `json:"revision"`
	TaskQueue  string          `json:"task_queue"`
	Paused     bool            `json:"paused"`
	Executions []executionFact `json:"executions"`
	Status     int32           `json:"status"`
}

func observe(ctx context.Context, q request, service readService) (observation, error) {
	refuse := func() (observation, error) { return observation{}, errRefused }
	if ctx == nil || ctx.Err() != nil || service == nil {
		return refuse()
	}
	id, prefix, err := requestIdentity(q)
	if err != nil {
		return refuse()
	}
	bounded, cancel := context.WithTimeout(ctx, q.Config.Timeout)
	defer cancel()
	out := observation{Format: "zasp-discovery-observation-v1", Kind: q.Kind, ScheduleID: id, Revision: q.Revision, TaskQueue: q.Config.DiscoveryTaskQueue, Executions: []executionFact{}}
	if q.Kind == "schedule" {
		r, err := service.DescribeSchedule(bounded, &workflowservice.DescribeScheduleRequest{Namespace: q.Config.Namespace, ScheduleId: id}, grpc.MaxCallRecvMsgSize(262144))
		if err != nil || bounded.Err() != nil || r == nil || proto.Size(r) > 262144 || r.Schedule == nil || r.Schedule.State == nil || r.Info == nil || len(r.Info.RecentActions) > 16 {
			return refuse()
		}
		a := r.Schedule.GetAction().GetStartWorkflow()
		if a == nil || a.WorkflowId != prefix || a.GetWorkflowType().GetName() != "DiscoveryScheduledWorkflow" || a.GetTaskQueue().GetName() != q.Config.DiscoveryTaskQueue || !scheduleInput(a.Input, q) || !fixedSchedule(r.Schedule) {
			return refuse()
		}
		out.Paused = r.Schedule.State.Paused
		for _, action := range r.Info.RecentActions {
			e := action.GetStartWorkflowResult()
			at := action.GetScheduleTime()
			if e == nil || !validExecution(e.WorkflowId, e.RunId, prefix) || at == nil || at.CheckValid() != nil || at.AsTime().Unix() < 0 {
				return refuse()
			}
			out.Executions = append(out.Executions, executionFact{WorkflowID: e.WorkflowId, RunID: e.RunId, ScheduledAt: at.AsTime().UTC()})
		}
		if bounded.Err() != nil {
			return refuse()
		}
		return out, nil
	}
	execution := &commonpb.WorkflowExecution{WorkflowId: q.WorkflowID, RunId: q.RunID}
	d, err := service.DescribeWorkflowExecution(bounded, &workflowservice.DescribeWorkflowExecutionRequest{Namespace: q.Config.Namespace, Execution: execution}, grpc.MaxCallRecvMsgSize(262144))
	if err != nil || bounded.Err() != nil || d == nil || proto.Size(d) > 262144 {
		return refuse()
	}
	i := d.GetWorkflowExecutionInfo()
	if i == nil || i.GetExecution().GetWorkflowId() != q.WorkflowID || i.GetExecution().GetRunId() != q.RunID || i.GetType().GetName() != "DiscoveryScheduledWorkflow" || i.TaskQueue != q.Config.DiscoveryTaskQueue || i.Status < enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING || i.Status > enumspb.WORKFLOW_EXECUTION_STATUS_TIMED_OUT {
		return refuse()
	}
	h, err := service.GetWorkflowExecutionHistory(bounded, &workflowservice.GetWorkflowExecutionHistoryRequest{Namespace: q.Config.Namespace, Execution: execution, MaximumPageSize: 1, WaitNewEvent: false, HistoryEventFilterType: enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT}, grpc.MaxCallRecvMsgSize(262144))
	if err != nil || bounded.Err() != nil || h == nil || proto.Size(h) > 262144 || len(h.GetHistory().GetEvents()) < 1 || len(h.GetHistory().GetEvents()) > 16 {
		return refuse()
	}
	// Temporal may return a stored event batch despite the requested page size.
	// Never follow its continuation token; only the first start is consumed.
	for index, event := range h.History.Events {
		if event == nil || event.EventId != int64(index+1) {
			return refuse()
		}
	}
	e := h.History.Events[0]
	a := e.GetWorkflowExecutionStartedEventAttributes()
	if e.EventId != 1 || e.EventType != enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED || a == nil || a.OriginalExecutionRunId != q.RunID || a.FirstExecutionRunId != q.RunID || a.ContinuedExecutionRunId != "" || a.GetWorkflowType().GetName() != "DiscoveryScheduledWorkflow" || a.GetTaskQueue().GetName() != q.Config.DiscoveryTaskQueue || !scheduleInput(a.Input, q) {
		return refuse()
	}
	attrs := a.GetSearchAttributes().GetIndexedFields()
	by, due := attrs["TemporalScheduledById"], attrs["TemporalScheduledStartTime"]
	if by == nil || due == nil || proto.Size(by) > 4096 || proto.Size(due) > 4096 {
		return refuse()
	}
	var actualID string
	var at time.Time
	dc := converter.GetDefaultDataConverter()
	if dc.FromPayload(by, &actualID) != nil || dc.FromPayload(due, &at) != nil || actualID != id || at.IsZero() || at.Unix() < 0 {
		return refuse()
	}
	out.Status = int32(i.Status)
	out.Executions = []executionFact{{WorkflowID: q.WorkflowID, RunID: q.RunID, ScheduledAt: at.UTC()}}
	if bounded.Err() != nil {
		return refuse()
	}
	return out, nil
}

func fixedSchedule(s *schedulepb.Schedule) bool {
	if s.Spec == nil || s.Policies == nil || len(s.Spec.Interval) != 1 || len(s.Spec.Calendar) != 0 || len(s.Spec.StructuredCalendar) != 0 || len(s.Spec.CronString) != 0 || len(s.Spec.ExcludeCalendar) != 0 || len(s.Spec.ExcludeStructuredCalendar) != 0 || s.Spec.EndTime != nil || s.Spec.TimezoneName != "" || len(s.Spec.TimezoneData) != 0 {
		return false
	}
	i := s.Spec.Interval[0]
	if i == nil || i.Interval == nil || i.Interval.CheckValid() != nil || i.Interval.AsDuration() != 300*time.Second {
		return false
	}
	if i.Phase != nil && (i.Phase.CheckValid() != nil || i.Phase.AsDuration() < 0 || i.Phase.AsDuration() >= 300*time.Second) {
		return false
	}
	if s.Spec.Jitter != nil && (s.Spec.Jitter.CheckValid() != nil || s.Spec.Jitter.AsDuration() != 0) {
		return false
	}
	p := s.Policies
	return p.OverlapPolicy == enumspb.SCHEDULE_OVERLAP_POLICY_ALLOW_ALL && p.CatchupWindow != nil && p.CatchupWindow.CheckValid() == nil && p.CatchupWindow.AsDuration() == 300*time.Second && !p.PauseOnFailure
}

func requestIdentity(q request) (string, string, error) {
	if q.Format != "zasp-discovery-observation-request-v1" || !q.Config.Enabled || q.Config.Validate() != nil || q.Config.Timeout > 10*time.Second || q.Revision < 1 || q.Revision > 1000000 {
		return "", "", errRefused
	}
	id, err := orchestration.DiscoveryScheduleID(q.Ref)
	if err != nil {
		return "", "", errRefused
	}
	digest := sha256.Sum256([]byte(id))
	prefix := "discovery-occurrence/v1/" + hex.EncodeToString(digest[:])
	if q.Kind != "schedule" && q.Kind != "occurrence" || q.Kind == "schedule" && (q.WorkflowID != "" || q.RunID != "") || q.Kind == "occurrence" && !validExecution(q.WorkflowID, q.RunID, prefix) {
		return "", "", errRefused
	}
	return id, prefix, nil
}

var runIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var occurrenceSuffix = regexp.MustCompile(`^[-/][0-9TZ:.+-]{1,64}$`)

func validExecution(workflowID, runID, prefix string) bool {
	return runIDPattern.MatchString(runID) && strings.HasPrefix(workflowID, prefix) && occurrenceSuffix.MatchString(strings.TrimPrefix(workflowID, prefix))
}
func scheduleInput(payloads *commonpb.Payloads, q request) bool {
	if payloads == nil || len(payloads.Payloads) != 1 || proto.Size(payloads) > 4096 {
		return false
	}
	var input orchestration.DiscoveryScheduleStart
	return converter.GetDefaultDataConverter().FromPayloads(payloads, &input) == nil && input.Ref == q.Ref && input.Revision == q.Revision
}
