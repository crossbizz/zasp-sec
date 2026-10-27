package orchestration

import (
	"context"
	"errors"
	"regexp"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
)

var retentionQueuePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)

func RetentionScheduleOptions(queue string) (client.ScheduleOptions, error) {
	if !retentionQueuePattern.MatchString(queue) {
		return client.ScheduleOptions{}, ErrInvalid
	}
	return client.ScheduleOptions{
		ID:      RetentionScheduleID,
		Spec:    client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: time.Hour}}},
		Action:  &client.ScheduleWorkflowAction{ID: RetentionWorkflowPrefix, Workflow: "RetentionScheduledWorkflow", TaskQueue: queue, WorkflowExecutionTimeout: 10 * time.Minute, WorkflowRunTimeout: 10 * time.Minute, WorkflowTaskTimeout: 10 * time.Second},
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP, CatchupWindow: time.Minute,
	}, nil
}

// EnsureRetentionSchedule creates only the fixed application schedule. Existing
// mismatched or paused schedules refuse; startup never overwrites operator state.
func EnsureRetentionSchedule(ctx context.Context, transport DiscoveryScheduleClient, queue string, timeout time.Duration) error {
	options, err := RetentionScheduleOptions(queue)
	if err != nil || ctx == nil || ctx.Err() != nil || transport == nil || timeout <= 0 || timeout > 30*time.Second {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err = transport.Create(bounded, options)
	if err == nil {
		if bounded.Err() != nil {
			return ErrScheduleOutcomeUnknown
		}
		return nil
	}
	if !errors.Is(err, temporal.ErrScheduleAlreadyRunning) {
		return ErrScheduleOutcomeUnknown
	}
	return CheckRetentionSchedule(bounded, transport, queue, timeout)
}

// CheckRetentionSchedule only reads operator state. Readiness never recreates a
// deleted schedule or overwrites pause, cadence, or action changes.
func CheckRetentionSchedule(ctx context.Context, transport DiscoveryScheduleClient, queue string, timeout time.Duration) error {
	options, err := RetentionScheduleOptions(queue)
	if err != nil || ctx == nil || ctx.Err() != nil || transport == nil || timeout <= 0 || timeout > 30*time.Second {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	handle := transport.GetHandle(bounded, RetentionScheduleID)
	if handle == nil {
		return ErrUnavailable
	}
	description, err := handle.Describe(bounded)
	if err != nil || bounded.Err() != nil || description == nil {
		return ErrScheduleOutcomeUnknown
	}
	schedule := description.Schedule
	action, ok := schedule.Action.(*client.ScheduleWorkflowAction)
	if !ok || action == nil {
		return ErrConflict
	}
	want := options.Action.(*client.ScheduleWorkflowAction)
	// Describe materializes empty argument and metadata collections. Compare the
	// application contract semantically while refusing every nondefault override.
	if !retentionScheduleActionMatches(action, want) || !retentionScheduleSpecMatches(schedule.Spec) || schedule.Policy == nil || schedule.Policy.Overlap != options.Overlap || schedule.Policy.CatchupWindow != options.CatchupWindow || schedule.Policy.PauseOnFailure || schedule.State == nil || schedule.State.Paused || schedule.State.LimitedActions {
		return ErrConflict
	}
	return nil
}

func retentionScheduleActionMatches(action, want *client.ScheduleWorkflowAction) bool {
	name, ok := action.Workflow.(string)
	return ok && name == want.Workflow && action.ID == want.ID && action.TaskQueue == want.TaskQueue &&
		action.WorkflowExecutionTimeout == want.WorkflowExecutionTimeout && action.WorkflowRunTimeout == want.WorkflowRunTimeout && action.WorkflowTaskTimeout == want.WorkflowTaskTimeout &&
		len(action.Args) == 0 && len(action.Memo) == 0 && len(action.TypedSearchAttributes.GetUntypedValues()) == 0 && len(action.UntypedSearchAttributes) == 0 &&
		action.RetryPolicy == nil && action.VersioningOverride == nil && action.StaticSummary == "" && action.StaticDetails == "" && action.Priority == want.Priority
}

func retentionScheduleSpecMatches(spec *client.ScheduleSpec) bool {
	return spec != nil && len(spec.Intervals) == 1 && spec.Intervals[0].Every == time.Hour && spec.Intervals[0].Offset == 0 &&
		len(spec.Calendars) == 0 && len(spec.CronExpressions) == 0 && len(spec.Skip) == 0 && spec.StartAt.IsZero() && spec.EndAt.IsZero() && spec.Jitter == 0 &&
		(spec.TimeZoneName == "" || spec.TimeZoneName == "UTC")
}
