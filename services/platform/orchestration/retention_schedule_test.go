package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
)

type retentionScheduleFixture struct {
	client.ScheduleClient
	client.ScheduleHandle
	options     client.ScheduleOptions
	description *client.ScheduleDescription
	exists      bool
	bounded     bool
	createErr   error
}

func (f *retentionScheduleFixture) Create(ctx context.Context, options client.ScheduleOptions) (client.ScheduleHandle, error) {
	_, f.bounded = ctx.Deadline()
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.exists {
		return nil, temporal.ErrScheduleAlreadyRunning
	}
	f.options = options
	f.description = &client.ScheduleDescription{Schedule: client.Schedule{Action: options.Action, Spec: &options.Spec, Policy: &client.SchedulePolicies{Overlap: options.Overlap, CatchupWindow: options.CatchupWindow}, State: &client.ScheduleState{}}}
	f.exists = true
	return f, nil
}
func (f *retentionScheduleFixture) GetHandle(context.Context, string) client.ScheduleHandle { return f }
func (f *retentionScheduleFixture) Describe(context.Context) (*client.ScheduleDescription, error) {
	return f.description, nil
}

func TestRetentionScheduleActualRecurringContract(t *testing.T) {
	fixture := &retentionScheduleFixture{}
	require.NoError(t, EnsureRetentionSchedule(context.Background(), fixture, "retention", time.Second))
	require.True(t, fixture.bounded)
	require.Equal(t, RetentionScheduleID, fixture.options.ID)
	require.Equal(t, time.Hour, fixture.options.Spec.Intervals[0].Every)
	require.Equal(t, enumspb.SCHEDULE_OVERLAP_POLICY_SKIP, fixture.options.Overlap)
	action := fixture.options.Action.(*client.ScheduleWorkflowAction)
	require.Empty(t, action.Args)
	require.Equal(t, "RetentionScheduledWorkflow", action.Workflow)
	require.Equal(t, 10*time.Minute, action.WorkflowExecutionTimeout)
	require.NoError(t, EnsureRetentionSchedule(context.Background(), fixture, "retention", time.Second), "exact schedule survives restart without overwrite")
	for _, kind := range []string{"workflow", "queue", "input", "timeout", "cadence", "overlap", "paused", "limited", "missing_description", "transport"} {
		t.Run(kind, func(t *testing.T) {
			f := &retentionScheduleFixture{}
			require.NoError(t, EnsureRetentionSchedule(context.Background(), f, "retention", time.Second))
			a := f.description.Schedule.Action.(*client.ScheduleWorkflowAction)
			switch kind {
			case "workflow":
				a.Workflow = "OtherWorkflow"
			case "queue":
				a.TaskQueue = "unrelated"
			case "input":
				a.Args = []any{map[string]string{"tenant": "PRIVATE"}}
			case "timeout":
				a.WorkflowExecutionTimeout = time.Hour
			case "cadence":
				f.description.Schedule.Spec.Intervals[0].Every = time.Second
			case "overlap":
				f.description.Schedule.Policy.Overlap = enumspb.SCHEDULE_OVERLAP_POLICY_ALLOW_ALL
			case "paused":
				f.description.Schedule.State.Paused = true
			case "limited":
				f.description.Schedule.State.LimitedActions = true
			case "missing_description":
				f.description = nil
			case "transport":
				f.createErr = errors.New("PRIVATE")
			}
			err := EnsureRetentionSchedule(context.Background(), f, "retention", time.Second)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "PRIVATE")
		})
	}
}

// Describe returns empty decoded collections even when Create omitted them.
// This fixture tests the application's schedule admission contract, not SDK internals.
func TestRetentionScheduleDescribedSemanticContract(t *testing.T) {
	normalized := func(t *testing.T) *retentionScheduleFixture {
		t.Helper()
		f := &retentionScheduleFixture{}
		require.NoError(t, EnsureRetentionSchedule(context.Background(), f, "retention", time.Second))
		a := f.description.Schedule.Action.(*client.ScheduleWorkflowAction)
		a.Args = []interface{}{}
		a.Memo = map[string]interface{}{}
		a.TypedSearchAttributes = temporal.NewSearchAttributes()
		a.UntypedSearchAttributes = map[string]*commonpb.Payload{}
		f.description.Schedule.Spec.Calendars = []client.ScheduleCalendarSpec{}
		f.description.Schedule.Spec.Skip = []client.ScheduleCalendarSpec{}
		f.description.Schedule.Spec.CronExpressions = []string{}
		return f
	}
	for _, zone := range []string{"", "UTC"} {
		f := normalized(t)
		f.description.Schedule.Spec.TimeZoneName = zone
		require.NoError(t, EnsureRetentionSchedule(context.Background(), f, "retention", time.Second), "empty decoded values preserve the original schedule")
	}
	for _, kind := range []string{"id", "run_timeout", "task_timeout", "memo", "typed_attributes", "untyped_attributes", "retry", "versioning", "summary", "details", "priority", "fairness", "weight", "calendar", "cron", "skip", "offset", "start", "end", "jitter", "timezone", "pause_on_failure", "catchup"} {
		t.Run(kind, func(t *testing.T) {
			f := normalized(t)
			s := &f.description.Schedule
			a := s.Action.(*client.ScheduleWorkflowAction)
			switch kind {
			case "id":
				a.ID = "unrelated"
			case "run_timeout":
				a.WorkflowRunTimeout = time.Hour
			case "task_timeout":
				a.WorkflowTaskTimeout = time.Minute
			case "memo":
				a.Memo["private"] = "unwanted"
			case "typed_attributes":
				a.TypedSearchAttributes = temporal.NewSearchAttributes(temporal.NewSearchAttributeKeyKeyword("private").ValueSet("unwanted"))
			case "untyped_attributes":
				a.UntypedSearchAttributes["private"] = &commonpb.Payload{}
			case "retry":
				a.RetryPolicy = &temporal.RetryPolicy{}
			case "versioning":
				a.VersioningOverride = &client.AutoUpgradeVersioningOverride{}
			case "summary":
				a.StaticSummary = "unwanted"
			case "details":
				a.StaticDetails = "unwanted"
			case "priority":
				a.Priority.PriorityKey = 1
			case "fairness":
				a.Priority.FairnessKey = "unwanted"
			case "weight":
				a.Priority.FairnessWeight = 2
			case "calendar":
				s.Spec.Calendars = []client.ScheduleCalendarSpec{{}}
			case "cron":
				s.Spec.CronExpressions = []string{"@hourly"}
			case "skip":
				s.Spec.Skip = []client.ScheduleCalendarSpec{{}}
			case "offset":
				s.Spec.Intervals[0].Offset = time.Minute
			case "start":
				s.Spec.StartAt = time.Now()
			case "end":
				s.Spec.EndAt = time.Now()
			case "jitter":
				s.Spec.Jitter = time.Minute
			case "timezone":
				s.Spec.TimeZoneName = "Europe/Berlin"
			case "pause_on_failure":
				s.Policy.PauseOnFailure = true
			case "catchup":
				s.Policy.CatchupWindow = time.Hour
			}
			require.ErrorIs(t, EnsureRetentionSchedule(context.Background(), f, "retention", time.Second), ErrConflict)
		})
	}
}

func TestRetentionScheduleReadinessOnlyDescribes(t *testing.T) {
	fixture := &retentionScheduleFixture{}
	require.NoError(t, EnsureRetentionSchedule(context.Background(), fixture, "retention", time.Second))
	fixture.createErr = errors.New("readiness must not create")
	require.NoError(t, CheckRetentionSchedule(context.Background(), fixture, "retention", time.Second))
	fixture.description.Schedule.State.Paused = true
	require.ErrorIs(t, CheckRetentionSchedule(context.Background(), fixture, "retention", time.Second), ErrConflict)
}
