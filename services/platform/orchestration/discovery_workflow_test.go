package orchestration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

func discoveryDesired() DiscoveryScheduleDesired {
	return DiscoveryScheduleDesired{Ref: DiscoveryScheduleRef{OrganizationID: testRef.OrganizationID, WorkspaceID: testRef.WorkspaceID, EnvironmentID: testRef.EnvironmentID, ScheduleID: "pid_00000000-0000-4000-8000-000000000008", IntegrationID: "pid_00000000-0000-4000-8000-000000000009"}, Revision: 4, CadenceSeconds: 300, Anchor: time.Date(2026, 9, 22, 10, 2, 0, 0, time.UTC), Enabled: true}
}

// Only the external SDK transport is doubled. Removing tenant identity or
// mapping disable to unpause must fail on the requests emitted by our adapter.
func TestDiscoveryScheduleReconciliation(t *testing.T) {
	d := discoveryDesired()
	source := &scheduleSourceFixture{desired: d}
	transport := &scheduleTransportFixture{}
	reconciler, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
	require.NoError(t, err)
	require.NoError(t, reconciler.Reconcile(context.Background(), d.Ref))
	first := transport.options
	require.Equal(t, "discovery-schedule/v1/"+testRef.OrganizationID+"/"+testRef.WorkspaceID+"/"+testRef.EnvironmentID+"/"+d.Ref.ScheduleID+"/"+d.Ref.IntegrationID, first.ID)
	require.Equal(t, enumspb.SCHEDULE_OVERLAP_POLICY_ALLOW_ALL, first.Overlap)
	require.Equal(t, 300*time.Second, first.CatchupWindow)
	require.False(t, first.TriggerImmediately)
	require.Empty(t, first.ScheduleBackfill)
	require.False(t, first.Paused)
	require.Equal(t, 120*time.Second, first.Spec.Intervals[0].Offset)
	require.Equal(t, 300*time.Second, first.Spec.Intervals[0].Every)
	require.Equal(t, d.Anchor, first.Spec.StartAt)
	require.True(t, transport.bounded)

	// Duplicate change delivery reads current state. The event carries only IDs.
	transport.exists = true
	source.desired.Enabled = false
	source.desired.Revision++
	require.NoError(t, reconciler.Reconcile(context.Background(), d.Ref))
	require.True(t, transport.schedule.State.Paused)
	require.NoError(t, reconciler.Reconcile(context.Background(), d.Ref))
	require.True(t, transport.schedule.State.Paused)

	// Identical connector and schedule IDs in a second tenant stay separate.
	other := d
	other.Ref.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
	source.desired, transport.exists = other, false
	require.NoError(t, reconciler.Reconcile(context.Background(), other.Ref))
	require.NotEqual(t, first.ID, transport.options.ID)
}

func TestDiscoveryScheduleRefusesStaleForeignAndUnknownWrites(t *testing.T) {
	for _, name := range []string{"stale", "foreign", "source_mismatch", "timeout", "cancelled", "malformed"} {
		t.Run(name, func(t *testing.T) {
			d := discoveryDesired()
			source := &scheduleSourceFixture{desired: d}
			transport := &scheduleTransportFixture{}
			r, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
			require.NoError(t, err)
			require.NoError(t, r.Reconcile(context.Background(), d.Ref))
			transport.exists = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "stale":
				source.desired.Revision--
			case "foreign":
				transport.schedule.Action.(*client.ScheduleWorkflowAction).Args = []interface{}{DiscoveryScheduleStart{Ref: DiscoveryScheduleRef{}}}
			case "source_mismatch":
				source.desired.Ref.IntegrationID = d.Ref.ScheduleID
			case "timeout":
				transport.updateErr = context.DeadlineExceeded
			case "cancelled":
				cancel()
			case "malformed":
				source.desired.CadenceSeconds = 0
			}
			err = r.Reconcile(ctx, d.Ref)
			require.Error(t, err)
			if name == "timeout" {
				require.ErrorIs(t, err, ErrScheduleOutcomeUnknown)
			}
			require.Equal(t, 0, transport.updates)
		})
	}
}

// The full scoped schedule identity stays authoritative even though Temporal's
// workflow ID prefix must leave room for its appended nominal timestamp.
func TestDiscoveryScheduleCompactActionAndExactLegacyRepair(t *testing.T) {
	for _, change := range []string{"own", "legacy", "legacy_foreign", "collision_input", "foreign_queue", "foreign_type", "prefix_only"} {
		t.Run(change, func(t *testing.T) {
			d := discoveryDesired()
			source := &scheduleSourceFixture{desired: d}
			transport := &scheduleTransportFixture{}
			r, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
			require.NoError(t, err)
			require.NoError(t, r.Reconcile(context.Background(), d.Ref))
			id := transport.options.ID
			want := fmt.Sprintf("discovery-occurrence/v1/%x", sha256.Sum256([]byte(id)))
			action := transport.schedule.Action.(*client.ScheduleWorkflowAction)
			require.Equal(t, want, action.ID)
			require.LessOrEqual(t, len(action.ID)+len("-2026-09-23T18:35:55.123456789Z"), 255)
			transport.exists = true
			switch change {
			case "legacy", "legacy_foreign":
				action.ID = id + "/occurrence"
			case "foreign_queue":
				action.TaskQueue = "other"
			case "foreign_type":
				action.Workflow = "OtherWorkflow"
			case "prefix_only":
				action.ID = id + "/occurrence/foreign"
			}
			if change == "collision_input" || change == "legacy_foreign" {
				foreign := d.Ref
				foreign.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
				action.Args = []interface{}{DiscoveryScheduleStart{Ref: foreign, Revision: d.Revision}}
			}
			err = r.Reconcile(context.Background(), d.Ref)
			if change != "own" && change != "legacy" {
				require.ErrorIs(t, err, ErrConflict)
				require.Zero(t, transport.updates)
				return
			}
			require.NoError(t, err)
			require.Equal(t, want, transport.schedule.Action.(*client.ScheduleWorkflowAction).ID)
			source.desired.Ref.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
			transport.exists = false
			require.NoError(t, r.Reconcile(context.Background(), source.desired.Ref))
			require.NotEqual(t, want, transport.schedule.Action.(*client.ScheduleWorkflowAction).ID)
		})
	}
}

func TestDiscoveryWorkflowSettlesFailedPageAuthorityFromEvidence(t *testing.T) {
	for _, outcome := range []string{"incomplete", "outcome_unknown"} {
		t.Run(outcome, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			start := discoveryStart()
			deadline := time.Now().UTC().Add(time.Hour)
			start.Continuation = &DiscoveryContinuation{CheckpointVersion: 1, ReceiptDigest: strings.Repeat("b", 64), Deadline: deadline}
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryPageCommand) (DiscoveryPage, error) {
				return DiscoveryPage{}, temporal.NewNonRetryableApplicationError("current authority refused", "refused", nil)
			}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
			reconciled := 0
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryReconcile) (DiscoveryResult, error) {
				reconciled++
				require.Equal(t, "activity_failed", q.Reason)
				require.Equal(t, deadline, q.Deadline)
				return DiscoveryResult{Outcome: outcome}, nil
			}, activity.RegisterOptions{Name: "ReconcileDiscoveryOutcome"})
			env.ExecuteWorkflow(DiscoveryWorkflow, start)
			require.NoError(t, env.GetWorkflowError())
			var result DiscoveryResult
			require.NoError(t, env.GetWorkflowResult(&result))
			require.Equal(t, outcome, result.Outcome)
			require.Equal(t, 1, reconciled)
		})
	}
}

func TestDiscoveryScheduleChangeDuringReconcileRequiresRedelivery(t *testing.T) {
	d := discoveryDesired()
	source := &scheduleSourceFixture{desired: d}
	transport := &scheduleTransportFixture{afterWrite: func() { source.desired.Enabled = false; source.desired.Revision++ }}
	r, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
	require.NoError(t, err)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	// A config write after the scoped read is not an atomic cross-store disable.
	// P4B's durable change delivery must cause this next reconciliation.
	require.False(t, transport.options.Paused)
	transport.afterWrite, transport.exists = nil, true
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.True(t, transport.schedule.State.Paused)
}

type scheduleSourceFixture struct {
	desired      DiscoveryScheduleDesired
	dueErr       error
	dueCalls     int
	nextDue, now time.Time
	admissions   []time.Time
}

func (s *scheduleSourceFixture) WithCurrentSchedule(ctx context.Context, ref DiscoveryScheduleRef, fn func(DiscoveryScheduleDesired) error) error {
	return fn(s.desired)
}

func (s *scheduleSourceFixture) ReconcileDiscoveryDue(ctx context.Context, ref DiscoveryScheduleRef) error {
	s.dueCalls++
	if s.dueErr != nil {
		return s.dueErr
	}
	if s.nextDue.IsZero() || !s.desired.Enabled {
		return nil
	}
	plan, due, err := PlanDiscoveryDue(s.nextDue, s.now, s.desired.CadenceSeconds)
	if err != nil {
		return err
	}
	if due {
		s.admissions = append(s.admissions, plan.DueAt)
		s.nextDue = plan.NextDueAt
	}
	return nil
}

func TestDiscoveryOutageCoalescesOldestDueAndReconciliationRepair(t *testing.T) {
	d := discoveryDesired()
	d.CadenceSeconds = 86400
	source := &scheduleSourceFixture{desired: d, nextDue: d.Anchor, now: d.Anchor.Add(time.Hour), dueErr: ErrUnavailable}
	transport := &scheduleTransportFixture{}
	r, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
	require.NoError(t, err)
	// RPC acknowledged but due-admission repair failed: change remains pending.
	require.Error(t, r.Reconcile(context.Background(), d.Ref))
	require.Empty(t, source.admissions)
	require.GreaterOrEqual(t, transport.options.CatchupWindow, time.Hour)
	transport.exists = true
	source.dueErr = nil
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.Equal(t, []time.Time{d.Anchor}, source.admissions)
	require.Equal(t, d.Anchor.Add(24*time.Hour), source.nextDue)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.Len(t, source.admissions, 1, "duplicate wakeups must not start another run")
	// Several missed cadences still produce one oldest outstanding occurrence.
	source.now = d.Anchor.Add(73 * time.Hour)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.Equal(t, []time.Time{d.Anchor, d.Anchor.Add(24 * time.Hour)}, source.admissions)
	require.Equal(t, d.Anchor.Add(96*time.Hour), source.nextDue)
	// A recreated Schedule uses the same persisted due state for startup repair.
	transport.exists = false
	source.now = d.Anchor.Add(100 * time.Hour)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.Equal(t, d.Anchor.Add(96*time.Hour), source.admissions[2])
	require.Equal(t, d.Anchor.Add(120*time.Hour), source.nextDue)
	require.Equal(t, 5, source.dueCalls)
}

func TestDiscoveryDuePolicyRejectsInvalidAndFutureDue(t *testing.T) {
	due := discoveryDesired().Anchor
	plan, ready, err := PlanDiscoveryDue(due, due.Add(-time.Second), 86400)
	require.NoError(t, err)
	require.False(t, ready)
	require.True(t, plan.DueAt.IsZero())
	_, _, err = PlanDiscoveryDue(due, due, 0)
	require.Error(t, err)
	plan, ready, err = PlanDiscoveryDue(due, due, 300)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, due, plan.DueAt)
	require.Equal(t, due.Add(5*time.Minute), plan.NextDueAt)
}

type scheduleTransportFixture struct {
	client.ScheduleClient
	client.ScheduleHandle
	options         client.ScheduleOptions
	schedule        client.Schedule
	exists, bounded bool
	updates         int
	updateErr       error
	afterWrite      func()
}

func (s *scheduleTransportFixture) Create(ctx context.Context, o client.ScheduleOptions) (client.ScheduleHandle, error) {
	_, s.bounded = ctx.Deadline()
	if s.exists {
		return nil, temporal.ErrScheduleAlreadyRunning
	}
	s.options = o
	s.schedule = client.Schedule{Action: o.Action, Spec: &o.Spec, Policy: &client.SchedulePolicies{Overlap: o.Overlap, CatchupWindow: o.CatchupWindow}, State: &client.ScheduleState{Paused: o.Paused}}
	// Describe/Update returns encoded payloads, not the original Go argument.
	a := s.schedule.Action.(*client.ScheduleWorkflowAction)
	p, err := converter.GetDefaultDataConverter().ToPayload(a.Args[0])
	if err != nil {
		return nil, err
	}
	a.Args = []interface{}{p}
	if s.afterWrite != nil {
		s.afterWrite()
	}
	return s, nil
}
func (s *scheduleTransportFixture) GetHandle(context.Context, string) client.ScheduleHandle { return s }
func (s *scheduleTransportFixture) Update(ctx context.Context, o client.ScheduleUpdateOptions) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	u, err := o.DoUpdate(client.ScheduleUpdateInput{Description: client.ScheduleDescription{Schedule: s.schedule}})
	if err != nil {
		return err
	}
	s.schedule = *u.Schedule
	s.updates++
	return nil
}

func discoveryStart() DiscoveryStart {
	return DiscoveryStart{Ref: testRef, IntegrationID: discoveryDesired().Ref.IntegrationID, InputDigest: strings.Repeat("a", 64)}
}

// A known-safe retry gets a new product receipt precondition, not a resend of
// the old page command. The cursor itself stays private in product SQL.
func TestDiscoveryRetryConsumesAdvancingProductReceipt(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid_%t", invalid), func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			calls := 0
			var second DiscoveryPageCommand
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryPageCommand) (DiscoveryPage, error) {
				calls++
				if calls == 1 {
					version := int64(1)
					if invalid {
						version = 0
					}
					return DiscoveryPage{Outcome: "retryable", CheckpointVersion: version, ReceiptDigest: strings.Repeat("c", 64), RetryAfterSeconds: 1}, nil
				}
				second = q
				return DiscoveryPage{Outcome: "denied"}, nil
			}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryFinish) error { return nil }, activity.RegisterOptions{Name: "FinishDiscovery"})
			env.ExecuteWorkflow(DiscoveryWorkflow, discoveryStart())
			if invalid {
				require.Error(t, env.GetWorkflowError())
				require.Equal(t, 1, calls)
			} else {
				require.NoError(t, env.GetWorkflowError())
				require.Equal(t, 2, calls)
				require.Equal(t, int64(1), second.ExpectedCheckpointVersion)
				require.Equal(t, strings.Repeat("c", 64), second.ExpectedCheckpointDigest)
			}
		})
	}
}

// Deadline expiry must prevent new apply, bound waits/Activity budgets, and use
// durable evidence reconciliation for an uncertain apply. Product responses are
// controlled; real late receipt/persistence proof remains P4B.
func TestDiscoveryOriginalDeadlineBoundsFreshWorkAndSettlesEvidence(t *testing.T) {
	for _, name := range []string{"late_complete", "late_retryable", "retry_wait", "apply_unknown", "apply_committed", "late_apply_receipt"} {
		t.Run(name, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
			env.SetStartTime(now)
			s := discoveryStart()
			s.Continuation = &DiscoveryContinuation{CheckpointVersion: 1, ReceiptDigest: strings.Repeat("b", 64), Deadline: now.Add(time.Second)}
			applies, reconciles := 0, 0
			var freshBudgets []time.Duration
			env.SetOnActivityStartedListener(func(info *activity.Info, _ context.Context, _ converter.EncodedValues) {
				if info.ActivityType.Name == "CollectDiscoveryPage" || info.ActivityType.Name == "ApplyDiscoverySnapshot" {
					freshBudgets = append(freshBudgets, info.ScheduleToCloseTimeout, info.StartToCloseTimeout)
				}
			})
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryPageCommand) (DiscoveryPage, error) { return DiscoveryPage{}, nil }, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
			page := DiscoveryPage{Outcome: "complete", CheckpointVersion: 2, ReceiptDigest: strings.Repeat("c", 64)}
			if name == "late_retryable" || name == "retry_wait" {
				page = DiscoveryPage{Outcome: "retryable", CheckpointVersion: 2, ReceiptDigest: strings.Repeat("c", 64), RetryAfterSeconds: 60}
			}
			env.RegisterActivityWithOptions(func(context.Context, map[string]any) (string, error) {
				applies++
				if strings.HasPrefix(name, "apply_") {
					return "", temporal.NewTimeoutError(enumspb.TIMEOUT_TYPE_START_TO_CLOSE, nil)
				}
				return strings.Repeat("d", 64), nil
			}, activity.RegisterOptions{Name: "ApplyDiscoverySnapshot"})
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryFinish) error { return nil }, activity.RegisterOptions{Name: "FinishDiscovery"})
			env.RegisterActivityWithOptions(func(_ context.Context, q map[string]any) (DiscoveryResult, error) {
				reconciles++
				require.Equal(t, "2026-09-23T10:00:01Z", q["deadline"])
				switch name {
				case "apply_unknown":
					return DiscoveryResult{Outcome: "outcome_unknown"}, nil
				case "apply_committed", "late_apply_receipt":
					return DiscoveryResult{Outcome: "succeeded", ReceiptDigest: strings.Repeat("d", 64)}, nil
				default:
					return DiscoveryResult{Outcome: "incomplete"}, nil
				}
			}, activity.RegisterOptions{Name: "ReconcileDiscoveryOutcome"})
			call := env.OnActivity("CollectDiscoveryPage", mock.Anything, mock.Anything).Return(page, nil)
			if name == "late_complete" || name == "late_retryable" {
				call.After(2 * time.Second)
			}
			if name == "late_apply_receipt" {
				env.OnActivity("ApplyDiscoverySnapshot", mock.Anything, mock.Anything).After(2 * time.Second).Return(
					func(context.Context, map[string]any) (string, error) { applies++; return strings.Repeat("d", 64), nil })
			}
			env.ExecuteWorkflow(DiscoveryWorkflow, s)
			require.NoError(t, env.GetWorkflowError())
			var result DiscoveryResult
			require.NoError(t, env.GetWorkflowResult(&result))
			require.Equal(t, 1, reconciles)
			if strings.HasPrefix(name, "apply_") || name == "late_apply_receipt" {
				require.Equal(t, 1, applies, "ambiguous application must not resend")
				if name == "apply_unknown" {
					require.Equal(t, "outcome_unknown", result.Outcome)
				} else {
					require.Equal(t, "succeeded", result.Outcome)
					require.Equal(t, strings.Repeat("d", 64), result.ReceiptDigest)
				}
			} else {
				require.Zero(t, applies, "fresh apply after deadline")
				require.Equal(t, "incomplete", result.Outcome)
			}
			require.NotEmpty(t, freshBudgets)
			for _, budget := range freshBudgets {
				require.LessOrEqual(t, budget, time.Second)
			}
			if name == "retry_wait" {
				require.Equal(t, time.Second, env.Now().Sub(now))
			}
		})
	}
}

func TestDiscoveryScheduleProjectsNonEarlyWholeSecondWakeup(t *testing.T) {
	for _, tc := range []struct {
		name, anchor, wakeup string
		offset               time.Duration
	}{
		{"whole", "2026-09-22T12:02:00Z", "2026-09-22T12:02:00Z", 120 * time.Second},
		{"fractional", "2026-09-22T12:02:00.123456Z", "2026-09-22T12:02:01Z", 121 * time.Second},
		{"cadence rollover", "2026-09-22T12:04:59.999999Z", "2026-09-22T12:05:00Z", 0},
		{"epoch", "1970-01-01T00:00:00.000001Z", "1970-01-01T00:00:01Z", time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := discoveryDesired()
			d.Anchor, _ = time.Parse(time.RFC3339Nano, tc.anchor)
			source := &scheduleSourceFixture{desired: d}
			transport := &scheduleTransportFixture{}
			r, err := NewDiscoveryScheduleReconciler(transport, source, "discovery", time.Second)
			require.NoError(t, err)
			require.NoError(t, r.Reconcile(context.Background(), d.Ref))
			wake, _ := time.Parse(time.RFC3339Nano, tc.wakeup)
			require.Equal(t, tc.offset, transport.options.Spec.Intervals[0].Offset)
			require.Equal(t, wake, transport.options.Spec.StartAt)
			require.Equal(t, d.Anchor, source.desired.Anchor)
		})
	}
	d := discoveryDesired()
	d.Anchor = time.Unix(-1, 999999999).UTC()
	transport := &scheduleTransportFixture{}
	r, _ := NewDiscoveryScheduleReconciler(transport, &scheduleSourceFixture{desired: d}, "discovery", time.Second)
	require.Error(t, r.Reconcile(context.Background(), d.Ref))
}

func TestDiscoveryWorkflowCancellationRecordsTypedProductOutcome(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	finished := ""
	env.RegisterActivityWithOptions(func(context.Context, DiscoveryPageCommand) (DiscoveryPage, error) {
		return DiscoveryPage{Outcome: "retryable", CheckpointVersion: 1, ReceiptDigest: strings.Repeat("c", 64), RetryAfterSeconds: 60}, nil
	}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
	env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryReconcile) (DiscoveryResult, error) {
		finished = q.Reason
		return DiscoveryResult{Outcome: "cancelled"}, nil
	}, activity.RegisterOptions{Name: "ReconcileDiscoveryOutcome"})
	env.RegisterDelayedCallback(env.CancelWorkflow, time.Second)
	env.ExecuteWorkflow(DiscoveryWorkflow, discoveryStart())
	require.Error(t, env.GetWorkflowError())
	require.Equal(t, "cancelled", finished)
}

func TestDiscoveryWorkflowRejectsForeignScheduledAdmission(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	d := discoveryDesired()
	id, err := DiscoveryScheduleID(d.Ref)
	require.NoError(t, err)
	require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": id, "TemporalScheduledStartTime": d.Anchor}))
	env.RegisterActivityWithOptions(func(context.Context, DiscoveryOccurrence) (DiscoveryAdmission, error) {
		s := discoveryStart()
		s.Ref.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
		return DiscoveryAdmission{Outcome: "admitted", Start: &s}, nil
	}, activity.RegisterOptions{Name: "AdmitDiscoveryScheduled"})
	// No collection Activity is registered: crossing the boundary is a failure.
	env.ExecuteWorkflow(DiscoveryScheduledWorkflow, DiscoveryScheduleStart{Ref: d.Ref, Revision: d.Revision})
	require.ErrorContains(t, env.GetWorkflowError(), "DiscoveryContractRefused")
}

func TestDiscoveryWorkflowIdentityAndMissingScheduleEvidence(t *testing.T) {
	a := discoveryStart()
	first, err := DiscoveryWorkflowID(a)
	require.NoError(t, err)
	b := a
	b.Ref.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
	second, err := DiscoveryWorkflowID(b)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	b = a
	b.Ref.RunID = "pid_00000000-0000-4000-8000-000000000011"
	second, err = DiscoveryWorkflowID(b)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	d := discoveryDesired()
	env.ExecuteWorkflow(DiscoveryScheduledWorkflow, DiscoveryScheduleStart{Ref: d.Ref, Revision: d.Revision})
	require.ErrorContains(t, env.GetWorkflowError(), "DiscoveryContractRefused")
}

func TestDiscoveryWorkflowLargeInventoryContinuesWithCheckpoint(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	started := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	env.SetStartTime(started)
	count := int64(0)
	env.RegisterActivityWithOptions(func(_ context.Context, s DiscoveryPageCommand) (DiscoveryPage, error) {
		require.Equal(t, discoveryStart(), s.Start)
		count++
		return DiscoveryPage{Outcome: "partial", CheckpointVersion: count, ReceiptDigest: strings.Repeat("b", 64)}, nil
	}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
	env.ExecuteWorkflow(DiscoveryWorkflow, discoveryStart())
	var continuation *workflow.ContinueAsNewError
	require.True(t, errors.As(env.GetWorkflowError(), &continuation), "page volume must continue, not fail inventory")
	require.Equal(t, int64(256), count)
	var next map[string]any
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continuation.Input, &next))
	checkpoint := next["continuation"].(map[string]any)
	require.Equal(t, float64(256), checkpoint["checkpoint_version"])
	require.Equal(t, strings.Repeat("b", 64), checkpoint["receipt_digest"])
	require.Equal(t, "2026-09-23T10:00:00Z", checkpoint["deadline"])

	resumed := suite.NewTestWorkflowEnvironment()
	resumed.SetStartTime(started.Add(time.Hour))
	resumed.RegisterActivityWithOptions(func(_ context.Context, s DiscoveryPageCommand) (DiscoveryPage, error) {
		// Continuation is a workflow hint, not provider authority or cursor input.
		require.Equal(t, discoveryStart(), s.Start)
		require.Equal(t, int64(256), s.ExpectedCheckpointVersion)
		require.Equal(t, strings.Repeat("b", 64), s.ExpectedCheckpointDigest)
		return DiscoveryPage{Outcome: "complete", CheckpointVersion: 257, ReceiptDigest: strings.Repeat("c", 64)}, nil
	}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
	resumed.RegisterActivityWithOptions(func(context.Context, DiscoveryApplyCommand) (string, error) { return strings.Repeat("d", 64), nil }, activity.RegisterOptions{Name: "ApplyDiscoverySnapshot"})
	resumed.RegisterActivityWithOptions(func(context.Context, DiscoveryFinish) error { return nil }, activity.RegisterOptions{Name: "FinishDiscovery"})
	var resumedStart DiscoveryStart
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continuation.Input, &resumedStart))
	resumed.ExecuteWorkflow(DiscoveryWorkflow, resumedStart)
	require.NoError(t, resumed.GetWorkflowError())
	var result DiscoveryResult
	require.NoError(t, resumed.GetWorkflowResult(&result))
	require.Equal(t, "succeeded", result.Outcome)
}

func TestDiscoveryWorkflowBindsPageCommandToCheckpointReceipt(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	var commands []map[string]any
	env.RegisterActivityWithOptions(func(_ context.Context, q map[string]any) (DiscoveryPage, error) {
		commands = append(commands, q)
		if len(commands) == 1 {
			return DiscoveryPage{Outcome: "partial", CheckpointVersion: 7, ReceiptDigest: strings.Repeat("b", 64)}, nil
		}
		return DiscoveryPage{Outcome: "revoked"}, nil
	}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
	env.RegisterActivityWithOptions(func(context.Context, DiscoveryFinish) error { return nil }, activity.RegisterOptions{Name: "FinishDiscovery"})
	env.ExecuteWorkflow(DiscoveryWorkflow, discoveryStart())
	require.NoError(t, env.GetWorkflowError())
	require.Len(t, commands, 2)
	require.Equal(t, float64(0), commands[0]["expected_checkpoint_version"])
	require.Equal(t, "", commands[0]["expected_checkpoint_digest"])
	require.Equal(t, float64(7), commands[1]["expected_checkpoint_version"])
	require.Equal(t, strings.Repeat("b", 64), commands[1]["expected_checkpoint_digest"])
	require.Equal(t, commands[0]["start"], commands[1]["start"])
	require.NotNil(t, commands[0]["start"])
}

// A repeated checkpoint must never authorize complete inventory. This fixture
// returns only product receipts; it is not a SQL/provider test.
func TestDiscoveryWorkflowCheckpointAndTerminalContracts(t *testing.T) {
	for _, outcome := range []string{"complete", "incomplete", "denied", "revoked", "malformed", "cancelled", "outcome_unknown", "terminal", "repeated_checkpoint", "unknown_state"} {
		t.Run(outcome, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			calls, applied, finished := 0, 0, ""
			start := discoveryStart()
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryPageCommand) (DiscoveryPage, error) {
				require.Equal(t, start, q.Start)
				calls++
				if calls == 1 || outcome == "repeated_checkpoint" {
					return DiscoveryPage{Outcome: "partial", CheckpointVersion: 1, ReceiptDigest: strings.Repeat("b", 64)}, nil
				}
				return DiscoveryPage{Outcome: outcome, CheckpointVersion: 2, ReceiptDigest: strings.Repeat("c", 64)}, nil
			}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryApplyCommand) (string, error) {
				require.Equal(t, start, q.Start)
				require.Equal(t, strings.Repeat("c", 64), q.CompleteReceiptDigest)
				applied++
				return strings.Repeat("d", 64), nil
			}, activity.RegisterOptions{Name: "ApplyDiscoverySnapshot"})
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryFinish) error {
				require.Equal(t, start, q.Start)
				finished = q.Outcome
				return nil
			}, activity.RegisterOptions{Name: "FinishDiscovery"})
			env.ExecuteWorkflow(DiscoveryWorkflow, start)
			if outcome == "repeated_checkpoint" || outcome == "unknown_state" {
				require.Error(t, env.GetWorkflowError())
				require.Zero(t, applied)
				require.NotEqual(t, "succeeded", finished)
				return
			}
			require.NoError(t, env.GetWorkflowError())
			var result DiscoveryResult
			require.NoError(t, env.GetWorkflowResult(&result))
			if outcome == "complete" {
				require.Equal(t, 1, applied)
				require.Equal(t, "succeeded", result.Outcome)
				require.Equal(t, strings.Repeat("d", 64), result.ReceiptDigest)
			} else {
				require.Zero(t, applied)
				require.Equal(t, outcome, result.Outcome)
			}
			require.Equal(t, result.Outcome, finished)
		})
	}
}

func TestDiscoveryScheduledWorkflowUsesExactOccurrenceAndAdmission(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "admitted", true: "revoked"}[deny], func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			d := discoveryDesired()
			due := d.Anchor
			id, err := DiscoveryScheduleID(d.Ref)
			require.NoError(t, err)
			require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": id, "TemporalScheduledStartTime": due}))
			admitted, collected := 0, 0
			env.RegisterActivityWithOptions(func(_ context.Context, q DiscoveryOccurrence) (DiscoveryAdmission, error) {
				admitted++
				require.Equal(t, d.Ref, q.Schedule.Ref)
				require.Equal(t, d.Revision, q.Schedule.Revision)
				require.Equal(t, due, q.DueAt)
				if deny {
					return DiscoveryAdmission{}, temporal.NewNonRetryableApplicationError("revoked", "DiscoveryRevoked", nil)
				}
				start := discoveryStart()
				return DiscoveryAdmission{Outcome: "admitted", Start: &start}, nil
			}, activity.RegisterOptions{Name: "AdmitDiscoveryScheduled"})
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryPageCommand) (DiscoveryPage, error) {
				collected++
				return DiscoveryPage{Outcome: "revoked"}, nil
			}, activity.RegisterOptions{Name: "CollectDiscoveryPage"})
			env.RegisterActivityWithOptions(func(context.Context, DiscoveryFinish) error { return nil }, activity.RegisterOptions{Name: "FinishDiscovery"})
			env.ExecuteWorkflow(DiscoveryScheduledWorkflow, DiscoveryScheduleStart{Ref: d.Ref, Revision: d.Revision})
			require.Equal(t, 1, admitted)
			if deny {
				require.Error(t, env.GetWorkflowError())
				require.Zero(t, collected)
			} else {
				require.NoError(t, env.GetWorkflowError())
				require.Zero(t, collected, "admission outbox is the sole collection start route")
				var result DiscoveryResult
				require.NoError(t, env.GetWorkflowResult(&result))
				require.Equal(t, "admitted", result.Outcome)
			}
		})
	}
}

func TestDiscoveryScheduledDuplicateWakeupDoesNotCollect(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	d := discoveryDesired()
	id, err := DiscoveryScheduleID(d.Ref)
	require.NoError(t, err)
	require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": id, "TemporalScheduledStartTime": d.Anchor}))
	env.RegisterActivityWithOptions(func(context.Context, DiscoveryOccurrence) (DiscoveryAdmission, error) {
		return DiscoveryAdmission{Outcome: "not_due"}, nil
	}, activity.RegisterOptions{Name: "AdmitDiscoveryScheduled"})
	env.ExecuteWorkflow(DiscoveryScheduledWorkflow, DiscoveryScheduleStart{Ref: d.Ref, Revision: d.Revision})
	require.NoError(t, env.GetWorkflowError())
	var result DiscoveryResult
	require.NoError(t, env.GetWorkflowResult(&result))
	require.Equal(t, "not_due", result.Outcome)
}
