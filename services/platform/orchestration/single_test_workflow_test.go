package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	enums "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

func TestSingleTestCleanupRecoversExhaustedTransientBatch(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		for _, failure := range []string{"unavailable", "timeout", "permanent", "permanent_unavailable", "unknown_nonretryable"} {
			t.Run(map[bool]string{false: "original/", true: "continuation/"}[continuation]+failure, func(t *testing.T) {
				var suite testsuite.WorkflowTestSuite
				env := suite.NewTestWorkflowEnvironment()
				started := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
				env.SetStartTime(started)
				calls := 0
				var attempts []int32
				env.RegisterActivityWithOptions(func(context.Context, StartRequest) (RunState, error) { return RunState{Phase: "terminal"}, nil }, activity.RegisterOptions{Name: "SingleObserve"})
				env.RegisterActivityWithOptions(func(ctx context.Context, q CleanupRequest) error {
					require.Equal(t, request(), q.Start)
					require.Equal(t, "terminal", q.Reason)
					calls++
					attempts = append(attempts, activity.GetInfo(ctx).Attempt)
					if calls > 12 {
						return nil
					}
					switch failure {
					case "unavailable":
						return activityError(errors.New("controlled dependency outage"))
					case "timeout":
						return temporal.NewTimeoutError(enums.TIMEOUT_TYPE_START_TO_CLOSE, nil)
					case "permanent":
						return activityError(ErrConflict)
					case "permanent_unavailable":
						return temporal.NewNonRetryableApplicationError("repair required", "ProductUnavailable", nil)
					default:
						return temporal.NewNonRetryableApplicationError("repair required", "UnknownContract", nil)
					}
				}, activity.RegisterOptions{Name: "SingleCleanup"})
				env.RegisterDelayedCallback(func() {
					env.SignalWorkflow("single-test-wake", nil)
					env.SignalWorkflow("single-test-wake", nil)
					env.CancelWorkflow()
				}, time.Second)
				if continuation {
					env.SetContinuedExecutionRunID("original-execution")
					env.ExecuteWorkflow(SingleTestCleanupWorkflow, SingleTestCleanupContinuation{Start: request(), BusinessDeadline: started.Add(-24 * time.Hour), Reason: "terminal", Outcome: "completed"})
				} else {
					env.ExecuteWorkflow(SingleTestWorkflow, request())
				}
				if failure == "permanent" || failure == "permanent_unavailable" || failure == "unknown_nonretryable" {
					require.Error(t, env.GetWorkflowError())
					require.Equal(t, 1, calls, "permanent refusal must remain repair-required")
				} else {
					require.NoError(t, env.GetWorkflowError(), "a bounded retry batch is not cleanup completion")
					require.Equal(t, 13, calls)
					require.Equal(t, int32(12), attempts[11])
					require.Equal(t, int32(1), attempts[12], "recovery must use a new bounded cleanup batch")
				}
				// No Plan/Test/Settle handler is registered: any execution reentry fails.
			})
		}
	}
}

func TestSingleTestCleanupTransientBatchContinuesSameIdentity(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	started := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	env.SetStartTime(started)
	calls := 0
	env.RegisterActivityWithOptions(func(context.Context, StartRequest) (RunState, error) { return RunState{Phase: "terminal"}, nil }, activity.RegisterOptions{Name: "SingleObserve"})
	env.RegisterActivityWithOptions(func(context.Context, CleanupRequest) error {
		calls++
		if calls <= 12 {
			return activityError(errors.New("temporary database outage"))
		}
		return activityError(ErrCleanupPending)
	}, activity.RegisterOptions{Name: "SingleCleanup"})
	env.ExecuteWorkflow(SingleTestWorkflow, request())
	var continued *workflow.ContinueAsNewError
	require.ErrorAs(t, env.GetWorkflowError(), &continued)
	require.Equal(t, 75, calls, "one exhausted batch plus63 pending observations")
	var state SingleTestCleanupContinuation
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continued.Input, &state))
	require.Equal(t, SingleTestCleanupContinuation{Start: request(), BusinessDeadline: started.Add(24 * time.Hour), Reason: "terminal", Outcome: "completed"}, state)
	resumed := suite.NewTestWorkflowEnvironment()
	resumed.SetContinuedExecutionRunID("transient-cleanup-original")
	resumed.SetStartTime(started.Add(48 * time.Hour))
	resumed.RegisterActivityWithOptions(func(_ context.Context, q CleanupRequest) error {
		require.Equal(t, state.Start, q.Start)
		require.Equal(t, state.Reason, q.Reason)
		return nil
	}, activity.RegisterOptions{Name: "SingleCleanup"})
	resumed.ExecuteWorkflow(SingleTestCleanupWorkflow, state)
	require.NoError(t, resumed.GetWorkflowError())
}

type singleTestProductFixture struct {
	phase      string
	operations []string
	cleanup    error
	pending    int
}

func (p *singleTestProductFixture) Observe(context.Context, StartRequest) (RunState, error) {
	return RunState{Phase: p.phase}, nil
}
func (p *singleTestProductFixture) Plan(context.Context, StartRequest) error {
	p.operations = append(p.operations, "plan")
	p.phase = "test"
	return nil
}
func (p *singleTestProductFixture) Test(context.Context, StartRequest) error {
	p.operations = append(p.operations, "test")
	p.phase = "settling"
	return nil
}
func (p *singleTestProductFixture) Settle(context.Context, StartRequest) error {
	p.operations = append(p.operations, "settle")
	p.phase = "terminal"
	return nil
}
func (p *singleTestProductFixture) Cleanup(context.Context, CleanupRequest) error {
	p.operations = append(p.operations, "cleanup")
	if p.pending > 0 {
		p.pending--
		return ErrCleanupPending
	}
	return p.cleanup
}

func TestSingleTestPendingCleanupOutlivesRetryExhaustion(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "later_proof", true: "cancelled_with_duplicate_wakes"}[cancel], func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			p := &singleTestProductFixture{phase: "terminal", pending: 13}
			a := &SingleTestActivities{Product: p}
			env.RegisterActivityWithOptions(a.Observe, activity.RegisterOptions{Name: "SingleObserve"})
			env.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
			env.RegisterDelayedCallback(func() {
				env.SignalWorkflow("single-test-wake", nil)
				env.SignalWorkflow("single-test-wake", nil)
				if cancel {
					env.CancelWorkflow()
				}
			}, time.Second)
			env.ExecuteWorkflow(SingleTestWorkflow, request())
			require.NoError(t, env.GetWorkflowError(), "pending cleanup must survive until actual proof")
			require.Zero(t, p.pending)
			require.Len(t, p.operations, 14)
			for _, op := range p.operations {
				require.Equal(t, "cleanup", op, "cleanup must never reenter execution")
			}
		})
	}
}

func TestSingleTestPendingCleanupContinuesWithoutNewBusinessDeadline(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	started := time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC)
	env.SetStartTime(started)
	p := &singleTestProductFixture{phase: "terminal", pending: 100}
	a := &SingleTestActivities{Product: p}
	env.RegisterActivityWithOptions(a.Observe, activity.RegisterOptions{Name: "SingleObserve"})
	env.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
	env.ExecuteWorkflow(SingleTestWorkflow, request())
	var continued *workflow.ContinueAsNewError
	require.ErrorAs(t, env.GetWorkflowError(), &continued)
	require.Equal(t, "SingleTestCleanupWorkflow", continued.WorkflowType.Name)
	var state SingleTestCleanupContinuation
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continued.Input, &state))
	require.Equal(t, request(), state.Start)
	require.Equal(t, started.Add(24*time.Hour), state.BusinessDeadline)
	require.Equal(t, "terminal", state.Reason)
	require.Equal(t, "completed", state.Outcome)
	require.Len(t, p.operations, 64)
	for _, op := range p.operations {
		require.Equal(t, "cleanup", op)
	}
	// The continuation itself has no execution activity registration and rejects
	// an arbitrary standalone start, even with an otherwise matching payload.
	standalone := suite.NewTestWorkflowEnvironment()
	standalone.ExecuteWorkflow(SingleTestCleanupWorkflow, state)
	require.Error(t, standalone.GetWorkflowError())
	resumed := suite.NewTestWorkflowEnvironment()
	resumed.SetContinuedExecutionRunID("prior-cleanup-run")
	resumed.SetStartTime(started.Add(48 * time.Hour))
	p.pending = 100
	resumed.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
	resumed.ExecuteWorkflow(SingleTestCleanupWorkflow, state)
	var next *workflow.ContinueAsNewError
	require.ErrorAs(t, resumed.GetWorkflowError(), &next)
	var nextState SingleTestCleanupContinuation
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(next.Input, &nextState))
	require.Equal(t, state, nextState, "continuation must not refresh deadline, reason or product identity")
	complete := suite.NewTestWorkflowEnvironment()
	complete.SetContinuedExecutionRunID("second-cleanup-run")
	complete.SetStartTime(started.Add(72 * time.Hour))
	p.pending = 0
	complete.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
	complete.ExecuteWorkflow(SingleTestCleanupWorkflow, nextState)
	require.NoError(t, complete.GetWorkflowError())
	require.Len(t, p.operations, 129)
	for _, op := range p.operations {
		require.Equal(t, "cleanup", op)
	}
}

func TestSingleTestWorkflowRequiresParentSettlement(t *testing.T) {
	for _, phase := range []string{"planning", "waiting_approval", "pending", "permission_lost", "stopping"} {
		t.Run(phase, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			p := &singleTestProductFixture{phase: phase}
			a := &SingleTestActivities{Product: p}
			for name, handler := range map[string]any{"SingleObserve": a.Observe, "SinglePlan": a.Plan, "SingleTest": a.Test, "SingleSettle": a.Settle, "SingleCleanup": a.Cleanup} {
				env.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
			}
			if phase == "waiting_approval" || phase == "pending" {
				env.RegisterDelayedCallback(func() { env.SignalWorkflow("single-test-wake", map[string]any{"approved": true, "tenant": "foreign"}) }, time.Second)
				env.RegisterDelayedCallback(env.CancelWorkflow, time.Minute)
			}
			env.ExecuteWorkflow(SingleTestWorkflow, request())
			if phase == "planning" {
				require.NoError(t, env.GetWorkflowError())
				require.Equal(t, []string{"plan", "test", "settle", "cleanup"}, p.operations)
			} else {
				require.Error(t, env.GetWorkflowError())
				require.Equal(t, []string{"cleanup"}, p.operations)
			}
		})
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	p := &singleTestProductFixture{phase: "terminal", cleanup: ErrConflict}
	a := &SingleTestActivities{Product: p}
	env.RegisterActivityWithOptions(a.Observe, activity.RegisterOptions{Name: "SingleObserve"})
	env.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
	env.ExecuteWorkflow(SingleTestWorkflow, request())
	require.Error(t, env.GetWorkflowError(), "terminal label cannot conceal pending cleanup")
}
