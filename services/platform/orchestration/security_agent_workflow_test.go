package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// Removing the verified-predecessor gate must make this test fail. The fake is
// the external product boundary; ordering and cancellation are the real workflow.
func TestSecurityAgentWorkflowVerifiedOrdering(t *testing.T) {
	for _, blocked := range []string{"waiting_approval", "stale", "permission_lost"} {
		t.Run(blocked, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			backend := &workflowProductFixture{state: RunState{Phase: blocked}}
			env.RegisterActivity(&Activities{Product: backend})
			env.RegisterDelayedCallback(env.CancelWorkflow, time.Minute)
			env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
			require.Empty(t, backend.effects)
			require.Equal(t, 1, backend.cleanups)
			require.Error(t, env.GetWorkflowError())
		})
	}
	t.Run("ordered_receipts", func(t *testing.T) {
		var suite testsuite.WorkflowTestSuite
		env := suite.NewTestWorkflowEnvironment()
		backend := &workflowProductFixture{state: RunState{Phase: "planning"}}
		env.RegisterActivity(&Activities{Product: backend})
		env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
		require.NoError(t, env.GetWorkflowError())
		require.Equal(t, []string{"plan", "apply", "advance", "test"}, backend.effects)
		require.Equal(t, 1, backend.cleanups)
	})
	t.Run("unverified_apply", func(t *testing.T) {
		var suite testsuite.WorkflowTestSuite
		env := suite.NewTestWorkflowEnvironment()
		backend := &workflowProductFixture{state: RunState{Phase: "apply"}, unverified: true}
		env.RegisterActivity(&Activities{Product: backend})
		env.RegisterDelayedCallback(env.CancelWorkflow, time.Minute)
		env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
		require.NotContains(t, backend.effects, "advance")
		require.NotContains(t, backend.effects, "test")
	})
}

func TestSecurityAgentWorkflowSignalsAreHints(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	backend := &workflowProductFixture{state: RunState{Phase: "waiting_approval"}}
	env.RegisterActivity(&Activities{Product: backend})
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow("product-decision", Message{Ref: workflowRequest().Ref, EventID: "pid_00000000-0000-4000-8000-000000000006", DecisionID: "pid_00000000-0000-4000-8000-000000000007", Kind: "approval"})
		env.SignalWorkflow("product-decision", []string{"malformed", "untrusted", "not authority"})
	}, time.Second)
	env.RegisterDelayedCallback(env.CancelWorkflow, time.Minute)
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.Empty(t, backend.effects, "signal payload must not authorize apply")
	require.Equal(t, 1, backend.cleanups)
}

func TestSecurityAgentWorkflowCleanupFailureRemainsFailure(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	backend := &workflowProductFixture{state: RunState{Phase: "terminal"}, cleanupErr: ErrConflict}
	env.RegisterActivity(&Activities{Product: backend})
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.Error(t, env.GetWorkflowError())
}

func workflowRequest() StartRequest {
	return request()
}

type workflowProductFixture struct {
	state      RunState
	effects    []string
	cleanups   int
	unverified bool
	cleanupErr error
}

func (f *workflowProductFixture) Observe(context.Context, StartRequest) (RunState, error) {
	return f.state, nil
}
func (f *workflowProductFixture) Plan(context.Context, StartRequest) error {
	f.effects = append(f.effects, "plan")
	f.state.Phase = "apply"
	return nil
}
func (f *workflowProductFixture) Apply(context.Context, StartRequest) error {
	f.effects = append(f.effects, "apply")
	if !f.unverified {
		f.state.Phase = "advance"
	}
	return nil
}
func (f *workflowProductFixture) Advance(context.Context, StartRequest) error {
	f.effects = append(f.effects, "advance")
	f.state.Phase = "test"
	return nil
}
func (f *workflowProductFixture) Test(context.Context, StartRequest) error {
	f.effects = append(f.effects, "test")
	f.state.Phase = "terminal"
	return nil
}
func (f *workflowProductFixture) Cleanup(ctx context.Context, _ CleanupRequest) error {
	if ctx.Err() != nil {
		return errors.New("compensation inherited cancellation")
	}
	f.cleanups++
	return f.cleanupErr
}

// Closing after one bounded Activity batch strands authoritative cleanup debt.
func TestSecurityAgentCleanupDebtContinuesWithImmutableOutcome(t *testing.T) {
	for _, outcome := range []string{"completed", "failed", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			started := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
			env.SetStartTime(started)
			phase := "terminal"
			if outcome == "failed" {
				phase = "permission_lost"
			}
			if outcome == "cancelled" {
				phase = "waiting_approval"
				env.RegisterDelayedCallback(env.CancelWorkflow, time.Second)
			}
			backend := &workflowProductFixture{state: RunState{Phase: phase}, cleanupErr: ErrCleanupPending}
			env.RegisterActivity(&Activities{Product: backend})
			env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
			var continued *workflow.ContinueAsNewError
			require.ErrorAs(t, env.GetWorkflowError(), &continued)
			require.Equal(t, "SecurityAgentCleanupWorkflow", continued.WorkflowType.Name)
			var state SecurityAgentCleanupContinuation
			require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continued.Input, &state))
			require.Equal(t, workflowRequest(), state.Start)
			require.Equal(t, started.Add(24*time.Hour), state.BusinessDeadline)
			require.Equal(t, outcome, state.Outcome)
			require.Equal(t, 64, backend.cleanups)
			require.Empty(t, backend.effects)
			standalone := suite.NewTestWorkflowEnvironment()
			standalone.ExecuteWorkflow(SecurityAgentCleanupWorkflow, state)
			require.Error(t, standalone.GetWorkflowError())
			require.Equal(t, 64, backend.cleanups)
			resumed := suite.NewTestWorkflowEnvironment()
			resumed.SetContinuedExecutionRunID("prior-run")
			resumed.SetStartTime(started.Add(48 * time.Hour))
			backend.cleanupErr = nil
			a := &Activities{Product: backend}
			resumed.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "Cleanup"})
			resumed.ExecuteWorkflow(SecurityAgentCleanupWorkflow, state)
			if outcome == "completed" {
				require.NoError(t, resumed.GetWorkflowError())
			} else {
				require.Error(t, resumed.GetWorkflowError())
			}
			if outcome == "cancelled" {
				require.True(t, temporal.IsCanceledError(resumed.GetWorkflowError()))
			}
			require.Equal(t, 65, backend.cleanups)
			require.Empty(t, backend.effects)
		})
	}
}

func TestSecurityAgentCleanupTransientBatchExhaustionRecovers(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(func(context.Context, StartRequest) (RunState, error) { return RunState{Phase: "terminal"}, nil }, activity.RegisterOptions{Name: "Observe"})
	calls := 0
	env.RegisterActivityWithOptions(func(ctx context.Context, q CleanupRequest) error {
		require.NoError(t, ctx.Err())
		require.Equal(t, CleanupRequest{Start: workflowRequest(), Reason: "terminal"}, q)
		calls++
		if calls <= 12 {
			return activityError(errors.New("dependency outage"))
		}
		return nil
	}, activity.RegisterOptions{Name: "Cleanup"})
	env.RegisterDelayedCallback(func() { env.SignalWorkflow("product-decision", []string{"untrusted"}); env.CancelWorkflow() }, time.Second)
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.NoError(t, env.GetWorkflowError())
	require.Equal(t, 13, calls)
}

func TestSecurityAgentCleanupContinuationRejectsChangedOutcome(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.SetContinuedExecutionRunID("prior-run")
	s := SecurityAgentCleanupContinuation{Start: workflowRequest(), BusinessDeadline: time.Now(), Reason: "workflow_cancelled", Outcome: "completed"}
	env.ExecuteWorkflow(SecurityAgentCleanupWorkflow, s)
	require.Error(t, env.GetWorkflowError())
}

func TestSecurityAgentCleanupOldHistoryRetainsFiniteRecovery(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.OnGetVersion("ordered-cleanup-continuation", workflow.DefaultVersion, workflow.Version(1)).Return(workflow.DefaultVersion)
	backend := &workflowProductFixture{state: RunState{Phase: "terminal"}, cleanupErr: ErrCleanupPending}
	env.RegisterActivity(&Activities{Product: backend})
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.Error(t, env.GetWorkflowError())
	var continued *workflow.ContinueAsNewError
	require.False(t, errors.As(env.GetWorkflowError(), &continued))
	require.Equal(t, 1, backend.cleanups)
}
