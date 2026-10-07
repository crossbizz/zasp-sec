package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
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

// Histories without the new version marker retain their original product order.
func TestSecurityAgentWorkflowLegacyVersionRetainsOrdering(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.OnGetVersion("security-agent-fresh-work-deadline-v1", workflow.DefaultVersion, 1).Return(workflow.DefaultVersion)
	backend := &workflowProductFixture{state: RunState{Phase: "planning"}}
	env.RegisterActivity(&Activities{Product: backend})
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.NoError(t, env.GetWorkflowError())
	require.Equal(t, []string{"plan", "apply", "advance", "test"}, backend.effects)
	require.Equal(t, 1, backend.cleanups)
}

// The dispatched product boundary receives only the remaining retry budget;
// compensation receives its independent original allowance.
func TestSecurityAgentWorkflowRemainingBudgetReachesProductBoundary(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	suite.SetLogger(deadlineWorkflowLogger{})
	env := suite.NewTestWorkflowEnvironment()
	started := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	env.SetStartTime(started)
	infos := map[string]activity.Info{}
	deadlines := map[string]time.Time{}
	backend := &workflowProductFixture{state: RunState{Phase: "planning"}, boundary: func(ctx context.Context, name string) {
		infos[name] = activity.GetInfo(ctx)
		if deadline, ok := ctx.Deadline(); ok {
			deadlines[name] = deadline
		}
	}}
	env.RegisterActivity(&Activities{Product: backend})
	nearDeadline := started.Add(24*time.Hour - 30*time.Second)
	delayed := false
	env.OnActivity("Observe", mock.Anything, mock.Anything).AfterFn(func() time.Duration {
		if !env.Now().Before(nearDeadline) && !delayed {
			delayed = true
			return 15 * time.Second
		}
		return 0
	}).Return(func(ctx context.Context, _ StartRequest) (RunState, error) {
		if env.Now().Before(nearDeadline) {
			return RunState{Phase: "waiting_approval"}, nil
		}
		backend.boundary(ctx, "observe")
		return backend.state, nil
	})
	env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
	require.NoError(t, env.GetWorkflowError())
	require.Equal(t, []string{"plan", "apply", "advance", "test"}, backend.effects)
	for _, name := range []string{"observe", "plan", "apply", "advance", "test"} {
		info, ok := infos[name]
		require.True(t, ok, name)
		require.Positive(t, info.StartToCloseTimeout, name)
		require.Positive(t, info.ScheduleToCloseTimeout, name)
		require.LessOrEqual(t, info.StartToCloseTimeout, 15*time.Second, name)
		require.LessOrEqual(t, info.ScheduleToCloseTimeout, 15*time.Second, name)
		deadline, ok := deadlines[name]
		require.True(t, ok, name)
		require.LessOrEqual(t, deadline.Sub(info.StartedTime), 15*time.Second, name)
	}
	require.Equal(t, 20*time.Minute, infos["cleanup"].StartToCloseTimeout)
	require.Equal(t, 2*time.Hour, infos["cleanup"].ScheduleToCloseTimeout)
	require.Equal(t, 1, backend.cleanups)
}

// A late authoritative read must not admit fresh product effects after the
// workflow's fixed budget; cleanup retains its separate disconnected budget.
func TestSecurityAgentWorkflowLateAuthorityCannotStartEffects(t *testing.T) {
	for _, phase := range []string{"planning", "apply", "advance", "test"} {
		t.Run(phase, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			suite.SetLogger(deadlineWorkflowLogger{})
			env := suite.NewTestWorkflowEnvironment()
			started := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
			env.SetStartTime(started)
			backend := &workflowProductFixture{state: RunState{Phase: phase}}
			env.RegisterActivity(&Activities{Product: backend})
			nearDeadline := started.Add(24*time.Hour - 30*time.Second)
			env.OnActivity("Observe", mock.Anything, mock.Anything).AfterFn(func() time.Duration {
				if !env.Now().Before(nearDeadline) {
					return 45 * time.Second
				}
				return 0
			}).Return(func(context.Context, StartRequest) (RunState, error) {
				if env.Now().Before(nearDeadline) {
					return RunState{Phase: "waiting_approval"}, nil
				}
				return RunState{Phase: phase}, nil
			})
			env.ExecuteWorkflow(SecurityAgentWorkflow, workflowRequest())
			require.Error(t, env.GetWorkflowError())
			require.Empty(t, backend.effects, "late authority cannot dispatch fresh product work")
			require.Equal(t, 1, backend.cleanups)
			require.Equal(t, "workflow_deadline", backend.cleanupReason)
		})
	}
}

type deadlineWorkflowLogger struct{}

func (deadlineWorkflowLogger) Debug(string, ...interface{}) {}
func (deadlineWorkflowLogger) Info(string, ...interface{})  {}
func (deadlineWorkflowLogger) Warn(string, ...interface{})  {}
func (deadlineWorkflowLogger) Error(string, ...interface{}) {}

func workflowRequest() StartRequest {
	return request()
}

type workflowProductFixture struct {
	state         RunState
	effects       []string
	cleanups      int
	unverified    bool
	cleanupErr    error
	cleanupReason string
	boundary      func(context.Context, string)
}

func (f *workflowProductFixture) Observe(context.Context, StartRequest) (RunState, error) {
	return f.state, nil
}
func (f *workflowProductFixture) Plan(ctx context.Context, _ StartRequest) error {
	if f.boundary != nil {
		f.boundary(ctx, "plan")
	}
	f.effects = append(f.effects, "plan")
	f.state.Phase = "apply"
	return nil
}
func (f *workflowProductFixture) Apply(ctx context.Context, _ StartRequest) error {
	if f.boundary != nil {
		f.boundary(ctx, "apply")
	}
	f.effects = append(f.effects, "apply")
	if !f.unverified {
		f.state.Phase = "advance"
	}
	return nil
}
func (f *workflowProductFixture) Advance(ctx context.Context, _ StartRequest) error {
	if f.boundary != nil {
		f.boundary(ctx, "advance")
	}
	f.effects = append(f.effects, "advance")
	f.state.Phase = "test"
	return nil
}
func (f *workflowProductFixture) Test(ctx context.Context, _ StartRequest) error {
	if f.boundary != nil {
		f.boundary(ctx, "test")
	}
	f.effects = append(f.effects, "test")
	f.state.Phase = "terminal"
	return nil
}
func (f *workflowProductFixture) Cleanup(ctx context.Context, q CleanupRequest) error {
	if f.boundary != nil {
		f.boundary(ctx, "cleanup")
	}
	f.cleanupReason = q.Reason
	if ctx.Err() != nil {
		return errors.New("compensation inherited cancellation")
	}
	f.cleanups++
	return f.cleanupErr
}
