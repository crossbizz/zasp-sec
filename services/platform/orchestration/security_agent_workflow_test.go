package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/testsuite"
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
