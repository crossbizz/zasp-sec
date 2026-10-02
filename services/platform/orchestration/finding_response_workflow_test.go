package orchestration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// This product boundary keeps authority outside the Workflow; wake bodies do
// not change it. The mutex also covers Activity workers and delayed callbacks.
type findingProductFixture struct {
	mu                       sync.Mutex
	phase                    string
	operations               []string
	cleanups                 []CleanupRequest
	pending                  int
	cleanupErr               error
	planEntered, planRelease chan struct{}
}

func (p *findingProductFixture) Observe(context.Context, StartRequest) (RunState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return RunState{Phase: p.phase}, nil
}
func (p *findingProductFixture) Plan(context.Context, StartRequest) error {
	if p.planEntered != nil {
		close(p.planEntered)
		<-p.planRelease
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.operations = append(p.operations, "plan")
	p.phase = "apply"
	return nil
}
func (p *findingProductFixture) Apply(context.Context, StartRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.operations = append(p.operations, "apply")
	p.phase = "terminal"
	return nil
}
func (p *findingProductFixture) Cleanup(_ context.Context, q CleanupRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.operations = append(p.operations, "cleanup")
	p.cleanups = append(p.cleanups, q)
	if p.pending > 0 {
		p.pending--
		return ErrCleanupPending
	}
	return p.cleanupErr
}
func registerFindingActivities(env *testsuite.TestWorkflowEnvironment, p *findingProductFixture) {
	a := &FindingResponseActivities{Product: p}
	for name, handler := range map[string]any{"FindingObserve": a.Observe, "FindingPlan": a.Plan, "FindingApply": a.Apply, "FindingCleanup": a.Cleanup} {
		env.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
	}
}

func TestFindingResponseWorkflowProductAuthority(t *testing.T) {
	for _, phase := range []string{"planning", "terminal", "waiting_approval", "pending", "permission_lost", "stopping", "stale", "test", "advance"} {
		t.Run(phase, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			p := &findingProductFixture{phase: phase}
			registerFindingActivities(env, p)
			if phase == "waiting_approval" || phase == "pending" {
				env.RegisterDelayedCallback(func() {
					env.SignalWorkflow("finding-response-wake", map[string]any{"approved": true, "phase": "apply", "tenant": "foreign"})
				}, time.Second)
				env.RegisterDelayedCallback(env.CancelWorkflow, 2*time.Second)
			}
			env.ExecuteWorkflow(FindingResponseWorkflow, request())
			if phase == "planning" || phase == "terminal" {
				require.NoError(t, env.GetWorkflowError())
				require.Equal(t, "terminal", p.cleanups[0].Reason)
			} else {
				require.Error(t, env.GetWorkflowError())
			}
			if phase == "planning" {
				require.Equal(t, []string{"plan", "apply", "cleanup"}, p.operations)
			} else {
				require.Equal(t, []string{"cleanup"}, p.operations)
			}
			require.Equal(t, request(), p.cleanups[0].Start)
			if phase == "waiting_approval" || phase == "pending" {
				require.True(t, temporal.IsCanceledError(env.GetWorkflowError()))
				require.Equal(t, "workflow_cancelled", p.cleanups[0].Reason)
			}
		})
	}
}

func TestFindingResponseWorkflowApprovedWakeRereadsProduct(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	p := &findingProductFixture{phase: "waiting_approval"}
	registerFindingActivities(env, p)
	env.RegisterDelayedCallback(func() {
		p.mu.Lock()
		p.phase = "apply"
		p.mu.Unlock()
		env.SignalWorkflow("finding-response-wake", nil)
	}, time.Second)
	env.ExecuteWorkflow(FindingResponseWorkflow, request())
	require.NoError(t, env.GetWorkflowError())
	require.Equal(t, []string{"apply", "cleanup"}, p.operations)
}

func TestFindingResponseCleanupContinuationPreservesDebtAndOutcome(t *testing.T) {
	for _, outcome := range []string{"completed", "failed", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			started := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
			env.SetStartTime(started)
			phase := "terminal"
			if outcome == "failed" {
				phase = "permission_lost"
			}
			if outcome == "cancelled" {
				phase = "waiting_approval"
				env.RegisterDelayedCallback(env.CancelWorkflow, time.Second)
			}
			p := &findingProductFixture{phase: phase, pending: 64}
			registerFindingActivities(env, p)
			env.ExecuteWorkflow(FindingResponseWorkflow, request())
			var continued *workflow.ContinueAsNewError
			require.ErrorAs(t, env.GetWorkflowError(), &continued)
			require.Equal(t, "FindingResponseCleanupWorkflow", continued.WorkflowType.Name)
			var state FindingResponseCleanupContinuation
			require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continued.Input, &state))
			require.Equal(t, request(), state.Start)
			require.Equal(t, started.Add(24*time.Hour), state.BusinessDeadline)
			require.Equal(t, outcome, state.Outcome)
			require.Len(t, p.cleanups, 64)
			standalone := suite.NewTestWorkflowEnvironment()
			standalone.ExecuteWorkflow(FindingResponseCleanupWorkflow, state)
			require.Error(t, standalone.GetWorkflowError())
			resumed := suite.NewTestWorkflowEnvironment()
			resumed.SetContinuedExecutionRunID("prior-run")
			resumed.SetStartTime(started.Add(48 * time.Hour))
			a := &FindingResponseActivities{Product: p}
			resumed.RegisterActivityWithOptions(a.Cleanup, activity.RegisterOptions{Name: "FindingCleanup"})
			resumed.ExecuteWorkflow(FindingResponseCleanupWorkflow, state)
			if outcome == "completed" {
				require.NoError(t, resumed.GetWorkflowError())
			} else {
				require.Error(t, resumed.GetWorkflowError())
			}
			if outcome == "cancelled" {
				require.True(t, temporal.IsCanceledError(resumed.GetWorkflowError()))
			}
			require.Len(t, p.cleanups, 65)
			for _, op := range p.operations {
				require.Equal(t, "cleanup", op)
			}
		})
	}
}

func TestFindingResponseCleanupTransientExhaustionRetainsDebt(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "permanent"}[permanent], func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			env.RegisterActivityWithOptions(func(context.Context, StartRequest) (RunState, error) { return RunState{Phase: "terminal"}, nil }, activity.RegisterOptions{Name: "FindingObserve"})
			calls := 0
			env.RegisterActivityWithOptions(func(_ context.Context, q CleanupRequest) error {
				require.Equal(t, CleanupRequest{Start: request(), Reason: "terminal"}, q)
				calls++
				if permanent {
					return activityError(ErrConflict)
				}
				if calls <= 12 {
					return activityError(errors.New("dependency outage"))
				}
				return nil
			}, activity.RegisterOptions{Name: "FindingCleanup"})
			env.RegisterDelayedCallback(func() { env.SignalWorkflow("finding-response-wake", nil); env.CancelWorkflow() }, time.Second)
			env.ExecuteWorkflow(FindingResponseWorkflow, request())
			if permanent {
				require.Error(t, env.GetWorkflowError())
				require.Equal(t, 1, calls)
			} else {
				require.NoError(t, env.GetWorkflowError())
				require.Equal(t, 13, calls)
			}
		})
	}
}

func TestFindingResponseActivitiesCloseDrainsBorrowedProduct(t *testing.T) {
	p := &findingProductFixture{planEntered: make(chan struct{}), planRelease: make(chan struct{})}
	a := &FindingResponseActivities{Product: p}
	done := make(chan error, 1)
	go func() { done <- a.Plan(context.Background(), request()) }()
	<-p.planEntered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, a.Close(ctx), context.Canceled)
	require.Error(t, a.Apply(context.Background(), request()), "closing must reject fresh effects")
	close(p.planRelease)
	require.NoError(t, <-done)
	require.NoError(t, a.Close(context.Background()))
	require.Equal(t, []string{"plan"}, p.operations)
}
