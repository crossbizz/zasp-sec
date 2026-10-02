package orchestration

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
	"strings"
	"testing"
	"time"
)

func recoveryRef() SingleTestRecoveryRef {
	return SingleTestRecoveryRef{Start: request(), CommandID: request().Ref.RunID, CommandDigest: strings.Repeat("b", 64)}
}

func TestSingleTestRecoveryWorkflowContracts(t *testing.T) {
	for _, mode := range []string{"pending", "cancel", "permanent", "continue", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			ref := recoveryRef()
			calls := 0
			forbidden := 0
			env.RegisterActivityWithOptions(func(context.Context, SingleTestRecoveryRef) error { forbidden++; return nil }, activity.RegisterOptions{Name: "SingleTest"})
			env.RegisterActivityWithOptions(func(_ context.Context, got SingleTestRecoveryRef) error {
				require.Equal(t, ref, got)
				calls++
				if mode == "permanent" {
					return activityError(ErrConflict)
				}
				if mode == "continue" || calls == 1 {
					return activityError(ErrCleanupPending)
				}
				return nil
			}, activity.RegisterOptions{Name: "SingleOperatorCleanup"})
			if mode == "cancel" {
				env.RegisterDelayedCallback(func() { env.CancelWorkflow() }, time.Second)
			}
			if mode == "invalid" {
				ref.CommandDigest = "invalid"
			}
			env.ExecuteWorkflow(SingleTestOperatorCleanupWorkflow, ref)
			switch mode {
			case "invalid":
				require.Error(t, env.GetWorkflowError())
				require.Zero(t, calls)
			case "permanent":
				require.Error(t, env.GetWorkflowError())
				require.Equal(t, 1, calls)
			case "continue":
				var next *workflow.ContinueAsNewError
				require.True(t, errors.As(env.GetWorkflowError(), &next))
				require.Equal(t, 64, calls)
			default:
				require.NoError(t, env.GetWorkflowError())
				require.Equal(t, 2, calls)
			}
			require.Zero(t, forbidden)
		})
	}
}
