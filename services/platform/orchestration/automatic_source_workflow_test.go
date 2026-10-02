package orchestration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

func automaticRef() AutomaticSourceRef {
	return AutomaticSourceRef{OrganizationID: testRef.OrganizationID, WorkspaceID: testRef.WorkspaceID, EnvironmentID: testRef.EnvironmentID, EventID: "pid_f0773000-0000-4000-8000-000000000001"}
}

// A capacity deferral must not retry the first page forever and starve later
// responders. Both event delivery and periodic catch-up own this same contract.
func TestAutomaticWorkflowsFinishSweepBeforeDeferredRetry(t *testing.T) {
	for _, catchup := range []bool{false, true} {
		t.Run(fmt.Sprint(catchup), func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			started := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
			env.SetStartTime(started)
			var cursors []string
			cursor := "pid_f0773000-0000-4000-8000-000000000005"
			page := func(ctx context.Context, after string) (AutomaticPage, error) {
				cursors = append(cursors, after)
				info := activity.GetInfo(ctx)
				require.Equal(t, 30*time.Second, info.StartToCloseTimeout)
				switch len(cursors) {
				case 1:
					return AutomaticPage{After: cursor, More: true, Retry: true, Scanned: 5, Admitted: 4}, nil
				case 2:
					return AutomaticPage{After: cursor, Scanned: 0}, nil
				case 3:
					return AutomaticPage{After: cursor, More: true, Scanned: 5, Admitted: 1}, nil
				default:
					return AutomaticPage{After: cursor}, nil
				}
			}
			if catchup {
				ref := selectorDesired().Ref
				env.RegisterActivityWithOptions(func(ctx context.Context, q AutomaticCatchupStart) (AutomaticPage, error) {
					require.Equal(t, ref, q.Ref)
					require.EqualValues(t, 3, q.Revision)
					return page(ctx, q.After)
				}, activity.RegisterOptions{Name: "AutomaticCatchupPage"})
				env.ExecuteWorkflow(AutomaticCatchupWorkflow, AutomaticCatchupStart{Ref: ref, Revision: 3})
			} else {
				env.RegisterActivityWithOptions(func(ctx context.Context, q AutomaticSourceStart) (AutomaticPage, error) {
					require.Equal(t, automaticRef(), q.Ref)
					return page(ctx, q.After)
				}, activity.RegisterOptions{Name: "AutomaticSourcePage"})
				env.ExecuteWorkflow(AutomaticSourceWorkflow, AutomaticSourceStart{Ref: automaticRef()})
			}
			require.NoError(t, env.GetWorkflowError())
			require.Equal(t, []string{"", cursor, "", cursor}, cursors)
			require.True(t, env.Now().After(started), "deferred capacity needs Temporal backoff")
		})
	}
}

func TestAutomaticSourceContinuationCarriesProgressAndDeferral(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	calls := 0
	env.RegisterActivityWithOptions(func(_ context.Context, q AutomaticSourceStart) (AutomaticPage, error) {
		calls++
		return AutomaticPage{After: fmt.Sprintf("pid_f0773000-0000-4000-8000-%012d", calls), More: true, Retry: calls == 1, Scanned: 5}, nil
	}, activity.RegisterOptions{Name: "AutomaticSourcePage"})
	env.ExecuteWorkflow(AutomaticSourceWorkflow, AutomaticSourceStart{Ref: automaticRef()})
	var continued *workflow.ContinueAsNewError
	require.ErrorAs(t, env.GetWorkflowError(), &continued)
	var next AutomaticSourceStart
	require.NoError(t, converter.GetDefaultDataConverter().FromPayloads(continued.Input, &next))
	require.Equal(t, automaticRef(), next.Ref)
	require.Equal(t, "pid_f0773000-0000-4000-8000-000000000100", next.After)
	require.True(t, next.Retry)
	resumed := suite.NewTestWorkflowEnvironment()
	resumed.SetContinuedExecutionRunID("source-original")
	var after []string
	resumed.RegisterActivityWithOptions(func(_ context.Context, q AutomaticSourceStart) (AutomaticPage, error) {
		after = append(after, q.After)
		return AutomaticPage{After: q.After}, nil
	}, activity.RegisterOptions{Name: "AutomaticSourcePage"})
	resumed.ExecuteWorkflow(AutomaticSourceWorkflow, next)
	require.NoError(t, resumed.GetWorkflowError())
	require.Equal(t, []string{next.After, ""}, after)
}

func TestAutomaticSourceRejectsInvalidPageAndForgedContinuation(t *testing.T) {
	for name, page := range map[string]AutomaticPage{
		"over_bound":            {Scanned: 26},
		"negative":              {Scanned: -1},
		"admitted_over_visited": {Scanned: 1, Admitted: 2},
		"missing_progress":      {More: true, Scanned: 5},
		"empty_more":            {More: true, After: "pid_f0773000-0000-4000-8000-000000000005"},
	} {
		t.Run(name, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			calls := 0
			env.RegisterActivityWithOptions(func(context.Context, AutomaticSourceStart) (AutomaticPage, error) { calls++; return page, nil }, activity.RegisterOptions{Name: "AutomaticSourcePage"})
			env.ExecuteWorkflow(AutomaticSourceWorkflow, AutomaticSourceStart{Ref: automaticRef()})
			require.Error(t, env.GetWorkflowError())
			require.Equal(t, 1, calls)
		})
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.ExecuteWorkflow(AutomaticSourceWorkflow, AutomaticSourceStart{Ref: automaticRef(), After: "pid_f0773000-0000-4000-8000-000000000005", Retry: true})
	require.Error(t, env.GetWorkflowError(), "a new root execution cannot invent page progress")
}
