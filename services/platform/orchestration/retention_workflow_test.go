package orchestration

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

type retentionStoreFixture struct {
	keys        []string
	unavailable int
	counters    RetentionCounters
	err         error
	onSweep     func()
}

func (s *retentionStoreFixture) Sweep(_ context.Context, key string) (RetentionCounters, error) {
	if s.onSweep != nil {
		s.onSweep()
	}
	s.keys = append(s.keys, key)
	if s.unavailable > 0 {
		s.unavailable--
		return RetentionCounters{}, errors.New("PRIVATE database detail")
	}
	return s.counters, s.err
}

func TestRetentionActivityShutdownJoinsBorrowedTransaction(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: RetentionWorkflowPrefix + "-shutdown"})
	require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": RetentionScheduleID, "TemporalScheduledStartTime": time.Now().UTC()}))
	store := &retentionStoreFixture{counters: RetentionCounters{Scopes: 1, Scanned: 1}}
	a := &RetentionActivities{Store: store}
	store.onSweep = func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		require.ErrorIs(t, a.Close(ctx), context.DeadlineExceeded, "database owner must retain the borrowed client while the transaction runs")
	}
	env.RegisterActivityWithOptions(a.Sweep, activity.RegisterOptions{Name: RetentionActivityName})
	env.ExecuteWorkflow(RetentionScheduledWorkflow)
	require.NoError(t, env.GetWorkflowError())
	require.NoError(t, a.Close(context.Background()), "owner may close the client only after the borrowed transaction joins")
	require.NoError(t, a.Close(context.Background()), "repeated close must remain safe")
}

func TestRetentionScheduledWorkflowStablePrivateBoundary(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: RetentionWorkflowPrefix + "-20261017"})
	require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": RetentionScheduleID, "TemporalScheduledStartTime": time.Now().UTC()}))
	store := &retentionStoreFixture{unavailable: 1, counters: RetentionCounters{Scopes: 2, Scanned: 20, Expired: 7}}
	a := &RetentionActivities{Store: store}
	env.RegisterActivityWithOptions(a.Sweep, activity.RegisterOptions{Name: RetentionActivityName})
	env.ExecuteWorkflow(RetentionScheduledWorkflow)
	require.NoError(t, env.GetWorkflowError())
	var got RetentionCounters
	require.NoError(t, env.GetWorkflowResult(&got))
	require.Equal(t, store.counters, got)
	require.Len(t, store.keys, 2)
	require.Equal(t, store.keys[0], store.keys[1], "activity retry must reuse original committed cycle receipt")
	require.Len(t, store.keys[0], 64)
	require.Equal(t, 1, reflect.TypeOf(RetentionScheduledWorkflow).NumIn(), "workflow accepts only its SDK context")
	require.Equal(t, 2, reflect.TypeOf(RetentionCycle{}).NumField(), "no tenant, policy, cursor or reference ID in history")
}

func TestRetentionScheduledWorkflowRejectsForeignOrInvalidBoundary(t *testing.T) {
	for _, kind := range []string{"unscheduled", "foreign_schedule", "foreign_workflow", "invalid_counters", "private_error"} {
		t.Run(kind, func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			id := RetentionWorkflowPrefix + "-20261017"
			if kind == "foreign_workflow" {
				id = "unrelated"
			}
			env.SetStartWorkflowOptions(client.StartWorkflowOptions{ID: id})
			if kind != "unscheduled" {
				by := RetentionScheduleID
				if kind == "foreign_schedule" {
					by = "unrelated"
				}
				require.NoError(t, env.SetSearchAttributesOnStart(map[string]interface{}{"TemporalScheduledById": by, "TemporalScheduledStartTime": time.Now().UTC()}))
			}
			store := &retentionStoreFixture{}
			if kind == "invalid_counters" {
				store.counters = RetentionCounters{Scopes: 1, Scanned: 1, Expired: 2}
			}
			if kind == "private_error" {
				store.err = ErrConflict
			}
			a := &RetentionActivities{Store: store}
			env.RegisterActivityWithOptions(a.Sweep, activity.RegisterOptions{Name: RetentionActivityName})
			env.ExecuteWorkflow(RetentionScheduledWorkflow)
			err := env.GetWorkflowError()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "PRIVATE")
			if strings.HasPrefix(kind, "foreign") || kind == "unscheduled" {
				require.Empty(t, store.keys)
			} else {
				require.Len(t, store.keys, 1)
			}
		})
	}
}
