package orchestration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
)

type selectorSourceFixture struct {
	desired      TestSelectorDesired
	acknowledged int
}

func (s *selectorSourceFixture) WithCurrentSelector(ctx context.Context, r TestSelectorRef, fn func(TestSelectorDesired) error) error {
	err := fn(s.desired)
	if err == nil {
		s.acknowledged++
	}
	return err
}
func selectorDesired() TestSelectorDesired {
	return TestSelectorDesired{Ref: TestSelectorRef{OrganizationID: testRef.OrganizationID, WorkspaceID: testRef.WorkspaceID, EnvironmentID: testRef.EnvironmentID, DefinitionID: testRef.RunID}, SchemaVersion: 1, Revision: 1, CadenceSeconds: 1, Enabled: true}
}

// Removing current-state reconciliation, the tenant from identity, or pause on
// disable must change our actual Schedule requests. SDK internals are not tested.
func TestTestSelectorReconciliation(t *testing.T) {
	d := selectorDesired()
	s := &selectorSourceFixture{desired: d}
	transport := &scheduleTransportFixture{}
	r, err := NewTestSelectorReconciler(transport, s, "tests", time.Second)
	require.NoError(t, err)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	first := transport.options
	require.Equal(t, time.Second, first.Spec.Intervals[0].Every)
	require.Equal(t, enumspb.SCHEDULE_OVERLAP_POLICY_SKIP, first.Overlap)
	require.Equal(t, 10*time.Second, first.CatchupWindow)
	require.False(t, first.TriggerImmediately)
	require.Equal(t, "TestSelectorWorkflow", first.Action.(*client.ScheduleWorkflowAction).Workflow)
	transport.exists = true
	s.desired.Revision = 2
	s.desired.CadenceSeconds = 2
	s.desired.Enabled = false
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.True(t, transport.schedule.State.Paused)
	require.Equal(t, 2*time.Second, transport.schedule.Spec.Intervals[0].Every)
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.True(t, transport.schedule.State.Paused)
	transport.exists = false
	s.desired.Enabled = true
	require.NoError(t, r.Reconcile(context.Background(), d.Ref))
	require.False(t, transport.schedule.State.Paused)
	s.desired.Ref.OrganizationID = "pid_00000000-0000-4000-8000-000000000010"
	require.NoError(t, r.Reconcile(context.Background(), s.desired.Ref))
	require.NotEqual(t, first.ID, transport.options.ID)
}

func TestTestSelectorRefusesInvalidStaleForeignAndUnknown(t *testing.T) {
	for _, kind := range []string{"missing_revision", "missing_schema", "missing_cadence", "negative", "too_large", "foreign_ref", "foreign_workflow", "foreign_queue", "stale", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			d := selectorDesired()
			s := &selectorSourceFixture{desired: d}
			transport := &scheduleTransportFixture{}
			r, err := NewTestSelectorReconciler(transport, s, "tests", time.Second)
			require.NoError(t, err)
			require.NoError(t, r.Reconcile(context.Background(), d.Ref))
			transport.exists = true
			s.desired.Revision = 2
			switch kind {
			case "missing_revision":
				s.desired.Revision = 0
			case "missing_schema":
				s.desired.SchemaVersion = 0
			case "missing_cadence":
				s.desired.CadenceSeconds = 0
			case "negative":
				s.desired.CadenceSeconds = -1
			case "too_large":
				s.desired.CadenceSeconds = 86401
			case "foreign_ref":
				s.desired.Ref.OrganizationID = d.Ref.DefinitionID
			case "foreign_workflow":
				transport.schedule.Action.(*client.ScheduleWorkflowAction).Workflow = "DiscoveryScheduledWorkflow"
			case "foreign_queue":
				transport.schedule.Action.(*client.ScheduleWorkflowAction).TaskQueue = "other"
			case "stale":
				transport.schedule.Action.(*client.ScheduleWorkflowAction).Args = []any{TestSelectorStart{Ref: d.Ref, Revision: 3}}
			case "unknown":
				transport.updateErr = context.DeadlineExceeded
			}
			require.Error(t, r.Reconcile(context.Background(), d.Ref))
			require.Equal(t, 1, s.acknowledged)
			if kind == "unknown" {
				transport.updateErr = nil
				require.NoError(t, r.Reconcile(context.Background(), d.Ref))
				require.Equal(t, 2, s.acknowledged)
			}
		})
	}
}
