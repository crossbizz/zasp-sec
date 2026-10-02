package orchestration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"strings"
	"time"
)

type TestSelectorRef struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	DefinitionID   string `json:"definition_id"`
}
type TestSelectorDesired struct {
	Ref            TestSelectorRef `json:"ref"`
	SchemaVersion  int             `json:"schema_version"`
	Revision       int64           `json:"revision"`
	CadenceSeconds int             `json:"cadence_seconds"`
	Enabled        bool            `json:"enabled"`
	Automatic      bool            `json:"automatic,omitempty"`
}
type TestSelectorStart struct {
	Ref      TestSelectorRef `json:"ref"`
	Revision int64           `json:"revision"`
}
type TestSelectorSource interface {
	WithCurrentSelector(context.Context, TestSelectorRef, func(TestSelectorDesired) error) error
}

func (r TestSelectorRef) Valid() bool {
	return validID(r.OrganizationID) && validID(r.WorkspaceID) && validID(r.EnvironmentID) && validID(r.DefinitionID)
}
func TestSelectorID(r TestSelectorRef) (string, error) {
	if !r.Valid() {
		return "", ErrInvalid
	}
	return "test-selector/v1/" + strings.Join([]string{r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.DefinitionID}, "/"), nil
}
func (d TestSelectorDesired) Valid() bool {
	return d.Ref.Valid() && d.SchemaVersion == 1 && d.Revision >= 1 && d.Revision <= 1000000 && d.CadenceSeconds >= 1 && d.CadenceSeconds <= 86400
}

type TestSelectorReconciler struct {
	client  DiscoveryScheduleClient
	source  TestSelectorSource
	queue   string
	timeout time.Duration
}

func NewTestSelectorReconciler(c DiscoveryScheduleClient, s TestSelectorSource, q string, t time.Duration) (*TestSelectorReconciler, error) {
	if c == nil || s == nil || strings.TrimSpace(q) != q || q == "" || len(q) > 255 || t <= 0 || t > 30*time.Second {
		return nil, ErrInvalid
	}
	return &TestSelectorReconciler{c, s, q, t}, nil
}
func (r *TestSelectorReconciler) Reconcile(ctx context.Context, ref TestSelectorRef) error {
	if r == nil || ctx == nil || ctx.Err() != nil || !ref.Valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	called := false
	err := r.source.WithCurrentSelector(bounded, ref, func(d TestSelectorDesired) error {
		if called || bounded.Err() != nil || !d.Valid() || d.Ref != ref {
			return ErrInvalid
		}
		called = true
		id, _ := TestSelectorID(ref)
		prefix := fmt.Sprintf("test-selector-wake/v1/%x", sha256.Sum256([]byte(id)))
		action := &client.ScheduleWorkflowAction{ID: prefix, Workflow: "TestSelectorWorkflow", TaskQueue: r.queue, Args: []any{TestSelectorStart{Ref: ref, Revision: d.Revision}}, WorkflowExecutionTimeout: 2 * time.Minute}
		if d.Automatic {
			action.Workflow = "AutomaticCatchupWorkflow"
			action.Args = []any{AutomaticCatchupStart{Ref: ref, Revision: d.Revision}}
			action.WorkflowExecutionTimeout = 0
		}
		spec := client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: time.Duration(d.CadenceSeconds) * time.Second}}}
		// A selector wake is not a product occurrence. Skipping an overlapping wake
		// is safe: source versions and shared capacity are read in the next admission.
		options := client.ScheduleOptions{ID: id, Spec: spec, Action: action, Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP, CatchupWindow: 10 * time.Second, Paused: !d.Enabled, PauseOnFailure: false}
		_, err := r.client.Create(bounded, options)
		if err == nil {
			if bounded.Err() != nil {
				return ErrScheduleOutcomeUnknown
			}
			return nil
		}
		if !errors.Is(err, temporal.ErrScheduleAlreadyRunning) {
			return ErrScheduleOutcomeUnknown
		}
		h := r.client.GetHandle(bounded, id)
		if h == nil {
			return ErrUnavailable
		}
		err = h.Update(bounded, client.ScheduleUpdateOptions{DoUpdate: func(in client.ScheduleUpdateInput) (*client.ScheduleUpdate, error) {
			a, ok := in.Description.Schedule.Action.(*client.ScheduleWorkflowAction)
			if !ok || a == nil || a.ID != prefix || (a.Workflow != "TestSelectorWorkflow" && a.Workflow != "AutomaticCatchupWorkflow") || a.TaskQueue != r.queue || len(a.Args) != 1 {
				return nil, ErrConflict
			}
			var prior TestSelectorStart
			switch v := a.Args[0].(type) {
			case *commonpb.Payload:
				if v == nil {
					return nil, ErrConflict
				}
				if a.Workflow == "AutomaticCatchupWorkflow" {
					var configured AutomaticCatchupStart
					if converter.GetDefaultDataConverter().FromPayload(v, &configured) != nil || configured.After != "" || configured.Retry {
						return nil, ErrConflict
					}
					prior = TestSelectorStart{Ref: configured.Ref, Revision: configured.Revision}
				} else if converter.GetDefaultDataConverter().FromPayload(v, &prior) != nil {
					return nil, ErrConflict
				}
			case TestSelectorStart:
				if a.Workflow != "TestSelectorWorkflow" {
					return nil, ErrConflict
				}
				prior = v
			case AutomaticCatchupStart:
				if a.Workflow != "AutomaticCatchupWorkflow" || v.After != "" || v.Retry {
					return nil, ErrConflict
				}
				prior = TestSelectorStart{Ref: v.Ref, Revision: v.Revision}
			default:
				return nil, ErrConflict
			}
			if prior.Ref != ref || prior.Revision < 1 || prior.Revision > d.Revision {
				return nil, ErrConflict
			}
			return &client.ScheduleUpdate{Schedule: &client.Schedule{Action: action, Spec: &spec, Policy: &client.SchedulePolicies{Overlap: options.Overlap, CatchupWindow: options.CatchupWindow}, State: &client.ScheduleState{Paused: !d.Enabled}}}, nil
		}})
		if errors.Is(err, ErrConflict) {
			return ErrConflict
		}
		if err != nil || bounded.Err() != nil {
			return ErrScheduleOutcomeUnknown
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !called {
		return ErrUnavailable
	}
	return nil
}

// The Activity performs only current scoped application admission. The73 start
// command is delivered to74 through its existing durable relay, never a lease.
func TestSelectorWorkflow(ctx workflow.Context, q TestSelectorStart) error {
	if !q.Ref.Valid() || q.Revision < 1 || q.Revision > 1000000 {
		return temporal.NewNonRetryableApplicationError("invalid selector reference", "invalid", nil)
	}
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 30 * time.Second, ScheduleToCloseTimeout: 90 * time.Second, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 10 * time.Second, MaximumAttempts: 3}})
	return workflow.ExecuteActivity(ctx, "AdmitTestSelector", q).Get(ctx, nil)
}
