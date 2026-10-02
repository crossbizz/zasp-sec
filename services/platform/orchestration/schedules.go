package orchestration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
)

// ErrScheduleOutcomeUnknown requires durable redelivery and reconciliation.
// A timed-out RPC may still apply after the serialization session is released.
var ErrScheduleOutcomeUnknown = errors.New("schedule write outcome unknown")

type DiscoveryScheduleRef struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ScheduleID     string `json:"schedule_id"`
	IntegrationID  string `json:"integration_id"`
}

func (r DiscoveryScheduleRef) valid() bool {
	return validID(r.OrganizationID) && validID(r.WorkspaceID) && validID(r.EnvironmentID) && validID(r.ScheduleID) && validID(r.IntegrationID)
}

func DiscoveryScheduleID(r DiscoveryScheduleRef) (string, error) {
	if !r.valid() {
		return "", ErrInvalid
	}
	return "discovery-schedule/v1/" + strings.Join([]string{r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.ScheduleID, r.IntegrationID}, "/"), nil
}

type DiscoveryScheduleDesired struct {
	Ref            DiscoveryScheduleRef
	Revision       int64
	CadenceSeconds int
	Anchor         time.Time
	Enabled        bool
}

func (d DiscoveryScheduleDesired) valid() bool {
	return d.Ref.valid() && d.Revision >= 1 && d.Revision <= 1000000 && d.CadenceSeconds >= 300 && d.CadenceSeconds <= 2678400 && !d.Anchor.IsZero() && d.Anchor.Location() == time.UTC && d.Anchor.Unix() >= 0
}

// WithCurrentSchedule must serialize the canonical tenant+schedule across
// instances and read current configuration after acquiring that serialization.
// Configuration writers either share it or atomically persist a new revision
// and durable change delivery. The callback must finish before session release.
// Use a bounded dedicated session, never a SQL transaction across Temporal RPC.
// This does NOT fence late RPCs; admission and each fresh provider effect must
// independently check current enabled/connector authority. Implemented in P4B.
type DiscoveryScheduleSource interface {
	WithCurrentSchedule(context.Context, DiscoveryScheduleRef, func(DiscoveryScheduleDesired) error) error
	// ReconcileDiscoveryDue uses the same atomic coalescing admission as ticks:
	// current scope/revision/connector checks, persisted oldest DueAt, DB now,
	// one admitted occurrence + first future due + durable start delivery.
	// Run after acknowledged Schedule writes, including recreation/startup.
	// Error/ambiguity MUST keep the desired change pending for durable retry.
	ReconcileDiscoveryDue(context.Context, DiscoveryScheduleRef) error
}

type DiscoveryScheduleClient interface {
	Create(context.Context, client.ScheduleOptions) (client.ScheduleHandle, error)
	GetHandle(context.Context, string) client.ScheduleHandle
}

type DiscoveryScheduleReconciler struct {
	client  DiscoveryScheduleClient
	source  DiscoveryScheduleSource
	queue   string
	timeout time.Duration
}

func NewDiscoveryScheduleReconciler(c DiscoveryScheduleClient, s DiscoveryScheduleSource, queue string, timeout time.Duration) (*DiscoveryScheduleReconciler, error) {
	if c == nil || s == nil || strings.TrimSpace(queue) != queue || queue == "" || len(queue) > 255 || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &DiscoveryScheduleReconciler{c, s, queue, timeout}, nil
}

// Reconcile consumes only a reference, never stale desired state from an event.
// A nil result means that write was acknowledged, not cross-store atomicity.
func (r *DiscoveryScheduleReconciler) Reconcile(ctx context.Context, ref DiscoveryScheduleRef) error {
	if r == nil || ctx == nil || ctx.Err() != nil || !ref.valid() {
		return ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	called := false
	err := r.source.WithCurrentSchedule(bounded, ref, func(d DiscoveryScheduleDesired) error {
		if called || bounded.Err() != nil || !d.valid() || d.Ref != ref {
			return ErrInvalid
		}
		called = true
		options := r.options(d)
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
		// SDK Update does not send a conflict token. The source's scoped
		// serialization and durable redelivery are required, not an optional cache.
		handle := r.client.GetHandle(bounded, options.ID)
		if handle == nil {
			return ErrUnavailable
		}
		err = handle.Update(bounded, client.ScheduleUpdateOptions{DoUpdate: func(input client.ScheduleUpdateInput) (*client.ScheduleUpdate, error) {
			existing, ok := input.Description.Schedule.Action.(*client.ScheduleWorkflowAction)
			if !ok || existing == nil || (existing.ID != options.Action.(*client.ScheduleWorkflowAction).ID && existing.ID != options.ID+"/occurrence") || existing.Workflow != "DiscoveryScheduledWorkflow" || existing.TaskQueue != r.queue || len(existing.Args) != 1 {
				return nil, ErrConflict
			}
			var prior DiscoveryScheduleStart
			switch value := existing.Args[0].(type) {
			case *commonpb.Payload:
				if value == nil || converter.GetDefaultDataConverter().FromPayload(value, &prior) != nil {
					return nil, ErrConflict
				}
			case DiscoveryScheduleStart:
				prior = value
			default:
				return nil, ErrConflict
			}
			if prior.Ref != ref || prior.Revision < 1 || prior.Revision > d.Revision {
				return nil, ErrConflict
			}
			return &client.ScheduleUpdate{Schedule: &client.Schedule{Action: options.Action, Spec: &options.Spec, Policy: &client.SchedulePolicies{Overlap: options.Overlap, CatchupWindow: options.CatchupWindow, PauseOnFailure: options.PauseOnFailure}, State: &client.ScheduleState{Paused: options.Paused}}}, nil
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
	return r.source.ReconcileDiscoveryDue(bounded, ref)
}

func (r *DiscoveryScheduleReconciler) options(d DiscoveryScheduleDesired) client.ScheduleOptions {
	id, _ := DiscoveryScheduleID(d.Ref)
	// Temporal appends a nominal timestamp to this prefix. Keep the full scoped
	// identity in the digest and argument, within the service's workflow ID bound.
	digest := sha256.Sum256([]byte(id))
	actionID := "discovery-occurrence/v1/" + hex.EncodeToString(digest[:])
	// Temporal interval occurrences have whole-second precision. Ceiling is a
	// wakeup projection only; product SQL retains the original anchor and due ID.
	wakeup := d.Anchor
	if wakeup.Nanosecond() != 0 {
		wakeup = wakeup.Truncate(time.Second).Add(time.Second)
	}
	return client.ScheduleOptions{
		ID:   id,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: time.Duration(d.CadenceSeconds) * time.Second, Offset: time.Duration(wakeup.Unix()%int64(d.CadenceSeconds)) * time.Second}}, StartAt: wakeup},
		// This is the admission wakeup. The outbox starts the collection workflow
		// with its own fixed fresh-work budget and bounded evidence-only settlement.
		Action: &client.ScheduleWorkflowAction{ID: actionID, Workflow: "DiscoveryScheduledWorkflow", Args: []interface{}{DiscoveryScheduleStart{Ref: d.Ref, Revision: d.Revision}}, TaskQueue: r.queue, WorkflowExecutionTimeout: 24 * time.Hour},
		// Legacy admission allowed distinct manual/periodic runs to coexist. Provider
		// serialization belongs to the scoped generation authority, not Schedule SKIP.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_ALLOW_ALL,
		// A recent tick wakes coalescing admission after outage. SQL admits the
		// persisted oldest due once, skips elapsed slots, and rejects duplicate
		// wakeups. ReconcileDiscoveryDue also repairs recreated/missing schedules.
		CatchupWindow: time.Duration(d.CadenceSeconds) * time.Second,
		Paused:        !d.Enabled, PauseOnFailure: false, TriggerImmediately: false,
	}
}

type DiscoveryDuePlan struct {
	DueAt     time.Time
	NextDueAt time.Time
}

// PlanDiscoveryDue expresses product cadence policy, not a scheduler or
// authorization. P4B must apply it atomically under the exact scoped schedule
// lock using DB time, committing occurrence admission, next due and outbox
// together. A tick's nominal time never replaces persistedDue.
func PlanDiscoveryDue(persistedDue, now time.Time, cadenceSeconds int) (DiscoveryDuePlan, bool, error) {
	if persistedDue.IsZero() || now.IsZero() || persistedDue.Location() != time.UTC || now.Location() != time.UTC || cadenceSeconds < 300 || cadenceSeconds > 2678400 {
		return DiscoveryDuePlan{}, false, ErrInvalid
	}
	if persistedDue.After(now) {
		return DiscoveryDuePlan{}, false, nil
	}
	cadence := time.Duration(cadenceSeconds) * time.Second
	elapsed := now.Sub(persistedDue)
	if elapsed == time.Duration(math.MaxInt64) {
		return DiscoveryDuePlan{}, false, ErrInvalid
	}
	intervals := elapsed/cadence + 1
	if int64(intervals) > math.MaxInt64/int64(cadence) {
		return DiscoveryDuePlan{}, false, ErrInvalid
	}
	next := persistedDue.Add(intervals * cadence)
	if !next.After(now) {
		return DiscoveryDuePlan{}, false, ErrInvalid
	}
	return DiscoveryDuePlan{DueAt: persistedDue, NextDueAt: next}, true, nil
}
