package orchestration

import (
	"context"
	"time"
)

// Only SQL can issue this reference. Its digest is not an authorization token;
// every Activity must load the committed command before any compensation.
type SingleTestRecoveryRef struct {
	Start         StartRequest `json:"start"`
	CommandID     string       `json:"command_id"`
	CommandDigest string       `json:"command_digest"`
}

func (r SingleTestRecoveryRef) valid() bool {
	return r.Start.valid() && validID(r.CommandID) && digestPattern.MatchString(r.CommandDigest)
}
func SingleTestRecoveryWorkflowID(r SingleTestRecoveryRef) (string, error) {
	if !r.valid() {
		return "", ErrInvalid
	}
	q := r.Start.Ref
	return "security-agent-test-cleanup/v1/" + q.OrganizationID + "/" + q.WorkspaceID + "/" + q.EnvironmentID + "/" + q.RunID + "/" + r.CommandID, nil
}

type SingleTestOriginalObservation struct {
	WorkflowID string    `json:"workflow_id"`
	RunID      *string   `json:"run_id"`
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
}
type SingleTestOriginalObserver interface {
	ObserveOriginal(context.Context, StartRequest) (SingleTestOriginalObservation, error)
}
type SingleTestRecoveryProduct interface {
	Step(context.Context, SingleTestRecoveryRef) error
}
type SingleTestRecoveryStore interface {
	Pending(context.Context) ([]SingleTestRecoveryRef, error)
	Attempt(context.Context, SingleTestRecoveryRef) error
	Ack(context.Context, SingleTestRecoveryRef) error
}
type SingleTestRecoveryActivities struct {
	Product  SingleTestRecoveryProduct
	lifetime Activities
}

func (a *SingleTestRecoveryActivities) Close(ctx context.Context) error {
	if a == nil {
		return ErrInvalid
	}
	return a.lifetime.Close(ctx)
}
func (a *SingleTestRecoveryActivities) Step(ctx context.Context, r SingleTestRecoveryRef) error {
	if a == nil || a.Product == nil || !r.valid() {
		return activityError(ErrInvalid)
	}
	return a.lifetime.runBorrowed(ctx, r.Start, func(c context.Context) error { return a.Product.Step(c, r) })
}
