package orchestration

import (
	"context"
	"errors"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

var ErrCleanupPending = errors.New("verified cleanup proof pending")

type SingleTestCleanupContinuation struct {
	Start            StartRequest `json:"start"`
	BusinessDeadline time.Time    `json:"business_deadline"`
	Reason           string       `json:"reason"`
	Outcome          string       `json:"outcome"`
}

func (s SingleTestCleanupContinuation) valid() bool {
	return s.Start.valid() && !s.BusinessDeadline.IsZero() &&
		(s.Reason == "terminal" || s.Reason == "workflow_failed" || s.Reason == "workflow_cancelled" || s.Reason == "workflow_deadline") &&
		(s.Outcome == "completed" || s.Outcome == "failed" || s.Outcome == "cancelled")
}

// A continuation never calls Observe, Plan or Test. Only SQL-backed cleanup
// proof can release it; wake payloads carry no product authority.
func SingleTestCleanupWorkflow(ctx workflow.Context, s SingleTestCleanupContinuation) error {
	if !s.valid() || workflow.GetInfo(ctx).ContinuedExecutionRunID == "" {
		return temporal.NewNonRetryableApplicationError("invalid cleanup continuation", "InvalidRun", nil)
	}
	if err := singleTestCleanupLoop(ctx, s); err != nil {
		return err
	}
	switch s.Outcome {
	case "cancelled":
		return temporal.NewCanceledError()
	case "failed":
		return temporal.NewNonRetryableApplicationError("product execution stopped after verified cleanup", "ProductRefused", nil)
	}
	return nil
}

func singleTestCleanupLoop(ctx workflow.Context, s SingleTestCleanupContinuation) error {
	detached, _ := workflow.NewDisconnectedContext(ctx)
	detached = workflow.WithActivityOptions(detached, workflow.ActivityOptions{StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: 2 * time.Hour, HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 12}})
	wakes := workflow.GetSignalChannel(detached, "single-test-wake")
	for observations := 0; observations < 64; observations++ {
		err := workflow.ExecuteActivity(detached, "SingleCleanup", CleanupRequest{Start: s.Start, Reason: s.Reason}).Get(detached, nil)
		if err == nil {
			return nil
		}
		var application *temporal.ApplicationError
		// Exhausting one bounded Activity batch is not evidence that cleanup
		// completed. Recoverable failures remain in this cleanup-only chain.
		// Unknown/permanent contracts stay explicit repair-required failures.
		recoverable := temporal.IsTimeoutError(err)
		if errors.As(err, &application) {
			recoverable = application.Type() == "CleanupPending" || application.Type() == "ProductUnavailable" && !application.NonRetryable()
		}
		if !recoverable {
			return err
		}
		timer, cancel := workflow.WithCancel(detached)
		selector := workflow.NewSelector(detached)
		selector.AddFuture(workflow.NewTimer(timer, 30*time.Second), func(workflow.Future) {})
		selector.AddReceive(wakes, func(channel workflow.ReceiveChannel, _ bool) { channel.Receive(detached, nil) })
		selector.Select(detached)
		cancel()
	}
	return workflow.NewContinueAsNewError(detached, SingleTestCleanupWorkflow, s)
}

type SingleTestProduct interface {
	Observe(context.Context, StartRequest) (RunState, error)
	Plan(context.Context, StartRequest) error
	Test(context.Context, StartRequest) error
	Settle(context.Context, StartRequest) error
	Cleanup(context.Context, CleanupRequest) error
}

type SingleTestActivities struct {
	Product  SingleTestProduct
	lifetime Activities
}

func (a *SingleTestActivities) Close(ctx context.Context) error {
	if a == nil {
		return ErrInvalid
	}
	return a.lifetime.Close(ctx)
}
func (a *SingleTestActivities) run(ctx context.Context, q StartRequest, f func(context.Context) error) error {
	if a == nil || a.Product == nil {
		return activityError(ErrInvalid)
	}
	return a.lifetime.runBorrowed(ctx, q, f)
}
func (a *SingleTestActivities) Observe(ctx context.Context, q StartRequest) (state RunState, err error) {
	err = a.run(ctx, q, func(c context.Context) error { var e error; state, e = a.Product.Observe(c, q); return e })
	switch state.Phase {
	case "planning", "test", "settling", "terminal", "waiting_approval", "pending", "permission_lost", "stopping":
	default:
		if err == nil {
			err = activityError(ErrInvalid)
		}
	}
	return
}
func (a *SingleTestActivities) Plan(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Plan(c, q) })
}
func (a *SingleTestActivities) Test(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Test(c, q) })
}
func (a *SingleTestActivities) Settle(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Settle(c, q) })
}
func (a *SingleTestActivities) Cleanup(ctx context.Context, q CleanupRequest) error {
	switch q.Reason {
	case "terminal", "workflow_failed", "workflow_cancelled", "workflow_deadline":
	default:
		return activityError(ErrInvalid)
	}
	return a.run(ctx, q.Start, func(c context.Context) error { return a.Product.Cleanup(c, q) })
}

// Only scoped immutable references and redacted phases enter history. Child
// completion is an intermediate phase; SQL verifies the parent before terminal.
func SingleTestWorkflow(ctx workflow.Context, q StartRequest) (result error) {
	if !q.valid() {
		return temporal.NewNonRetryableApplicationError("invalid scoped run", "InvalidRun", nil)
	}
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: time.Hour, HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 5}})
	deadline := workflow.Now(ctx).Add(24 * time.Hour)
	reason := "workflow_failed"
	defer func() {
		outcome := "completed"
		if result != nil {
			outcome = "failed"
		}
		if ctx.Err() != nil || temporal.IsCanceledError(result) {
			reason = "workflow_cancelled"
			outcome = "cancelled"
		}
		if err := singleTestCleanupLoop(ctx, SingleTestCleanupContinuation{Start: q, BusinessDeadline: deadline, Reason: reason, Outcome: outcome}); err != nil {
			result = err
		}
	}()
	wakes := workflow.GetSignalChannel(ctx, "single-test-wake")
	previous := ""
	for workflow.Now(ctx).Before(deadline) {
		var state RunState
		if err := workflow.ExecuteActivity(ctx, "SingleObserve", q).Get(ctx, &state); err != nil {
			return err
		}
		action := ""
		switch state.Phase {
		case "planning":
			action = "SinglePlan"
		case "test":
			action = "SingleTest"
		case "settling":
			action = "SingleSettle"
		case "terminal":
			reason = "terminal"
			return nil
		case "waiting_approval", "pending":
		default:
			return temporal.NewNonRetryableApplicationError("product execution stopped", "ProductRefused", nil)
		}
		if action != "" && previous != state.Phase {
			if err := workflow.ExecuteActivity(ctx, action, q).Get(ctx, nil); err != nil {
				return err
			}
			previous = state.Phase
			continue
		}
		previous = ""
		timerCtx, cancel := workflow.WithCancel(ctx)
		selector := workflow.NewSelector(ctx)
		selector.AddFuture(workflow.NewTimer(timerCtx, 30*time.Second), func(workflow.Future) {})
		selector.AddReceive(wakes, func(channel workflow.ReceiveChannel, _ bool) { channel.Receive(ctx, nil) })
		selector.Select(ctx)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	reason = "workflow_deadline"
	return temporal.NewNonRetryableApplicationError("product execution deadline reached", "ExecutionDeadline", nil)
}
