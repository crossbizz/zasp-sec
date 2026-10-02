package orchestration

import (
	"errors"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

func compensate(ctx workflow.Context, request StartRequest, reason string) error {
	detached, _ := workflow.NewDisconnectedContext(ctx)
	detached = workflow.WithActivityOptions(detached, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: 2 * time.Hour,
		HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 12},
	})
	// A completed Activity means verified compensation, never accepted delivery.
	// Exhausted recovery leaves the durable product pending/unknown and fails.
	return workflow.ExecuteActivity(detached, "Cleanup", CleanupRequest{Start: request, Reason: reason}).Get(detached, nil)
}

// Cleanup continuations retain the admitted effect identity and original outcome.
// They contain no provider data and cannot authorize another forward action.
type SecurityAgentCleanupContinuation struct {
	Start            StartRequest `json:"start"`
	BusinessDeadline time.Time    `json:"business_deadline"`
	Reason           string       `json:"reason"`
	Outcome          string       `json:"outcome"`
}

func (s SecurityAgentCleanupContinuation) valid() bool {
	if !s.Start.valid() || s.BusinessDeadline.IsZero() {
		return false
	}
	switch s.Reason {
	case "terminal":
		return s.Outcome == "completed"
	case "workflow_failed", "workflow_deadline":
		return s.Outcome == "failed"
	case "workflow_cancelled":
		return s.Outcome == "cancelled"
	}
	return false
}

// Only a continued execution may enter this cleanup-only recovery path.
func SecurityAgentCleanupWorkflow(ctx workflow.Context, s SecurityAgentCleanupContinuation) error {
	if !s.valid() || workflow.GetInfo(ctx).ContinuedExecutionRunID == "" {
		return temporal.NewNonRetryableApplicationError("invalid cleanup continuation", "InvalidRun", nil)
	}
	if err := securityAgentCleanupLoop(ctx, s); err != nil {
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

func securityAgentCleanupLoop(ctx workflow.Context, s SecurityAgentCleanupContinuation) error {
	detached, _ := workflow.NewDisconnectedContext(ctx)
	detached = workflow.WithActivityOptions(detached, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: 2 * time.Hour,
		HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 12},
	})
	wakes := workflow.GetSignalChannel(detached, "product-decision")
	for observations := 0; observations < 64; observations++ {
		err := workflow.ExecuteActivity(detached, "Cleanup", CleanupRequest{Start: s.Start, Reason: s.Reason}).Get(detached, nil)
		if err == nil {
			return nil
		}
		var application *temporal.ApplicationError
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
	return workflow.NewContinueAsNewError(detached, SecurityAgentCleanupWorkflow, s)
}
