package orchestration

import (
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"time"
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
