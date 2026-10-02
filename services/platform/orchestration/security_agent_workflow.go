package orchestration

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SecurityAgentWorkflow carries only immutable scoped references and redacted
// product state. Every next action follows a fresh authoritative product read.
func SecurityAgentWorkflow(ctx workflow.Context, request StartRequest) (result error) {
	if !request.valid() {
		return temporal.NewNonRetryableApplicationError("invalid scoped run", "InvalidRun", nil)
	}
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: time.Hour,
		HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 5},
	})
	reason := "workflow_failed"
	defer func() {
		if ctx.Err() != nil || temporal.IsCanceledError(result) {
			reason = "workflow_cancelled"
		}
		cleanupErr := compensate(ctx, request, reason)
		if cleanupErr != nil {
			result = cleanupErr
		}
	}()
	deadline := workflow.Now(ctx).Add(24 * time.Hour)
	signals := workflow.GetSignalChannel(ctx, "product-decision")
	lastActionPhase := ""
	for workflow.Now(ctx).Before(deadline) {
		var state RunState
		if err := workflow.ExecuteActivity(ctx, "Observe", request).Get(ctx, &state); err != nil {
			return err
		}
		var action string
		switch state.Phase {
		case "planning":
			action = "Plan"
		case "apply":
			action = "Apply"
		case "advance":
			action = "Advance"
		case "test":
			action = "Test"
		case "terminal":
			reason = "terminal"
			return nil
		case "waiting_approval", "pending":
		default:
			return temporal.NewNonRetryableApplicationError("product authority refused execution", "ProductRefused", nil)
		}
		if action != "" && state.Phase != lastActionPhase {
			if err := workflow.ExecuteActivity(ctx, action, request).Get(ctx, nil); err != nil {
				return err
			}
			lastActionPhase = state.Phase
			continue
		}
		lastActionPhase = ""
		// A signal is only a wakeup. In particular its claimed decision and scope
		// never alter workflow authority; Observe verifies committed SQL state.
		timerCtx, cancel := workflow.WithCancel(ctx)
		timer := workflow.NewTimer(timerCtx, 30*time.Second)
		selector := workflow.NewSelector(ctx)
		selector.AddFuture(timer, func(workflow.Future) {})
		selector.AddReceive(signals, func(channel workflow.ReceiveChannel, _ bool) { channel.Receive(ctx, nil) })
		selector.Select(ctx)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	reason = "workflow_deadline"
	return temporal.NewNonRetryableApplicationError("product execution deadline reached", "ExecutionDeadline", nil)
}
