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
	// Existing histories retain their original commands; new executions fence
	// fresh work at the workflow deadline without changing cleanup authority.
	boundedWork := workflow.GetVersion(ctx, "security-agent-fresh-work-deadline-v1", workflow.DefaultVersion, 1) != workflow.DefaultVersion
	deadline := workflow.Now(ctx).Add(24 * time.Hour)
	reason := "workflow_failed"
	defer func() {
		if boundedWork && result != nil && !workflow.Now(ctx).Before(deadline) {
			reason = "workflow_deadline"
		}
		if ctx.Err() != nil || temporal.IsCanceledError(result) {
			reason = "workflow_cancelled"
		}
		cleanupErr := compensate(ctx, request, reason)
		if cleanupErr != nil {
			result = cleanupErr
		}
	}()
	signals := workflow.GetSignalChannel(ctx, "product-decision")
	lastActionPhase := ""
	for workflow.Now(ctx).Before(deadline) {
		var state RunState
		activityCtx := ctx
		if boundedWork {
			activityCtx = securityAgentRemainingActivityContext(ctx, deadline)
		}
		if err := workflow.ExecuteActivity(activityCtx, "Observe", request).Get(ctx, &state); err != nil {
			return err
		}
		if boundedWork && !workflow.Now(ctx).Before(deadline) {
			break
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
			if boundedWork {
				activityCtx = securityAgentRemainingActivityContext(ctx, deadline)
			}
			if err := workflow.ExecuteActivity(activityCtx, action, request).Get(ctx, nil); err != nil {
				return err
			}
			lastActionPhase = state.Phase
			continue
		}
		lastActionPhase = ""
		// A signal is only a wakeup. In particular its claimed decision and scope
		// never alter workflow authority; Observe verifies committed SQL state.
		timerCtx, cancel := workflow.WithCancel(ctx)
		wait := 30 * time.Second
		if boundedWork && deadline.Sub(workflow.Now(ctx)) < wait {
			wait = deadline.Sub(workflow.Now(ctx))
		}
		timer := workflow.NewTimer(timerCtx, wait)
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

// A fresh activity may retry only inside the remaining workflow budget. The
// disconnected compensation context deliberately keeps its original limits.
func securityAgentRemainingActivityContext(ctx workflow.Context, deadline time.Time) workflow.Context {
	options := workflow.GetActivityOptions(ctx)
	remaining := deadline.Sub(workflow.Now(ctx))
	if options.StartToCloseTimeout > remaining {
		options.StartToCloseTimeout = remaining
	}
	if options.ScheduleToCloseTimeout > remaining {
		options.ScheduleToCloseTimeout = remaining
	}
	return workflow.WithActivityOptions(ctx, options)
}
