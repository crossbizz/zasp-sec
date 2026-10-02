package orchestration

import (
	"errors"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"time"
)

// Starting this workflow grants no authority. Its only Activity must load a
// committed SQL recovery command. Cancellation cannot discharge SQL debt.
func SingleTestOperatorCleanupWorkflow(ctx workflow.Context, r SingleTestRecoveryRef) error {
	if !r.valid() {
		return temporal.NewNonRetryableApplicationError("invalid recovery reference", "InvalidRun", nil)
	}
	detached, _ := workflow.NewDisconnectedContext(ctx)
	detached = workflow.WithActivityOptions(detached, workflow.ActivityOptions{StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: 2 * time.Hour, HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 12}})
	wakes := workflow.GetSignalChannel(detached, "single-test-recovery-wake")
	for n := 0; n < 64; n++ {
		err := workflow.ExecuteActivity(detached, "SingleOperatorCleanup", r).Get(detached, nil)
		if err == nil {
			return nil
		}
		var app *temporal.ApplicationError
		recoverable := temporal.IsTimeoutError(err)
		if errors.As(err, &app) {
			recoverable = app.Type() == "CleanupPending" || app.Type() == "ProductUnavailable" && !app.NonRetryable()
		}
		if !recoverable {
			return err
		}
		timer, cancel := workflow.WithCancel(detached)
		s := workflow.NewSelector(detached)
		s.AddFuture(workflow.NewTimer(timer, 30*time.Second), func(workflow.Future) {})
		s.AddReceive(wakes, func(c workflow.ReceiveChannel, _ bool) { c.Receive(detached, nil) })
		s.Select(detached)
		cancel()
	}
	return workflow.NewContinueAsNewError(detached, SingleTestOperatorCleanupWorkflow, r)
}
