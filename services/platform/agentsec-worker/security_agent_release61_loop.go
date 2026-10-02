package main

import (
	"context"
	"time"
)

// Run is opt-in only. Errors stop this local owner; it never retries a failed
// external operation. A caller may start a fresh owner, which rereads SQL.
func (r *securityAgentRelease61Runtime) Run(ctx context.Context, backoff time.Duration) error {
	return runRelease61Ticks(ctx, backoff, r.Tick)
}

func runRelease61Ticks(ctx context.Context, backoff time.Duration, tick func(context.Context) (string, error)) error {
	if ctx == nil || backoff < 100*time.Millisecond || backoff > 30*time.Second || tick == nil {
		return errWorkerExecution
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		transition, err := tick(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		if transition == "terminal" {
			return nil
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
