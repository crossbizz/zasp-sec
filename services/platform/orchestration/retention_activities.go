package orchestration

import (
	"context"
	"sync"

	"go.temporal.io/sdk/activity"
)

// Sweep commits atomic SQL expiry and its durable receipt before returning.
// A retry with the same cycle key returns that receipt, not a second sweep.
type RetentionStore interface {
	Sweep(context.Context, string) (RetentionCounters, error)
}

type RetentionActivities struct {
	Store   RetentionStore
	mu      sync.Mutex
	closing bool
	active  int
	drained chan struct{}
}

// Close stops admission and joins transactions before their owner closes the
// database. On timeout, the owner must retain the client and retry Close.
func (a *RetentionActivities) Close(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrInvalid
	}
	a.mu.Lock()
	if !a.closing {
		a.closing = true
		a.drained = make(chan struct{})
		if a.active == 0 {
			close(a.drained)
		}
	}
	drained := a.drained
	a.mu.Unlock()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *RetentionActivities) Sweep(ctx context.Context, cycle RetentionCycle) (out RetentionCounters, resultErr error) {
	defer func() {
		if recover() != nil {
			out = RetentionCounters{}
			resultErr = activityError(ErrUnavailable)
		}
	}()
	if a == nil || a.Store == nil || ctx == nil || !cycle.Valid() {
		return RetentionCounters{}, activityError(ErrInvalid)
	}
	if ctx.Err() != nil {
		return RetentionCounters{}, activityError(ctx.Err())
	}
	info := activity.GetInfo(ctx)
	if info.WorkflowExecution.ID != cycle.WorkflowID || info.WorkflowExecution.RunID != cycle.RunID || info.ActivityType.Name != RetentionActivityName {
		return RetentionCounters{}, activityError(ErrInvalid)
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return RetentionCounters{}, activityError(ErrUnavailable)
	}
	a.active++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.active--
		if a.closing && a.active == 0 {
			close(a.drained)
		}
	}()
	key, _ := cycle.Key()
	result, err := a.Store.Sweep(ctx, key)
	if err != nil {
		return RetentionCounters{}, activityError(err)
	}
	if !result.Valid() {
		return RetentionCounters{}, activityError(ErrInvalid)
	}
	return result, nil
}
