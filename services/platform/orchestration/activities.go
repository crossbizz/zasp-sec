package orchestration

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
)

type RunState struct {
	Phase string `json:"phase"`
}
type CleanupRequest struct {
	Start  StartRequest `json:"start"`
	Reason string       `json:"reason"`
}

// Product owns all authority, version/approval checks and effect evidence.
// Implementations must not return provider data through this boundary.
type Product interface {
	Observe(context.Context, StartRequest) (RunState, error)
	Plan(context.Context, StartRequest) error
	Apply(context.Context, StartRequest) error
	Advance(context.Context, StartRequest) error
	Test(context.Context, StartRequest) error
	Cleanup(context.Context, CleanupRequest) error
}
type Activities struct {
	Product Product
	mu      sync.Mutex
	closing bool
	active  int
	drained chan struct{}
}

// Close stops admission and joins borrowed product clients. On timeout the
// owner must retain those clients and retry Close after outstanding work joins.
func (a *Activities) Close(ctx context.Context) error {
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

func (a *Activities) Observe(ctx context.Context, q StartRequest) (RunState, error) {
	var state RunState
	err := a.run(ctx, q, func(ctx context.Context) error { var err error; state, err = a.Product.Observe(ctx, q); return err })
	switch state.Phase {
	case "planning", "apply", "advance", "test", "terminal", "waiting_approval", "pending", "stale", "permission_lost":
	default:
		if err == nil {
			err = activityError(ErrInvalid)
		}
	}
	return state, err
}
func (a *Activities) Plan(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Plan(c, q) })
}
func (a *Activities) Apply(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Apply(c, q) })
}
func (a *Activities) Advance(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Advance(c, q) })
}
func (a *Activities) Test(ctx context.Context, q StartRequest) error {
	return a.run(ctx, q, func(c context.Context) error { return a.Product.Test(c, q) })
}
func (a *Activities) Cleanup(ctx context.Context, q CleanupRequest) error {
	switch q.Reason {
	case "terminal", "workflow_cancelled", "workflow_deadline", "workflow_failed":
	default:
		return activityError(ErrInvalid)
	}
	return a.run(ctx, q.Start, func(c context.Context) error { return a.Product.Cleanup(c, q) })
}

func (a *Activities) run(ctx context.Context, q StartRequest, work func(context.Context) error) error {
	if a == nil || a.Product == nil || ctx == nil || !q.valid() {
		return activityError(ErrInvalid)
	}
	return a.runBorrowed(ctx, q, work)
}

// Shared borrowed-client lifetime only. It has no product or execution protocol.
func (a *Activities) runBorrowed(ctx context.Context, q StartRequest, work func(context.Context) error) error {
	if a == nil || ctx == nil || !q.valid() || work == nil {
		return activityError(ErrInvalid)
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return activityError(ErrUnavailable)
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
	heartbeatCtx, stop := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				activity.RecordHeartbeat(ctx)
			}
		}
	}()
	defer func() { stop(); <-joined }()
	return activityError(work(ctx))
}

func activityError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrCleanupPending) {
		return temporal.NewNonRetryableApplicationError("verified cleanup proof pending", "CleanupPending", nil)
	}
	if errors.Is(err, context.Canceled) {
		return temporal.NewCanceledError()
	}
	var sql interface{ SQLState() string }
	permanent := errors.Is(err, ErrInvalid) || errors.Is(err, ErrConflict)
	if errors.As(err, &sql) {
		switch sql.SQLState() {
		case "22023", "42501", "40001":
			permanent = true
		}
	}
	if permanent {
		return temporal.NewNonRetryableApplicationError("product validation or authority rejected", "ProductRefused", nil)
	}
	// Underlying database/provider errors may contain credentials or bodies.
	return temporal.NewApplicationError("product operation unavailable", "ProductUnavailable")
}
