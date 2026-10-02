package orchestration

import (
	"context"
	"sync"
)

type AutomaticProduct interface {
	AutomaticSourcePage(context.Context, AutomaticSourceStart) (AutomaticPage, error)
	AutomaticCatchupPage(context.Context, AutomaticCatchupStart) (AutomaticPage, error)
}

// Borrowed database clients cannot close while a page transaction is running.
// This owner tracks only local lifetime, never delivery or source progress.
type AutomaticActivities struct {
	Product AutomaticProduct
	mu      sync.Mutex
	closing bool
	active  int
	drained chan struct{}
}

func (a *AutomaticActivities) Close(ctx context.Context) error {
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
func (a *AutomaticActivities) run(ctx context.Context, after string, work func() (AutomaticPage, error)) (AutomaticPage, error) {
	if a == nil || a.Product == nil || ctx == nil || (after != "" && !validID(after)) {
		return AutomaticPage{}, activityError(ErrInvalid)
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return AutomaticPage{}, activityError(ErrUnavailable)
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
	p, err := work()
	if err == nil && !p.Valid(after) {
		err = ErrInvalid
	}
	return p, activityError(err)
}
func (a *AutomaticActivities) Source(ctx context.Context, q AutomaticSourceStart) (AutomaticPage, error) {
	if !q.Ref.Valid() {
		return AutomaticPage{}, activityError(ErrInvalid)
	}
	return a.run(ctx, q.After, func() (AutomaticPage, error) { return a.Product.AutomaticSourcePage(ctx, q) })
}
func (a *AutomaticActivities) Catchup(ctx context.Context, q AutomaticCatchupStart) (AutomaticPage, error) {
	if !q.Ref.Valid() || q.Revision < 1 || q.Revision > 1000000 {
		return AutomaticPage{}, activityError(ErrInvalid)
	}
	return a.run(ctx, q.After, func() (AutomaticPage, error) { return a.Product.AutomaticCatchupPage(ctx, q) })
}
