package main

import (
	"context"
	"sync"
	"time"
)

func borrowedDiscoveryReadiness(b *discoveryRuntimeBorrowers, ready func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		return b.run(ctx, func() error { return ready(ctx) })
	}
}

// The outbox owns transport clients and its database. Loop cancellation does
// not prove an in-flight publish/readiness call has returned. Keep those clients
// alive on a timed-out join so a later Close can finish the same ownership exit.
func joinDiscoveryOutboxRuntime(deps workerRuntimeDependencies, timeout time.Duration) workerRuntimeDependencies {
	b := &discoveryRuntimeBorrowers{}
	deps.Processor = borrowedDiscoveryProcessor{borrowers: b, processor: deps.Processor}
	deps.Ready = borrowedDiscoveryReadiness(b, deps.Ready)
	closeOwned := deps.Close
	var once sync.Once
	var closeErr error
	deps.Close = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if b.close(ctx) != nil {
			return errRuntimeUnavailable
		}
		once.Do(func() { closeErr = closeOwned() })
		return closeErr
	}
	return deps
}
