package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type discoveryLifecycleProcessor func(context.Context) error

func (f discoveryLifecycleProcessor) RunOnce(ctx context.Context) error { return f(ctx) }

// Missing borrower coverage must not let Close destroy clients underneath a
// canceled outbox publish or an in-flight readiness operation.
func TestDiscoveryOutboxLifecycleRetainsBorrowers(t *testing.T) {
	for _, operation := range []string{"ready", "canceled_processor"} {
		t.Run(operation, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseCall := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseCall()
			var closed, calls atomic.Int32
			work := func(ctx context.Context) error {
				if calls.Add(1) != 1 {
					return nil
				}
				close(entered)
				<-release
				if closed.Load() != 0 {
					return errRuntimeUnavailable
				}
				return ctx.Err()
			}
			deps := joinDiscoveryOutboxRuntime(workerRuntimeDependencies{Processor: discoveryLifecycleProcessor(work), Ready: work, Close: func() error { closed.Add(1); return nil }}, 10*time.Millisecond)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "ready" {
					done <- deps.Ready(ctx)
				} else {
					done <- deps.Processor.RunOnce(ctx)
				}
			}()
			<-entered
			if operation != "ready" {
				cancel()
			}
			if err := deps.Close(); err == nil || closed.Load() != 0 {
				t.Errorf("timed-out join closed borrowed clients: err=%v closes=%d", err, closed.Load())
			}
			// Both entry points must refuse without reaching the owned client.
			if deps.Ready(context.Background()) == nil || deps.Processor.RunOnce(context.Background()) == nil || calls.Load() != 1 {
				t.Error("accepted new call after closing")
			}
			releaseCall()
			err := <-done
			if operation == "ready" && err != nil || operation != "ready" && err != context.Canceled {
				t.Error("borrowed client lost before completion", err)
			}
			if deps.Close() != nil || deps.Close() != nil || closed.Load() != 1 {
				t.Error("retry did not join and close exactly once", closed.Load())
			}
		})
	}
}

func TestDiscoveryReadinessJoinsSharedActivityBorrowers(t *testing.T) {
	b := &discoveryRuntimeBorrowers{}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	ready := borrowedDiscoveryReadiness(b, func(context.Context) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	go func() { done <- ready(context.Background()) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b.close(ctx) == nil {
		t.Error("readiness not retained by shared Activity join")
	}
	close(release)
	if <-done != nil || b.close(context.Background()) != nil || ready(context.Background()) == nil {
		t.Fatal("readiness close/retry contract")
	}
}
