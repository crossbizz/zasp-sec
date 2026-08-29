package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunLifecycleWorkersStartsAllAndCancelsSiblings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var firstStarted, secondStarted atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- runLifecycleWorkers(ctx,
			func(workerContext context.Context) error {
				firstStarted.Store(true)
				<-workerContext.Done()
				return workerContext.Err()
			},
			func(workerContext context.Context) error {
				secondStarted.Store(true)
				<-workerContext.Done()
				return workerContext.Err()
			},
		)
	}()
	deadline := time.Now().Add(time.Second)
	for (!firstStarted.Load() || !secondStarted.Load()) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !firstStarted.Load() || !secondStarted.Load() {
		t.Fatal("lifecycle workers did not both start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle workers did not stop")
	}
}

func TestRunLifecycleWorkersFailsClosedWhenOneWorkerStops(t *testing.T) {
	siblingCanceled := make(chan struct{})
	err := runLifecycleWorkers(context.Background(),
		func(context.Context) error { return errors.New("provider detail") },
		func(workerContext context.Context) error {
			<-workerContext.Done()
			close(siblingCanceled)
			return workerContext.Err()
		},
	)
	if !errors.Is(err, errRuntimeUnavailable) || err.Error() != errRuntimeUnavailable.Error() {
		t.Fatalf("worker error=%v", err)
	}
	select {
	case <-siblingCanceled:
	case <-time.After(time.Second):
		t.Fatal("failed worker did not cancel sibling")
	}
}

func TestRunLifecycleWorkersRejectsInvalidConfiguration(t *testing.T) {
	if err := runLifecycleWorkers(context.Background()); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("empty workers error=%v", err)
	}
	if err := runLifecycleWorkers(context.Background(), nil); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("nil worker error=%v", err)
	}
}
