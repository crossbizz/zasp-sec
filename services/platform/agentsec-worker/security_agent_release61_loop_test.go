package main

import (
	"context"
	"testing"
	"time"
)

func TestRelease61LoopRejectsUnboundedOrCancelledWork(t *testing.T) {
	r := &securityAgentRelease61Runtime{}
	loop, ok := any(r).(interface {
		Run(context.Context, time.Duration) error
	})
	if !ok {
		t.Fatal("bounded dormant release61 loop absent")
	}
	if loop.Run(nil, time.Second) == nil {
		t.Fatal("nil context accepted")
	}
	for _, delay := range []time.Duration{-1, 0, time.Hour} {
		if loop.Run(context.Background(), delay) == nil {
			t.Fatal("unbounded loop accepted", delay)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := time.Now()
	if loop.Run(ctx, time.Second) != context.Canceled || time.Since(before) > time.Second {
		t.Fatal("caller cancellation lost")
	}
	if loop.Run(context.Background(), time.Second) == nil {
		t.Fatal("unconfigured runtime loop accepted")
	}
}

func TestRelease61LoopBackoffCancellationAndErrorStop(t *testing.T) {
	calls := 0
	start := time.Now()
	if err := runRelease61Ticks(context.Background(), 100*time.Millisecond, func(context.Context) (string, error) {
		calls++
		if calls == 3 {
			return "terminal", nil
		}
		return "approval_pause", nil
	}); err != nil || calls != 3 || time.Since(start) < 200*time.Millisecond {
		t.Fatal("busy loop or terminal replay", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls = 0
	timer := time.AfterFunc(25*time.Millisecond, cancel)
	defer timer.Stop()
	if err := runRelease61Ticks(ctx, time.Second, func(context.Context) (string, error) { calls++; return "lease_wait", nil }); err != context.Canceled || calls != 1 {
		t.Fatal("backoff ignored cancellation", calls, err)
	}
	calls = 0
	if err := runRelease61Ticks(context.Background(), time.Second, func(context.Context) (string, error) { calls++; return "", errWorkerExecution }); err != errWorkerExecution || calls != 1 {
		t.Fatal("failed owner was retried", calls, err)
	}
}
