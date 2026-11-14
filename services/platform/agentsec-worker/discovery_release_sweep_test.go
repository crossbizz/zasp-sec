package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The scheduler releases abandoned discovery runs on a timer: once per
// interval, again after a failure, and with the processor's batch bound.
func TestScheduleProcessorReleasesAbandonedRunsOnATimer(t *testing.T) {
	at := time.Date(2026, 11, 14, 4, 0, 0, 0, time.UTC)
	var calls []int
	var fail error
	p := &temporalDiscoveryScheduleProcessor{limit: 25, now: func() time.Time { return at },
		release: func(_ context.Context, limit int) (int, error) { calls = append(calls, limit); return 0, fail }}
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 1 || calls[0] != 25 {
		t.Fatalf("first pass err=%v calls=%v", err, calls)
	}
	at = at.Add(discoveryReleaseInterval - time.Second)
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 1 {
		t.Fatalf("pass inside the interval err=%v calls=%v", err, calls)
	}
	at = at.Add(time.Second)
	fail = errors.New("database unavailable")
	if err := p.releaseDue(context.Background()); err == nil || len(calls) != 2 {
		t.Fatalf("failed sweep err=%v calls=%v", err, calls)
	}
	// A failed sweep does not wait for the next interval.
	fail = nil
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("retry after failure err=%v calls=%v", err, calls)
	}
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("pass after success err=%v calls=%v", err, calls)
	}
}
