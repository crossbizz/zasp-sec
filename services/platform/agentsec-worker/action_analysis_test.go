package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundActionAnalysisScheduleDrainsAndRetriesIndependently(t *testing.T) {
	now := time.Unix(10, 0)
	n := 0
	p := temporalDiscoveryScheduleProcessor{limit: 2, now: func() time.Time { return now }}
	p.analyze = func(_ context.Context, limit int) (int, error) {
		n++
		if limit != 2 {
			t.Fatal(limit)
		}
		switch n {
		case 1:
			return 0, errWorkerExecution
		case 2:
			return 2, nil
		default:
			return 0, nil
		}
	}
	if !errors.Is(p.analyzeDue(context.Background()), errWorkerExecution) {
		t.Fatal("failed pass suppressed")
	}
	for j := 0; j < 3; j++ {
		if err := p.analyzeDue(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n != 3 {
		t.Fatal("expected error retry, full-batch drain, idle pause", n)
	}
	now = now.Add(time.Minute)
	if err := p.analyzeDue(context.Background()); err != nil || n != 4 {
		t.Fatal(err, n)
	}
}
