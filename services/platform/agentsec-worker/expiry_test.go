package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

type fakeExpiryScanner struct {
	mu    sync.Mutex
	calls int
	stop  context.CancelFunc
}

func (scanner *fakeExpiryScanner) RunOnce(_ context.Context, organizationID string, at time.Time, workerID string, limit int) (securityagent.ExpiryReport, error) {
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	scanner.calls++
	if organizationID != "org-a" || workerID != "worker-a" || limit != 100 || at.Location() != time.UTC {
		return securityagent.ExpiryReport{}, errRuntimeUnavailable
	}
	if scanner.calls == 2 {
		scanner.stop()
	}
	return securityagent.ExpiryReport{Cleaned: map[bool]int{true: 1, false: 0}[scanner.calls == 1]}, nil
}

func TestExpiryLoopUsesExistingWorkerWithBoundedPeriodicScans(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	scanner := &fakeExpiryScanner{stop: cancel}
	now := time.Date(2026, 8, 18, 22, 0, 0, 0, time.UTC)
	if err := runExpiryLoop(ctx, scanner, "org-a", "worker-a", time.Millisecond, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	if scanner.calls != 2 {
		t.Fatalf("calls=%d", scanner.calls)
	}
}
