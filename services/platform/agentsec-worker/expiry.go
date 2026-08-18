package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

type expiryScanner interface {
	RunOnce(context.Context, string, time.Time, string, int) (securityagent.ExpiryReport, error)
}

func runExpiryLoop(ctx context.Context, scanner expiryScanner, organizationID, workerID string, interval time.Duration, now func() time.Time) error {
	if ctx == nil || scanner == nil || !validLoopValue(organizationID) || !validLoopValue(workerID) || interval <= 0 || interval > time.Hour || now == nil {
		return errRuntimeUnavailable
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		at := now()
		if at.Location() != time.UTC {
			return errRuntimeUnavailable
		}
		if _, err := scanner.RunOnce(ctx, organizationID, at, workerID, 100); err != nil {
			return errRuntimeUnavailable
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func validLoopValue(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
