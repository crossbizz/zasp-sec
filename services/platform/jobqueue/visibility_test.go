package jobqueue

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type visibilityRecordingDriver struct {
	*recordingDriver
	extend func(context.Context, []DriverReceipt, int32) ([]domain.ProductID, error)
}

func (driver *visibilityRecordingDriver) ExtendVisibility(ctx context.Context, receipts []DriverReceipt, seconds int32) ([]domain.ProductID, error) {
	return driver.extend(ctx, receipts, seconds)
}

func TestQueueExtendsVisibilityForExactOwnedReceipts(t *testing.T) {
	t.Parallel()
	base := noCallDriver()
	driver := &visibilityRecordingDriver{recordingDriver: base}
	queue := mustQueue(t, driver, validConfig())
	jobs := fixtureJobs(t)
	receipts := []Receipt{fixtureReceipt(queue, jobs[0].JobID, "1"), fixtureReceipt(queue, jobs[1].JobID, "2")}
	driver.extend = func(ctx context.Context, values []DriverReceipt, seconds int32) ([]domain.ProductID, error) {
		requireOperationDeadline(t, ctx)
		if seconds != 300 || len(values) != len(receipts) || values[0].JobID != jobs[0].JobID || values[1].JobID != jobs[1].JobID {
			t.Fatalf("visibility input = %#v / %d", values, seconds)
		}
		return []domain.ProductID{jobs[1].JobID, jobs[0].JobID}, nil
	}
	var contract JobQueue = queue
	if err := contract.ExtendVisibility(context.Background(), receipts, 5*time.Minute); err != nil {
		t.Fatalf("ExtendVisibility() error = %v", err)
	}
}

func TestQueueVisibilityRejectsInvalidInputsWithoutDriverIO(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	driver := &visibilityRecordingDriver{recordingDriver: noCallDriver(), extend: func(context.Context, []DriverReceipt, int32) ([]domain.ProductID, error) {
		calls.Add(1)
		return nil, nil
	}}
	queue := mustQueue(t, driver, validConfig())
	otherQueue := mustQueue(t, &visibilityRecordingDriver{recordingDriver: noCallDriver(), extend: driver.extend}, validConfig())
	jobID := fixtureJobs(t)[0].JobID
	valid := fixtureReceipt(queue, jobID, "1")
	for name, test := range map[string]struct {
		receipts []Receipt
		duration time.Duration
	}{
		"empty":            {nil, time.Minute},
		"forged":           {[]Receipt{{}}, time.Minute},
		"foreign queue":    {[]Receipt{fixtureReceipt(otherQueue, jobID, "1")}, time.Minute},
		"duplicate":        {[]Receipt{valid, valid}, time.Minute},
		"zero duration":    {[]Receipt{valid}, 0},
		"fractional":       {[]Receipt{valid}, time.Second + time.Nanosecond},
		"over twelve hour": {[]Receipt{valid}, 12*time.Hour + time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if err := queue.ExtendVisibility(context.Background(), test.receipts, test.duration); !errors.Is(err, ErrVisibility) {
				t.Fatalf("ExtendVisibility() error = %v", err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := queue.ExtendVisibility(cancelled, []Receipt{valid}, time.Minute); !errors.Is(err, ErrVisibility) {
		t.Fatalf("canceled ExtendVisibility() error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("driver calls = %d", calls.Load())
	}
}

func TestQueueVisibilityRequiresExactFullRedactedDriverAcknowledgement(t *testing.T) {
	t.Parallel()
	const secret = "opaque-receipt-secret-must-not-escape"
	jobs := fixtureJobs(t)
	tests := []struct {
		name string
		call func([]DriverReceipt) ([]domain.ProductID, error)
	}{
		{"partial", func(values []DriverReceipt) ([]domain.ProductID, error) {
			return []domain.ProductID{values[0].JobID}, nil
		}},
		{"duplicate", func(values []DriverReceipt) ([]domain.ProductID, error) {
			return []domain.ProductID{values[0].JobID, values[0].JobID}, nil
		}},
		{"foreign", func([]DriverReceipt) ([]domain.ProductID, error) {
			return []domain.ProductID{jobs[0].JobID, mustProductID(t, "pid_90000000-0000-4000-8000-000000000009")}, nil
		}},
		{"error", func([]DriverReceipt) ([]domain.ProductID, error) { return nil, errors.New(secret) }},
		{"panic", func([]DriverReceipt) ([]domain.ProductID, error) { panic(secret) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := &visibilityRecordingDriver{recordingDriver: noCallDriver(), extend: func(_ context.Context, values []DriverReceipt, _ int32) ([]domain.ProductID, error) {
				return test.call(values)
			}}
			queue := mustQueue(t, driver, validConfig())
			receipts := []Receipt{fixtureReceipt(queue, jobs[0].JobID, "1"), fixtureReceipt(queue, jobs[1].JobID, "2")}
			err := queue.ExtendVisibility(context.Background(), receipts, time.Minute)
			if !errors.Is(err, ErrVisibility) || strings.Contains(err.Error(), secret) {
				t.Fatalf("ExtendVisibility() error = %q", err)
			}
		})
	}
}

func TestQueueVisibilityRejectsDriverWithoutRenewalAuthority(t *testing.T) {
	t.Parallel()
	queue := mustQueue(t, noCallDriver(), validConfig())
	receipt := fixtureReceipt(queue, fixtureJobs(t)[0].JobID, "1")
	if err := queue.ExtendVisibility(context.Background(), []Receipt{receipt}, time.Minute); !errors.Is(err, ErrVisibility) {
		t.Fatalf("ExtendVisibility() error = %v", err)
	}
}
