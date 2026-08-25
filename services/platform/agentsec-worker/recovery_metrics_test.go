package main

import (
	"strings"
	"testing"
	"time"
)

func TestRecoveryMetricsExposeFixedCardinalityQueueHoldLeaseExhaustionAndCleanup(t *testing.T) {
	metrics := newRecoveryMetrics()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	metrics.now = func() time.Time { return now }
	metrics.observeDriverReadiness(true)
	metrics.observeClaim(recoveryOperationClaim{CreatedAt: now.Add(-2 * time.Minute)}, now)
	metrics.beginHold(now.Add(-90 * time.Second))
	metrics.observeLeaseLoss()
	metrics.observeExhaustion()
	metrics.observeCleanupFailure()
	payload := metrics.render()
	for _, want := range []string{
		"zasp_recovery_driver_ready 1\n",
		"zasp_recovery_queue_age_seconds 120\n",
		"zasp_recovery_hold_age_seconds 90\n",
		"zasp_recovery_exhaustion_total 1\n",
		"zasp_recovery_lease_loss_total 1\n",
		"zasp_recovery_cleanup_failure_total 1\n",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("metrics missing %q:\n%s", want, payload)
		}
	}
	metrics.endHold()
	if !strings.Contains(metrics.render(), "zasp_recovery_hold_age_seconds 0\n") {
		t.Fatal("released recovery hold remained active")
	}
}
