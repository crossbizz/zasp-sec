package main

import (
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestWorkerMetricsExposeOnlyFixedCardinalityOperationalSeries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	metrics := newWorkerMetrics()
	metrics.observeProjectionClaim([]apiserver.ProjectionWorkLease{
		{AvailableAt: now.Add(-90 * time.Second)},
		{AvailableAt: now.Add(-30 * time.Second)},
	}, now)
	metrics.addInflight(2)
	metrics.observeLeaseLoss()
	metrics.observeRetry()
	metrics.observeExhaustion()
	metrics.observeFailure()
	metrics.observeDriverReadiness(true)

	payload := metrics.render()
	for _, want := range []string{
		"zasp_worker_claimed_total 2\n",
		"zasp_worker_active 1\n",
		"zasp_worker_inflight 2\n",
		"zasp_worker_lease_loss_total 1\n",
		"zasp_worker_retry_total 1\n",
		"zasp_worker_exhaustion_total 1\n",
		"zasp_worker_failure_total 1\n",
		"zasp_worker_driver_ready 1\n",
		"zasp_worker_projection_backlog_age_seconds 90\n",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("metrics missing %q:\n%s", want, payload)
		}
	}
	if strings.Contains(payload, "scope=") || strings.Contains(payload, "provider=") || strings.Contains(payload, "organization=") {
		t.Fatalf("metrics contain unbounded labels:\n%s", payload)
	}

	metrics.observeProjectionClaim(nil, now.Add(time.Minute))
	metrics.addInflight(-2)
	metrics.observeDriverReadiness(false)
	payload = metrics.render()
	for _, want := range []string{
		"zasp_worker_active 0\n",
		"zasp_worker_inflight 0\n",
		"zasp_worker_driver_ready 0\n",
		"zasp_worker_projection_backlog_age_seconds 0\n",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("reset metrics missing %q:\n%s", want, payload)
		}
	}
}

func TestWorkerMetricsIgnoreInvalidProjectionAvailability(t *testing.T) {
	t.Parallel()
	metrics := newWorkerMetrics()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	metrics.observeProjectionClaim([]apiserver.ProjectionWorkLease{{AvailableAt: now.Add(time.Second)}}, now)
	if !strings.Contains(metrics.render(), "zasp_worker_projection_backlog_age_seconds 0\n") {
		t.Fatalf("future availability produced backlog age:\n%s", metrics.render())
	}
}
