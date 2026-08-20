package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// workerMetrics deliberately has no labels. Each worker process is already
// deployed for one bounded mode/kind, so labels would only add cardinality and
// make accidental scope or provider disclosure possible.
type workerMetrics struct {
	claimed          atomic.Uint64
	inflight         atomic.Int64
	leaseLoss        atomic.Uint64
	retries          atomic.Uint64
	exhaustions      atomic.Uint64
	failures         atomic.Uint64
	driverReady      atomic.Int64
	backlogAgeMillis atomic.Int64
}

func newWorkerMetrics() *workerMetrics { return &workerMetrics{} }

func (metrics *workerMetrics) observeProjectionClaim(leases []apiserver.ProjectionWorkLease, now time.Time) {
	if metrics == nil {
		return
	}
	metrics.claimed.Add(uint64(len(leases)))
	oldest := now
	found := false
	for _, lease := range leases {
		if lease.AvailableAt.IsZero() || lease.AvailableAt.After(now) {
			continue
		}
		if !found || lease.AvailableAt.Before(oldest) {
			oldest, found = lease.AvailableAt, true
		}
	}
	age := int64(0)
	if found {
		age = now.Sub(oldest).Milliseconds()
		if age < 0 {
			age = 0
		}
	}
	metrics.backlogAgeMillis.Store(age)
}

func (metrics *workerMetrics) addInflight(delta int64) {
	if metrics == nil {
		return
	}
	value := metrics.inflight.Add(delta)
	if value < 0 {
		metrics.inflight.Store(0)
	}
}

func (metrics *workerMetrics) observeLeaseLoss() {
	if metrics != nil {
		metrics.leaseLoss.Add(1)
	}
}
func (metrics *workerMetrics) observeRetry() {
	if metrics != nil {
		metrics.retries.Add(1)
	}
}
func (metrics *workerMetrics) observeExhaustion() {
	if metrics != nil {
		metrics.exhaustions.Add(1)
	}
}
func (metrics *workerMetrics) observeFailure() {
	if metrics != nil {
		metrics.failures.Add(1)
	}
}
func (metrics *workerMetrics) observeDriverReadiness(ready bool) {
	if metrics == nil {
		return
	}
	if ready {
		metrics.driverReady.Store(1)
	} else {
		metrics.driverReady.Store(0)
	}
}

func (metrics *workerMetrics) render() string {
	if metrics == nil {
		return ""
	}
	inflight := metrics.inflight.Load()
	if inflight < 0 {
		inflight = 0
	}
	active := int64(0)
	if inflight > 0 {
		active = 1
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# HELP zasp_worker_claimed_total Durable work items claimed.\n# TYPE zasp_worker_claimed_total counter\nzasp_worker_claimed_total %d\n", metrics.claimed.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_active Worker has active in-flight work.\n# TYPE zasp_worker_active gauge\nzasp_worker_active %d\n", active)
	fmt.Fprintf(&output, "# HELP zasp_worker_inflight Current in-flight work items.\n# TYPE zasp_worker_inflight gauge\nzasp_worker_inflight %d\n", inflight)
	fmt.Fprintf(&output, "# HELP zasp_worker_lease_loss_total Lease ownership losses.\n# TYPE zasp_worker_lease_loss_total counter\nzasp_worker_lease_loss_total %d\n", metrics.leaseLoss.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_retry_total Retryable work outcomes.\n# TYPE zasp_worker_retry_total counter\nzasp_worker_retry_total %d\n", metrics.retries.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_exhaustion_total Work items that exhausted their bounded attempts.\n# TYPE zasp_worker_exhaustion_total counter\nzasp_worker_exhaustion_total %d\n", metrics.exhaustions.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_failure_total Non-retryable or worker-boundary failures.\n# TYPE zasp_worker_failure_total counter\nzasp_worker_failure_total %d\n", metrics.failures.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_driver_ready Exact worker repository and driver authority readiness.\n# TYPE zasp_worker_driver_ready gauge\nzasp_worker_driver_ready %d\n", metrics.driverReady.Load())
	fmt.Fprintf(&output, "# HELP zasp_worker_projection_backlog_age_seconds Age of the oldest projection item in the latest claim; zero after an empty claim.\n# TYPE zasp_worker_projection_backlog_age_seconds gauge\nzasp_worker_projection_backlog_age_seconds %g\n", float64(metrics.backlogAgeMillis.Load())/1000)
	return output.String()
}
