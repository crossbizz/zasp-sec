package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// recoveryMetrics is label-free because each deployment owns one recovery lane.
type recoveryMetrics struct {
	driverReady      atomic.Int64
	queueAgeMillis   atomic.Int64
	holdStartedNanos atomic.Int64
	exhaustions      atomic.Uint64
	leaseLoss        atomic.Uint64
	cleanupFailures  atomic.Uint64
	now              func() time.Time
}

func newRecoveryMetrics() *recoveryMetrics { return &recoveryMetrics{now: time.Now} }

func (metrics *recoveryMetrics) observeDriverReadiness(ready bool) {
	if metrics == nil {
		return
	}
	if ready {
		metrics.driverReady.Store(1)
	} else {
		metrics.driverReady.Store(0)
	}
}

func (metrics *recoveryMetrics) observeClaim(claim recoveryOperationClaim, now time.Time) {
	if metrics == nil {
		return
	}
	age := int64(0)
	if !claim.CreatedAt.IsZero() && !claim.CreatedAt.After(now) {
		age = now.Sub(claim.CreatedAt).Milliseconds()
	}
	metrics.queueAgeMillis.Store(max(age, 0))
}

func (metrics *recoveryMetrics) observeEmptyClaim() {
	if metrics != nil {
		metrics.queueAgeMillis.Store(0)
	}
}

func (metrics *recoveryMetrics) beginHold(started time.Time) {
	if metrics != nil && !started.IsZero() {
		metrics.holdStartedNanos.Store(started.UTC().UnixNano())
	}
}

func (metrics *recoveryMetrics) endHold() {
	if metrics != nil {
		metrics.holdStartedNanos.Store(0)
	}
}

func (metrics *recoveryMetrics) observeExhaustion() {
	if metrics != nil {
		metrics.exhaustions.Add(1)
	}
}

func (metrics *recoveryMetrics) observeLeaseLoss() {
	if metrics != nil {
		metrics.leaseLoss.Add(1)
	}
}

func (metrics *recoveryMetrics) observeCleanupFailure() {
	if metrics != nil {
		metrics.cleanupFailures.Add(1)
	}
}

func (metrics *recoveryMetrics) render() string {
	if metrics == nil {
		return ""
	}
	now := time.Now().UTC()
	if metrics.now != nil {
		now = metrics.now().UTC()
	}
	holdAgeMillis := int64(0)
	if started := metrics.holdStartedNanos.Load(); started > 0 {
		holdAgeMillis = max(now.Sub(time.Unix(0, started).UTC()).Milliseconds(), 0)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# HELP zasp_recovery_driver_ready Exact recovery repository, queue, and provider readiness.\n# TYPE zasp_recovery_driver_ready gauge\nzasp_recovery_driver_ready %d\n", metrics.driverReady.Load())
	fmt.Fprintf(&output, "# HELP zasp_recovery_queue_age_seconds Age of the latest claimed recovery operation.\n# TYPE zasp_recovery_queue_age_seconds gauge\nzasp_recovery_queue_age_seconds %g\n", float64(max(metrics.queueAgeMillis.Load(), 0))/1000)
	fmt.Fprintf(&output, "# HELP zasp_recovery_hold_age_seconds Age of the active local recovery hold.\n# TYPE zasp_recovery_hold_age_seconds gauge\nzasp_recovery_hold_age_seconds %g\n", float64(holdAgeMillis)/1000)
	fmt.Fprintf(&output, "# HELP zasp_recovery_exhaustion_total Recovery operations terminalized after bounded attempts.\n# TYPE zasp_recovery_exhaustion_total counter\nzasp_recovery_exhaustion_total %d\n", metrics.exhaustions.Load())
	fmt.Fprintf(&output, "# HELP zasp_recovery_lease_loss_total Recovery database or queue lease losses.\n# TYPE zasp_recovery_lease_loss_total counter\nzasp_recovery_lease_loss_total %d\n", metrics.leaseLoss.Load())
	fmt.Fprintf(&output, "# HELP zasp_recovery_cleanup_failure_total Restore cleanup failures.\n# TYPE zasp_recovery_cleanup_failure_total counter\nzasp_recovery_cleanup_failure_total %d\n", metrics.cleanupFailures.Load())
	return output.String()
}
