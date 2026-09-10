package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

const reconciliationMaintenanceInterval = 15 * time.Second
const reconciliationMaintenanceTimeout = 2 * time.Second
const reconciliationMaintenanceMaxAge = 45 * time.Second

type reconciliationMaintenanceSource interface {
	ReconciliationMaintenance(context.Context) (apiserver.ReconciliationMaintenanceSnapshot, error)
}

type reconciliationMaintenanceSample struct {
	value    apiserver.ReconciliationMaintenanceSnapshot
	received time.Time // Local clock retains its monotonic component for freshness.
	valid    bool
}

// Sampling is serial and belongs to the API lifecycle. Shutdown waits for this
// worker before closing the pool. Sampling errors do not change API readiness.
func runReconciliationMaintenance(ctx context.Context, source reconciliationMaintenanceSource, metrics *operationalMetrics) error {
	if ctx == nil || invalidRuntimeValue(source) || metrics == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		metrics.observeReconciliationMaintenance(apiserver.ReconciliationMaintenanceSnapshot{}, false, time.Now())
	}()
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, reconciliationMaintenanceTimeout)
		snapshot, err := source.ReconciliationMaintenance(probe)
		valid := err == nil && probe.Err() == nil && ctx.Err() == nil && snapshot.Valid()
		cancel()
		metrics.observeReconciliationMaintenance(snapshot, valid, time.Now())
		timer := time.NewTimer(reconciliationMaintenanceInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func (metrics *operationalMetrics) observeReconciliationMaintenance(snapshot apiserver.ReconciliationMaintenanceSnapshot, valid bool, received time.Time) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if received.Before(metrics.maintenance.received) {
		return
	}
	// Copy optional timestamps so the cached sample cannot be changed by a source.
	for i := range snapshot.Tables {
		if timestamp := snapshot.Tables[i].LastAutovacuum; timestamp != nil {
			copy := *timestamp
			snapshot.Tables[i].LastAutovacuum = &copy
		}
	}
	metrics.maintenance = reconciliationMaintenanceSample{value: snapshot, received: received, valid: valid && snapshot.Valid()}
}

// Caller holds metrics.mu. No SQL is performed on the scrape path.
func (metrics *operationalMetrics) writeReconciliationMaintenance(output *strings.Builder, now time.Time) {
	sample := metrics.maintenance
	valid := sample.valid && !sample.received.IsZero() && !now.Before(sample.received) && now.Sub(sample.received) <= reconciliationMaintenanceMaxAge
	flag := 0
	if valid {
		flag = 1
	}
	fmt.Fprintf(output, "# HELP zasp_reconciliation_maintenance_sample_valid Fresh valid maintenance statistics; zero means unavailable, not healthy.\n# TYPE zasp_reconciliation_maintenance_sample_valid gauge\nzasp_reconciliation_maintenance_sample_valid %d\n", flag)
	if !valid {
		return
	}
	output.WriteString("# HELP zasp_reconciliation_maintenance_dead_tuples Estimated dead tuples; zero is not proof of completed cleanup.\n# TYPE zasp_reconciliation_maintenance_dead_tuples gauge\n")
	output.WriteString("# HELP zasp_reconciliation_maintenance_live_tuples Estimated live tuples.\n# TYPE zasp_reconciliation_maintenance_live_tuples gauge\n")
	output.WriteString("# HELP zasp_reconciliation_maintenance_autovacuum_enabled Ordinary autovacuum enabled globally and per table; not a scheduling guarantee.\n# TYPE zasp_reconciliation_maintenance_autovacuum_enabled gauge\n")
	output.WriteString("# HELP zasp_reconciliation_maintenance_last_autovacuum_seconds Recorded autovacuum timestamp, or zero if never recorded; not cleanup proof.\n# TYPE zasp_reconciliation_maintenance_last_autovacuum_seconds gauge\n")
	for _, row := range sample.value.Tables {
		enabled := 0
		if row.AutovacuumEnabled {
			enabled = 1
		}
		last := int64(0)
		if row.LastAutovacuum != nil {
			last = row.LastAutovacuum.Unix()
		}
		fmt.Fprintf(output, "zasp_reconciliation_maintenance_dead_tuples{table=%q} %d\nzasp_reconciliation_maintenance_live_tuples{table=%q} %d\nzasp_reconciliation_maintenance_autovacuum_enabled{table=%q} %d\nzasp_reconciliation_maintenance_last_autovacuum_seconds{table=%q} %d\n", row.Table, row.DeadTuples, row.Table, row.LiveTuples, row.Table, enabled, row.Table, last)
	}
}
