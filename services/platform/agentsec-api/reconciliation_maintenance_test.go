package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestReconciliationMaintenanceStartsUnavailable(t *testing.T) {
	output := newOperationalMetrics().Prometheus()
	if !strings.Contains(output, "zasp_reconciliation_maintenance_sample_valid 0\n") {
		t.Fatalf("unsampled database maintenance must be explicitly unavailable: %s", output)
	}
	if strings.Contains(output, "zasp_reconciliation_maintenance_dead_tuples{") {
		t.Fatal("unknown maintenance state fabricated zero dead tuples")
	}
}

func TestReconciliationMaintenancePrometheusExposition(t *testing.T) {
	tool := os.Getenv("ZASP_PROMTOOL_BIN")
	if tool == "" {
		t.Skip("enable actual Prometheus exposition validation with ZASP_PROMTOOL_BIN")
	}
	metrics := newOperationalMetrics()
	metrics.observeReconciliationMaintenance(maintenanceFixture(), true, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, tool, "check", "metrics")
	command.Stdin = strings.NewReader(metrics.Prometheus())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual metrics rejected by Prometheus: %s error=%v", output, err)
	}
}

func maintenanceFixture() apiserver.ReconciliationMaintenanceSnapshot {
	return apiserver.ReconciliationMaintenanceSnapshot{ObservedAt: time.Now(), Tables: [2]apiserver.ReconciliationMaintenanceTable{
		{Table: "zasp_connector_effect_lane_scopes", DeadTuples: 10001, AutovacuumEnabled: true},
		{Table: "zasp_connector_effects", LiveTuples: 1, AutovacuumEnabled: true},
	}}
}

func TestReconciliationMaintenanceRejectsStaleFailedAndForeignSamples(t *testing.T) {
	metrics := newOperationalMetrics()
	now := time.Now()
	metrics.observeReconciliationMaintenance(maintenanceFixture(), true, now)
	var output strings.Builder
	metrics.writeReconciliationMaintenance(&output, now)
	if !strings.Contains(output.String(), `zasp_reconciliation_maintenance_dead_tuples{table="zasp_connector_effect_lane_scopes"} 10001`) {
		t.Fatal(output.String())
	}
	for _, elapsed := range []time.Duration{46 * time.Second, -time.Second} {
		output.Reset()
		metrics.writeReconciliationMaintenance(&output, now.Add(elapsed))
		if !strings.Contains(output.String(), "sample_valid 0\n") || strings.Contains(output.String(), "dead_tuples{") {
			t.Fatal("stale sample published", output.String())
		}
	}
	// An old completion cannot replace a newer sample.
	metrics.observeReconciliationMaintenance(apiserver.ReconciliationMaintenanceSnapshot{}, false, now.Add(-time.Second))
	if !strings.Contains(metrics.Prometheus(), "sample_valid 1\n") {
		t.Fatal("old completion replaced fresh sample")
	}
	metrics.observeReconciliationMaintenance(maintenanceFixture(), false, now.Add(time.Millisecond))
	if strings.Contains(metrics.Prometheus(), "dead_tuples{") {
		t.Fatal("failed probe retained healthy-looking statistics")
	}
	foreign := maintenanceFixture()
	foreign.Tables[0].Table = "tenant-secret-label"
	metrics.observeReconciliationMaintenance(foreign, true, time.Now().Add(time.Second))
	if strings.Contains(metrics.Prometheus(), "tenant-secret-label") {
		t.Fatal("unbounded private label published")
	}
}

type maintenanceSourceFunc func(context.Context) (apiserver.ReconciliationMaintenanceSnapshot, error)

func (f maintenanceSourceFunc) ReconciliationMaintenance(ctx context.Context) (apiserver.ReconciliationMaintenanceSnapshot, error) {
	return f(ctx)
}

func TestReconciliationMaintenanceStopsAndInvalidatesBeforeShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := newOperationalMetrics()
	called := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runReconciliationMaintenance(ctx, maintenanceSourceFunc(func(ctx context.Context) (apiserver.ReconciliationMaintenanceSnapshot, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 2*time.Second {
				return apiserver.ReconciliationMaintenanceSnapshot{}, errors.New("unbounded probe")
			}
			close(called)
			return maintenanceFixture(), nil
		}), metrics)
	}()
	<-called
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(metrics.Prometheus(), "sample_valid 1\n") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(metrics.Prometheus(), "sample_valid 1\n") {
		t.Fatal("sampler did not publish actual source sample")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for sampling interval")
	}
	if !strings.Contains(metrics.Prometheus(), "sample_valid 0\n") {
		t.Fatal("shutdown left sample marked valid")
	}
}

func TestReconciliationMaintenanceDiscardsLateSuccessAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := newOperationalMetrics()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runReconciliationMaintenance(ctx, maintenanceSourceFunc(func(probe context.Context) (apiserver.ReconciliationMaintenanceSnapshot, error) {
			close(entered)
			<-probe.Done()
			<-release
			return maintenanceFixture(), nil
		}), metrics)
	}()
	<-entered
	cancel()
	select {
	case <-done:
		close(release)
		t.Fatal("sampler returned before its active query ended")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sampler did not stop after the query returned")
	}
	if !strings.Contains(metrics.Prometheus(), "sample_valid 0\n") || strings.Contains(metrics.Prometheus(), "dead_tuples{") {
		t.Fatal("late source success after cancellation became healthy statistics")
	}
}
