package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionReconciliationLanePlan(context.Context) error {
	runner.events = append(runner.events, "up-production-reconciliation-lane-plan")
	if runner.errAt == "up-production-reconciliation-lane-plan" {
		return errors.New("detail")
	}
	runner.version = 46
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionReconciliationLanePlan(context.Context) error {
	runner.events = append(runner.events, "down-production-reconciliation-lane-plan")
	if runner.errAt == "down-production-reconciliation-lane-plan" {
		return errors.New("detail")
	}
	runner.version = 45
	return nil
}

func TestAgentsecMigrateReconciliationLanePlanRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 45}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 47 || !equalMigrationEvents(up.events, []string{"version", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 46, errAt: "down-production-runtime-enrollment-pairing"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || down.version != 45 || !equalMigrationEvents(down.events, []string{"version", "down-production-reconciliation-lane-plan", "down-production-runtime-enrollment-pairing"}) {
		t.Fatalf("down=%v version=%d err=%v", down.events, down.version, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(45)
		if direction == "down" {
			version = 46
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-reconciliation-lane-plan"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
