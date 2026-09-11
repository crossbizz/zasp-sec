package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeAcceptance(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-acceptance")
	if runner.errAt == "up-production-runtime-acceptance" {
		return errors.New("detail")
	}
	runner.version = 48
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeAcceptance(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-acceptance")
	if runner.errAt == "down-production-runtime-acceptance" {
		return errors.New("detail")
	}
	runner.version = 47
	return nil
}

func TestAgentsecMigrateRuntimeAcceptanceRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 47}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 49 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("up events=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 48, errAt: "down-production-runtime-candidate-authority"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || down.version != 47 || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-acceptance", "down-production-runtime-candidate-authority"}) {
		t.Fatalf("down events=%v version=%d err=%v", down.events, down.version, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(47)
		if direction == "down" {
			version = 48
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-acceptance"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
