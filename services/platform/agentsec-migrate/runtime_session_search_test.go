package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeSessionSearch(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-session-search")
	if runner.errAt == "up-production-runtime-session-search" {
		return errors.New("detail")
	}
	runner.version = 42
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeSessionSearch(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-session-search")
	if runner.errAt == "down-production-runtime-session-search" {
		return errors.New("detail")
	}
	runner.version = 41
	return nil
}

func TestAgentsecMigrateRuntimeSessionSearchRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 41}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 46 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 42, errAt: "down-production-runtime-session-reads"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-session-search", "down-production-runtime-session-reads"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(41)
		if direction == "down" {
			version = 42
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-session-search"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
