package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeSessionReads(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-session-reads")
	if runner.errAt == "up-production-runtime-session-reads" {
		return errors.New("detail")
	}
	runner.version = 41
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeSessionReads(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-session-reads")
	if runner.errAt == "down-production-runtime-session-reads" {
		return errors.New("detail")
	}
	runner.version = 40
	return nil
}

func TestAgentsecMigrateRuntimeSessionReadsRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 40}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 42 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-session-reads", "up-production-runtime-session-search", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 41, errAt: "down-production-runtime-sessions"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-session-reads", "down-production-runtime-sessions"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(40)
		if direction == "down" {
			version = 41
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-session-reads"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
