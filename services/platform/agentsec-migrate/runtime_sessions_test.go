package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeSessions(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-sessions")
	if runner.errAt == "up-production-runtime-sessions" {
		return errors.New("detail")
	}
	runner.version = 40
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeSessions(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-sessions")
	if runner.errAt == "down-production-runtime-sessions" {
		return errors.New("detail")
	}
	runner.version = 39
	return nil
}

func TestAgentsecMigrateRuntimeSessionsRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 39}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 49 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "up-production-runtime-correlation-routing", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 40, errAt: "down-production-red-team-artifacts"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-sessions", "down-production-red-team-artifacts"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(39)
		if direction == "down" {
			version = 40
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-sessions"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
