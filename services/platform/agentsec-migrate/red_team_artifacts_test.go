package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRedTeamArtifacts(context.Context) error {
	runner.events = append(runner.events, "up-production-red-team-artifacts")
	if runner.errAt == "up-production-red-team-artifacts" {
		return errors.New("detail")
	}
	runner.version = 39
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRedTeamArtifacts(context.Context) error {
	runner.events = append(runner.events, "down-production-red-team-artifacts")
	if runner.errAt == "down-production-red-team-artifacts" {
		return errors.New("detail")
	}
	runner.version = 38
	return nil
}

func TestAgentsecMigrateRedTeamArtifactsRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 38}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 42 || !equalMigrationEvents(up.events, []string{"version", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 39, errAt: "down-production-red-team-invocation"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-red-team-artifacts", "down-production-red-team-invocation"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
	failed := &scriptedMigrationRunner{version: 38, errAt: "up-production-red-team-artifacts"}
	if err := runReleaseMigration(context.Background(), failed, []string{"up"}); err == nil || failed.version != 38 {
		t.Fatalf("failed migration admitted version=%d err=%v", failed.version, err)
	}
}
