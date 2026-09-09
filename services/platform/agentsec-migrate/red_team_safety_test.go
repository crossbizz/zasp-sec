package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRedTeamSafety(context.Context) error {
	runner.events = append(runner.events, "up-production-red-team-safety")
	if runner.errAt == "up-production-red-team-safety" {
		return errors.New("detail")
	}
	runner.version = 37
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRedTeamSafety(context.Context) error {
	runner.events = append(runner.events, "down-production-red-team-safety")
	if runner.errAt == "down-production-red-team-safety" {
		return errors.New("detail")
	}
	runner.version = 36
	return nil
}

func TestAgentsecMigrateRedTeamSafetyRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 36}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 40 || !equalMigrationEvents(up.events, []string{"version", "up-production-red-team-safety", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 37, errAt: "down-production-runtime-queue-replay"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-red-team-safety", "down-production-runtime-queue-replay"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
}
