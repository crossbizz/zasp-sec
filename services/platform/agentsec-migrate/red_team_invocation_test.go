package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRedTeamInvocation(context.Context) error {
	runner.events = append(runner.events, "up-production-red-team-invocation")
	if runner.errAt == "up-production-red-team-invocation" {
		return errors.New("detail")
	}
	runner.version = 38
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRedTeamInvocation(context.Context) error {
	runner.events = append(runner.events, "down-production-red-team-invocation")
	if runner.errAt == "down-production-red-team-invocation" {
		return errors.New("detail")
	}
	runner.version = 37
	return nil
}

func TestAgentsecMigrateRedTeamInvocationRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 37}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 43 || !equalMigrationEvents(up.events, []string{"version", "up-production-red-team-invocation", "up-production-red-team-artifacts", "up-production-runtime-sessions", "up-production-runtime-session-reads", "up-production-runtime-session-search", "up-production-runtime-session-query", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 38, errAt: "down-production-red-team-safety"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-red-team-invocation", "down-production-red-team-safety"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
}
