package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeCandidateAuthority(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-candidate-authority")
	if runner.errAt == "up-production-runtime-candidate-authority" {
		return errors.New("detail")
	}
	runner.version = 47
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeCandidateAuthority(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-candidate-authority")
	if runner.errAt == "down-production-runtime-candidate-authority" {
		return errors.New("detail")
	}
	runner.version = 46
	return nil
}

func TestAgentsecMigrateRuntimeCandidateAuthorityRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 46}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 48 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-candidate-authority", "up-production-runtime-acceptance", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 47, errAt: "down-production-reconciliation-lane-plan"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || down.version != 46 || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-candidate-authority", "down-production-reconciliation-lane-plan"}) {
		t.Fatalf("down=%v version=%d err=%v", down.events, down.version, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(46)
		if direction == "down" {
			version = 47
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-candidate-authority"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
