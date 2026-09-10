package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeSessionEvidence(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-session-evidence")
	if runner.errAt == "up-production-runtime-session-evidence" {
		return errors.New("detail")
	}
	runner.version = 44
	return nil
}
func (runner *scriptedMigrationRunner) DownProductionRuntimeSessionEvidence(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-session-evidence")
	if runner.errAt == "down-production-runtime-session-evidence" {
		return errors.New("detail")
	}
	runner.version = 43
	return nil
}
func TestAgentsecMigrateRuntimeSessionEvidenceRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 43}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 47 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-session-evidence", "up-production-runtime-enrollment-pairing", "up-production-reconciliation-lane-plan", "up-production-runtime-candidate-authority", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 44, errAt: "down-production-runtime-session-query"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-session-evidence", "down-production-runtime-session-query"}) {
		t.Fatalf("down=%v err=%v", down.events, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(43)
		if direction == "down" {
			version = 44
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-session-evidence"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
