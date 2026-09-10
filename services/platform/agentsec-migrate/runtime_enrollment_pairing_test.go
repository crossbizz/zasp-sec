package main

import (
	"context"
	"errors"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeEnrollmentPairing(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-enrollment-pairing")
	if runner.errAt == "up-production-runtime-enrollment-pairing" {
		return errors.New("detail")
	}
	runner.version = 45
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeEnrollmentPairing(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-enrollment-pairing")
	if runner.errAt == "down-production-runtime-enrollment-pairing" {
		return errors.New("detail")
	}
	runner.version = 44
	return nil
}

func TestAgentsecMigrateRuntimeEnrollmentPairingRelease(t *testing.T) {
	up := &scriptedMigrationRunner{version: 44}
	if err := runReleaseMigration(context.Background(), up, []string{"up"}); err != nil || up.version != 45 || !equalMigrationEvents(up.events, []string{"version", "up-production-runtime-enrollment-pairing", "version"}) {
		t.Fatalf("up=%v version=%d err=%v", up.events, up.version, err)
	}
	down := &scriptedMigrationRunner{version: 45, errAt: "down-production-runtime-session-evidence"}
	if err := runReleaseMigration(context.Background(), down, []string{"down"}); err == nil || down.version != 44 || !equalMigrationEvents(down.events, []string{"version", "down-production-runtime-enrollment-pairing", "down-production-runtime-session-evidence"}) {
		t.Fatalf("down=%v version=%d err=%v", down.events, down.version, err)
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(44)
		if direction == "down" {
			version = 45
		}
		failed := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-enrollment-pairing"}
		if err := runReleaseMigration(context.Background(), failed, []string{direction}); err == nil || failed.version != version || len(failed.events) != 2 {
			t.Fatalf("%s failed migration admitted version=%d events=%v err=%v", direction, failed.version, failed.events, err)
		}
	}
}
