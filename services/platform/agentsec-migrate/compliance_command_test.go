package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionCompliance(context.Context) error {
	runner.events = append(runner.events, "up-compliance")
	if runner.errAt == "up-compliance" {
		return migrations.ErrInvalidState
	}
	runner.version = 56
	return nil
}
func (runner *scriptedMigrationRunner) DownProductionCompliance(context.Context) error {
	runner.events = append(runner.events, "down-compliance")
	if runner.errAt == "down-compliance" {
		return migrations.ErrInvalidState
	}
	runner.version = 55
	return nil
}
func TestComplianceExplicitReleaseCommands(t *testing.T) {
	for _, start := range []int64{48, 49, 50, 51, 52, 53, 54, 55, 56} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"up-to-56"}); err != nil || runner.version != 56 {
			t.Errorf("upgrade from%d version%d: %v", start, runner.version, err)
		}
	}
	if !isForwardMigration([]string{"up-to-56"}) {
		t.Error("compliance upgrade skips registration")
	}
	for _, start := range []int64{55, 56} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-55"}); err != nil || runner.version != 55 {
			t.Errorf("rollback from%d: %v", start, err)
		}
	}
	for _, command := range []string{"up-to-55", "down-to-54", "up", "down"} {
		runner := &scriptedMigrationRunner{version: 56}
		if err := runReleaseMigration(context.Background(), runner, []string{command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != 56 {
			t.Errorf("historical%s crossed56: %v", command, err)
		}
	}
}
