package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeCorrelationRouting(context.Context) error {
	runner.events = append(runner.events, "up-production-runtime-correlation-routing")
	if runner.errAt == "up-production-runtime-correlation-routing" {
		return errors.New("detail")
	}
	runner.version = 49
	return nil
}
func (runner *scriptedMigrationRunner) DownProductionRuntimeCorrelationRouting(context.Context) error {
	runner.events = append(runner.events, "down-production-runtime-correlation-routing")
	if runner.errAt == "down-production-runtime-correlation-routing" {
		return errors.New("detail")
	}
	runner.version = 48
	return nil
}

func TestAgentsecMigrateRoutingReleaseAndCompatibilityStage(t *testing.T) {
	for _, scenario := range []struct {
		name, command string
		start, want   int64
		events        []string
		wantErr       error
	}{
		{"activate", "up", 48, 49, []string{"version", "up-production-runtime-correlation-routing", "version"}, nil},
		{"already-current", "up", 49, 49, []string{"version", "version"}, nil},
		{"prestage", "up-to-48", 47, 48, []string{"version", "up-production-runtime-acceptance", "version"}, nil},
		{"prestage-existing", "up-to-48", 48, 48, []string{"version", "version"}, nil},
		{"prestage-not-downgrade", "up-to-48", 49, 49, []string{"version"}, migrations.ErrInvalidState},
		{"unknown-future", "up", 50, 50, []string{"version"}, migrations.ErrInvalidState},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			runner := &scriptedMigrationRunner{version: scenario.start}
			err := runReleaseMigration(context.Background(), runner, []string{scenario.command})
			if !errors.Is(err, scenario.wantErr) || runner.version != scenario.want || !equalMigrationEvents(runner.events, scenario.events) {
				t.Fatal("release stage mismatch", runner.version, runner.events, err)
			}
		})
	}
	for _, direction := range []string{"up", "down"} {
		version := int64(48)
		if direction == "down" {
			version = 49
		}
		runner := &scriptedMigrationRunner{version: version, errAt: direction + "-production-runtime-correlation-routing"}
		if err := runReleaseMigration(context.Background(), runner, []string{direction}); err == nil || runner.version != version || !equalMigrationEvents(runner.events, []string{"version", direction + "-production-runtime-correlation-routing"}) {
			t.Fatal("failed routing migration didn't stop", runner.events, err)
		}
	}
}
