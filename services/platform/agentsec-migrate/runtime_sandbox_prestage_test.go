package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSandboxPrestageStopsAt49AndRegistersPrincipals(t *testing.T) {
	for _, scenario := range []struct {
		start  int64
		want   int64
		events []string
		err    error
	}{
		{48, 49, []string{"version", "up-production-runtime-correlation-routing", "version"}, nil},
		{49, 49, []string{"version", "version"}, nil},
		{50, 50, []string{"version"}, migrations.ErrInvalidState},
	} {
		runner := &scriptedMigrationRunner{version: scenario.start}
		err := runReleaseMigration(context.Background(), runner, []string{"up-to-49"})
		if !errors.Is(err, scenario.err) || runner.version != scenario.want || !equalMigrationEvents(runner.events, scenario.events) {
			t.Fatal("sandbox prestage changed target or failed", runner.version, runner.events, err)
		}
	}
	if !isForwardMigration([]string{"up-to-49"}) {
		t.Fatal("prestage skipped principal configuration and registration")
	}
	for _, args := range [][]string{{"up-to-49", "extra"}, {"up-to-52"}, {"down"}} {
		if isForwardMigration(args) {
			t.Fatal("unsupported command gained registration side effects", args)
		}
	}
}
