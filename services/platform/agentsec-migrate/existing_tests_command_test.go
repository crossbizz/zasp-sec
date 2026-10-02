package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentExistingTests(context.Context) error {
	runner.events = append(runner.events, "up-existing-tests")
	if runner.errAt == "up-existing-tests" {
		return migrations.ErrInvalidState
	}
	runner.version = 55
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentExistingTests(context.Context) error {
	runner.events = append(runner.events, "down-existing-tests")
	if runner.errAt == "down-existing-tests" {
		return migrations.ErrInvalidState
	}
	runner.version = 54
	return nil
}

func TestExistingTestsExplicitReleaseCommands(t *testing.T) {
	for _, start := range []int64{48, 49, 50, 51, 52, 53, 54, 55} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"up-to-55"}); err != nil || runner.version != 55 {
			t.Errorf("upgrade from %d: version=%d events=%v error=%v", start, runner.version, runner.events, err)
		}
	}
	if !isForwardMigration([]string{"up-to-55"}) {
		t.Error("explicit upgrade skips principal registration")
	}
	for _, start := range []int64{54, 55} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-54"}); err != nil || runner.version != 54 {
			t.Errorf("rollback from %d: version=%d error=%v", start, runner.version, err)
		}
	}
}

func TestExistingTestsReleaseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		start   int64
		command string
		want    []string
	}{
		{53, "up-to-55", []string{"version", "up-security-agent-run-context", "up-existing-tests", "version"}},
		{55, "up-to-55", []string{"version", "version"}},
		{55, "down-to-54", []string{"version", "down-existing-tests", "version"}},
		{54, "down-to-54", []string{"version", "version"}},
	} {
		runner := &scriptedMigrationRunner{version: tc.start}
		if err := runReleaseMigration(context.Background(), runner, []string{tc.command}); err != nil || !equalMigrationEvents(runner.events, tc.want) {
			t.Errorf("release order from %d via %s: error=%v events=%v", tc.start, tc.command, err, runner.events)
		}
	}
	for _, command := range []string{"up", "up-to-48", "up-to-49", "up-to-50", "up-to-51", "up-to-52", "up-to-53", "up-to-54", "down", "down-to-49", "down-to-51", "down-to-52", "down-to-53"} {
		runner := &scriptedMigrationRunner{version: 55}
		if err := runReleaseMigration(context.Background(), runner, []string{command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != 55 || !equalMigrationEvents(runner.events, []string{"version"}) {
			t.Errorf("historical command %s crossed schema55: error=%v events=%v", command, err, runner.events)
		}
	}
	for _, tc := range []struct {
		start            int64
		command, failure string
	}{
		{53, "up-to-55", "up-security-agent-run-context"},
		{54, "up-to-55", "up-existing-tests"},
		{55, "down-to-54", "down-existing-tests"},
	} {
		runner := &scriptedMigrationRunner{version: tc.start, errAt: tc.failure}
		if err := runReleaseMigration(context.Background(), runner, []string{tc.command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != tc.start || !equalMigrationEvents(runner.events, []string{"version", tc.failure}) {
			t.Errorf("failure boundary %+v: version=%d error=%v events=%v", tc, runner.version, err, runner.events)
		}
	}
	for _, start := range []int64{53, 56} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-54"}); !errors.Is(err, migrations.ErrInvalidState) || !equalMigrationEvents(runner.events, []string{"version"}) {
			t.Errorf("rollback admitted wrong source %d: error=%v events=%v", start, err, runner.events)
		}
	}
	for _, args := range [][]string{{"up-to-55", "extra"}, {"up-to-61"}, {"down-to-54"}} {
		if isForwardMigration(args) {
			t.Errorf("unexpected forward command %v", args)
		}
	}
}
