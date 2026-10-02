package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (runner *scriptedMigrationRunner) UpProductionAuditExports(context.Context) error {
	runner.events = append(runner.events, "up-audit-exports")
	if runner.errAt == "up-audit-exports" {
		return migrations.ErrInvalidState
	}
	runner.version = 52
	return nil
}

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentBudgets(context.Context) error {
	runner.events = append(runner.events, "up-security-agent-budgets")
	if runner.errAt == "up-security-agent-budgets" {
		return migrations.ErrInvalidState
	}
	runner.version = 53
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionSecurityAgentBudgets(context.Context) error {
	runner.events = append(runner.events, "down-security-agent-budgets")
	if runner.errAt == "down-security-agent-budgets" {
		return migrations.ErrInvalidState
	}
	runner.version = 52
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionAuditExports(context.Context) error {
	runner.events = append(runner.events, "down-audit-exports")
	if runner.errAt == "down-audit-exports" {
		return migrations.ErrInvalidState
	}
	runner.version = 51
	return nil
}

func TestAuditExportsExplicitReleaseCommand(t *testing.T) {
	for _, start := range []int64{48, 49, 50, 51, 52} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"up-to-52"}); err != nil || runner.version != 52 {
			t.Errorf("explicit audit schema command from %d: version=%d err=%v", start, runner.version, err)
		}
	}
	if !isForwardMigration([]string{"up-to-52"}) {
		t.Error("explicit audit schema command skips principal registration")
	}
	failed := &scriptedMigrationRunner{version: 50, errAt: "up-audit-exports"}
	if err := runReleaseMigration(context.Background(), failed, []string{"up-to-52"}); !errors.Is(err, migrations.ErrInvalidState) || failed.version != 51 || !equalMigrationEvents(failed.events, []string{"version", "up-precision", "up-audit-exports"}) {
		t.Errorf("failed audit upgrade crossed target: version=%d events=%v err=%v", failed.version, failed.events, err)
	}
	for _, start := range []int64{51, 52} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-51"}); err != nil || runner.version != 51 {
			t.Errorf("explicit audit rollback from %d: version=%d err=%v", start, runner.version, err)
		}
	}
	retained := &scriptedMigrationRunner{version: 52, errAt: "down-audit-exports"}
	if err := runReleaseMigration(context.Background(), retained, []string{"down-to-51"}); !errors.Is(err, migrations.ErrInvalidState) || retained.version != 52 || !equalMigrationEvents(retained.events, []string{"version", "down-audit-exports"}) {
		t.Errorf("refused rollback changed version: version=%d events=%v err=%v", retained.version, retained.events, err)
	}
}

func TestAuditExportsCommandsPreserveHistoricalAndFutureBoundaries(t *testing.T) {
	for _, command := range []string{"up", "up-to-48", "up-to-49", "up-to-50", "up-to-51", "down", "down-to-49"} {
		runner := &scriptedMigrationRunner{version: 52}
		if err := runReleaseMigration(context.Background(), runner, []string{command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != 52 || !equalMigrationEvents(runner.events, []string{"version"}) {
			t.Errorf("historical command %s changed schema52: version=%d events=%v err=%v", command, runner.version, runner.events, err)
		}
	}
	for _, start := range []int64{50, 53} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-51"}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != start || !equalMigrationEvents(runner.events, []string{"version"}) {
			t.Errorf("rollback accepted wrong source%d: version=%d events=%v err=%v", start, runner.version, runner.events, err)
		}
	}
	for _, args := range [][]string{{"up-to-52", "extra"}, {"up-to-56"}, {"down-to-51"}, {"down-to-52"}, {"down-to-53"}} {
		if isForwardMigration(args) {
			t.Error("unexpected forward command", args)
		}
	}
	defaults := &scriptedMigrationRunner{version: 48}
	if err := runReleaseMigration(context.Background(), defaults, []string{"up"}); err != nil || defaults.version != 49 || !equalMigrationEvents(defaults.events, []string{"version", "up-production-runtime-correlation-routing", "version"}) {
		t.Errorf("default migration changed: version=%d events=%v err=%v", defaults.version, defaults.events, err)
	}
}
