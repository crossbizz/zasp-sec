package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (runner *scriptedMigrationRunner) UpProductionSecurityAgentRunContext(context.Context) error {
	runner.events = append(runner.events, "up-security-agent-run-context")
	if runner.errAt == "up-security-agent-run-context" {
		return migrations.ErrInvalidState
	}
	runner.version = 54
	return nil
}
func (runner *scriptedMigrationRunner) DownProductionSecurityAgentRunContext(context.Context) error {
	runner.events = append(runner.events, "down-security-agent-run-context")
	if runner.errAt == "down-security-agent-run-context" {
		return migrations.ErrInvalidState
	}
	runner.version = 53
	return nil
}

func TestRunContextExplicitReleaseCommands(t *testing.T) {
	for _, start := range []int64{52, 53, 54} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"up-to-54"}); err != nil || runner.version != 54 {
			t.Errorf("up from%d: version=%d error=%v", start, runner.version, err)
		}
	}
	if !isForwardMigration([]string{"up-to-54"}) {
		t.Error("54 command skips principal registration")
	}
	for _, start := range []int64{53, 54} {
		runner := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), runner, []string{"down-to-53"}); err != nil || runner.version != 53 {
			t.Errorf("down from%d: version=%d error=%v", start, runner.version, err)
		}
	}
	for _, command := range []string{"up", "up-to-53", "down-to-52", "down"} {
		runner := &scriptedMigrationRunner{version: 54}
		if err := runReleaseMigration(context.Background(), runner, []string{command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != 54 || !equalMigrationEvents(runner.events, []string{"version"}) {
			t.Errorf("historical command%s crossed54: %v %v", command, err, runner.events)
		}
	}
	for _, operation := range []string{"up-security-agent-run-context", "down-security-agent-run-context"} {
		start, command := int64(53), "up-to-54"
		if operation[0:4] == "down" {
			start, command = 54, "down-to-53"
		}
		runner := &scriptedMigrationRunner{version: start, errAt: operation}
		if err := runReleaseMigration(context.Background(), runner, []string{command}); !errors.Is(err, migrations.ErrInvalidState) || runner.version != start {
			t.Errorf("failed command lost boundary: %v", err)
		}
	}
}
