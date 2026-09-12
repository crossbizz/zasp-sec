package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (runner *scriptedMigrationRunner) UpProductionRuntimeSandboxBinding(context.Context) error {
	runner.events = append(runner.events, "up-sandbox")
	if runner.errAt == "up-sandbox" {
		return migrations.ErrInvalidState
	}
	runner.version = 50
	return nil
}

func (runner *scriptedMigrationRunner) DownProductionRuntimeSandboxBinding(context.Context) error {
	runner.events = append(runner.events, "down-sandbox")
	if runner.errAt == "down-sandbox" {
		return migrations.ErrInvalidState
	}
	runner.version = 49
	return nil
}

func TestSandboxExplicitCommands(t *testing.T) {
	for _, item := range []struct {
		command     string
		start, want int64
		errAt       string
		events      []string
		wantErr     error
	}{
		{"up-to-50", 49, 50, "", []string{"version", "up-sandbox", "version"}, nil},
		{"up-to-50", 48, 50, "", []string{"version", "up-production-runtime-correlation-routing", "up-sandbox", "version"}, nil},
		{"up-to-50", 50, 50, "", []string{"version", "version"}, nil},
		{"up-to-50", 51, 51, "", []string{"version"}, migrations.ErrInvalidState},
		{"up-to-50", 49, 49, "up-sandbox", []string{"version", "up-sandbox"}, migrations.ErrInvalidState},
		{"down-to-49", 50, 49, "", []string{"version", "down-sandbox", "version"}, nil},
		{"down-to-49", 49, 49, "", []string{"version", "version"}, nil},
		{"down-to-49", 48, 48, "", []string{"version"}, migrations.ErrInvalidState},
		{"down-to-49", 51, 51, "", []string{"version"}, migrations.ErrInvalidState},
		{"down-to-49", 50, 50, "down-sandbox", []string{"version", "down-sandbox"}, migrations.ErrInvalidState},
	} {
		runner := &scriptedMigrationRunner{version: item.start, errAt: item.errAt}
		err := runReleaseMigration(context.Background(), runner, []string{item.command})
		if !errors.Is(err, item.wantErr) || runner.version != item.want || !equalMigrationEvents(runner.events, item.events) {
			t.Errorf("%s from %d: version=%d events=%v err=%v", item.command, item.start, runner.version, runner.events, err)
		}
	}
	if !isForwardMigration([]string{"up-to-50"}) {
		t.Fatal("release50 skips principal registration")
	}
	for _, args := range [][]string{{"down-to-49"}, {"up-to-50", "extra"}, {"up-to-52"}} {
		if isForwardMigration(args) {
			t.Fatal("unexpected principal registration", args)
		}
	}
}
