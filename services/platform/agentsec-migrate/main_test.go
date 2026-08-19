package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLoadMigrationTimeoutRequiresFiniteBound(t *testing.T) {
	if got, err := loadMigrationTimeout(func(string) string { return "2m" }); err != nil || got != 2*time.Minute {
		t.Fatalf("timeout = (%v, %v)", got, err)
	}
	for _, value := range []string{"", "0s", "31m", "forever"} {
		if _, err := loadMigrationTimeout(func(string) string { return value }); err == nil {
			t.Fatalf("timeout %q accepted", value)
		}
	}
}

type scriptedMigrationRunner struct {
	events  []string
	errAt   string
	version int64
}

func (runner *scriptedMigrationRunner) Version(context.Context) (int64, error) {
	runner.events = append(runner.events, "version")
	if runner.errAt == "version" {
		return 0, errors.New("detail")
	}
	return runner.version, nil
}

func (runner *scriptedMigrationRunner) Up(context.Context) error {
	runner.events = append(runner.events, "up-baseline")
	if runner.errAt == "up-baseline" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) UpCore(context.Context) error {
	runner.events = append(runner.events, "up-core")
	if runner.errAt == "up-core" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) UpWorkflows(context.Context) error {
	runner.events = append(runner.events, "up-workflows")
	if runner.errAt == "up-workflows" {
		return errors.New("detail")
	}
	runner.version = 3
	return nil
}

func (runner *scriptedMigrationRunner) DownWorkflows(context.Context) error {
	runner.events = append(runner.events, "down-workflows")
	if runner.errAt == "down-workflows" {
		return errors.New("detail")
	}
	runner.version = 2
	return nil
}

func (runner *scriptedMigrationRunner) DownCore(context.Context) error {
	runner.events = append(runner.events, "down-core")
	if runner.errAt == "down-core" {
		return errors.New("detail")
	}
	runner.version = 1
	return nil
}

func (runner *scriptedMigrationRunner) Down(context.Context) error {
	runner.events = append(runner.events, "down-baseline")
	if runner.errAt == "down-baseline" {
		return errors.New("detail")
	}
	runner.version = 0
	return nil
}

func TestRunReleaseMigrationReachesExactTargetStateIdempotently(t *testing.T) {
	for _, test := range []struct {
		direction string
		version   int64
		want      []string
	}{
		{direction: "up", version: 0, want: []string{"version", "up-baseline", "up-core", "up-workflows", "version"}},
		{direction: "up", version: 1, want: []string{"version", "up-core", "up-workflows", "version"}},
		{direction: "up", version: 2, want: []string{"version", "up-workflows", "version"}},
		{direction: "up", version: 3, want: []string{"version", "version"}},
		{direction: "down", version: 3, want: []string{"version", "down-workflows", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 2, want: []string{"version", "down-core", "down-baseline", "version"}},
		{direction: "down", version: 1, want: []string{"version", "down-baseline", "version"}},
		{direction: "down", version: 0, want: []string{"version", "version"}},
	} {
		t.Run(test.direction+string(rune('0'+test.version)), func(t *testing.T) {
			runner := &scriptedMigrationRunner{version: test.version}
			if err := runReleaseMigration(context.Background(), runner, []string{test.direction}); err != nil {
				t.Fatal(err)
			}
			if len(runner.events) != len(test.want) {
				t.Fatalf("events = %#v", runner.events)
			}
			for index := range test.want {
				if runner.events[index] != test.want[index] {
					t.Fatalf("events = %#v, want %#v", runner.events, test.want)
				}
			}
		})
	}
}

func TestRunReleaseMigrationRejectsDriftAndHonorsDeadline(t *testing.T) {
	if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{version: 4}, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runReleaseMigration(ctx, &scriptedMigrationRunner{}, []string{"up"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestRunReleaseMigrationRejectsAmbiguousInputsAndStopsOnFailure(t *testing.T) {
	for _, arguments := range [][]string{nil, {}, {"status"}, {"up", "extra"}} {
		if err := runReleaseMigration(context.Background(), &scriptedMigrationRunner{}, arguments); err == nil {
			t.Fatalf("arguments %#v accepted", arguments)
		}
	}
	runner := &scriptedMigrationRunner{errAt: "up-baseline"}
	if err := runReleaseMigration(context.Background(), runner, []string{"up"}); err == nil || len(runner.events) != 2 {
		t.Fatalf("failure = %v, events = %#v", err, runner.events)
	}
}

func TestReleaseMigrationReachesExactPostgresTargetFromEmptyV1AndV2AndRejectsDrift(t *testing.T) {
	dsn := startMigrationPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("empty to v3: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 3 {
		t.Fatalf("v3 = (%d, %v)", version, err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("v3 retry: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"down"}); err != nil {
		t.Fatalf("v3 to empty: %v", err)
	}
	if err := runner.Up(ctx); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); err != nil {
		t.Fatalf("v1 to v3: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_schema_versions SET checksum = repeat('0', 64) WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := runReleaseMigration(ctx, runner, []string{"up"}); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatalf("drift error = %v", err)
	}
}

func startMigrationPostgres(t *testing.T) string {
	t.Helper()
	initdb, initErr := exec.LookPath("initdb")
	postgres, postgresErr := exec.LookPath("postgres")
	ready, readyErr := exec.LookPath("pg_isready")
	ctl, ctlErr := exec.LookPath("pg_ctl")
	if initErr != nil || postgresErr != nil || readyErr != nil || ctlErr != nil {
		t.Skip("local PostgreSQL binaries unavailable")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := exec.Command(initdb, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_test", "-D", data).Run(); err != nil {
		t.Fatalf("initdb: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	var stderr bytes.Buffer
	command := exec.Command(postgres, "-D", data, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", "")
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop := exec.Command(ctl, "-D", data, "-m", "fast", "-w", "stop")
		if stop.Run() != nil && command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if exec.Command(ready, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-U", "zasp_test", "-d", "postgres").Run() == nil {
			return fmt.Sprintf("postgres://zasp_test@127.0.0.1:%d/postgres?sslmode=disable", port)
		}
	}
	t.Fatalf("postgres did not become ready: %s", stderr.String())
	return ""
}
