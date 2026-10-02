package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type bootstrapObservedRunner struct {
	*scriptedMigrationRunner
	beforeAudit func()
}

func (runner *bootstrapObservedRunner) UpProductionAuditExports(ctx context.Context) error {
	runner.beforeAudit()
	return runner.scriptedMigrationRunner.UpProductionAuditExports(ctx)
}

func TestRegisteredMigrationBootstrapsBeforeAuditExports(t *testing.T) {
	base := &scriptedMigrationRunner{version: 50}
	q := &releaseReadinessQueryer{}
	observed := &bootstrapObservedRunner{scriptedMigrationRunner: base, beforeAudit: func() {
		if len(q.statements) != 18 {
			t.Fatalf("audit migration entered before registration/readiness finished: %v", q.statements)
		}
	}}
	runner := &registeredReleaseMigrationRunner{releaseMigrationRunner: observed, queryer: q}
	if err := runReleaseMigration(context.Background(), runner, []string{"up-to-55"}); err != nil {
		t.Fatal(err)
	}
	if base.version != 55 || !equalMigrationEvents(base.events, []string{"version", "up-precision", "up-audit-exports", "up-security-agent-budgets", "up-security-agent-run-context", "up-existing-tests", "version"}) {
		t.Fatalf("wrong migration path: %v", base.events)
	}
	if len(q.statements) != 18 || q.statements[0] != "SELECT zasp_production_runtime_precision_readiness($1,$2)" || q.statements[1] != "SELECT session_user=$1" || q.statements[17] != q.statements[0] || !reflect.DeepEqual(q.arguments[0], []any{migrations.ProductionRuntimePrecision().Checksum(), migrations.ProductionRuntimePrecisionSemanticFingerprint()}) {
		t.Fatalf("missing drift/registration barrier: %v %v", q.statements, q.arguments)
	}
}

func TestRegisteredMigrationBootstrapFailureNeverCrosses51(t *testing.T) {
	for index := 1; index <= 18; index++ {
		for _, queryError := range []bool{false, true} {
			base := &scriptedMigrationRunner{version: 51}
			q := &releaseReadinessQueryer{failAt: index, queryError: queryError}
			runner := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}
			if err := runReleaseMigration(context.Background(), runner, []string{"up-to-55"}); !errors.Is(err, errReleasePrincipalRegistration) || base.version != 51 || !equalMigrationEvents(base.events, []string{"version"}) || len(q.statements) != index {
				t.Fatalf("barrier%d error=%v events=%v calls=%d", index, err, base.events, len(q.statements))
			}
		}
	}
}

func TestRegisteredMigrationDoesNotRebindHistoricalOrLaterReleases(t *testing.T) {
	for _, tc := range []struct {
		version int64
		command string
	}{{48, "up"}, {51, "up-to-51"}, {52, "up-to-55"}, {55, "up-to-55"}, {55, "down-to-54"}} {
		base := &scriptedMigrationRunner{version: tc.version}
		q := &releaseReadinessQueryer{}
		if err := runReleaseMigration(context.Background(), &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}, []string{tc.command}); err != nil || len(q.statements) != 0 {
			t.Fatalf("unrelated command ran bootstrap %+v: %v %v", tc, err, q.statements)
		}
	}
}

func TestRegisteredMigrationWebhookCommands(t *testing.T) {
	for _, tc := range []struct {
		name, command, event string
		start, end           int64
	}{
		{"upgrade", "up-to-59", "up-agent-webhooks", 58, 59},
		{"downgrade", "down-from-59", "down-agent-webhooks", 59, 58},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, fail := range []bool{false, true} {
				base := &scriptedMigrationRunner{version: tc.start}
				if fail {
					base.errAt = tc.event
				}
				q := &releaseReadinessQueryer{}
				err := runReleaseMigration(context.Background(), &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}, []string{tc.command})
				if fail {
					if !errors.Is(err, migrations.ErrInvalidState) || base.version != tc.start {
						t.Fatalf("failed wrapper command: version=%d error=%v", base.version, err)
					}
				} else if err != nil || base.version != tc.end {
					t.Fatalf("production wrapper %s: version=%d error=%v", tc.command, base.version, err)
				}
				if len(base.events) < 2 || base.events[1] != tc.event || len(q.statements) != 0 {
					t.Fatalf("wrong wrapper path: events=%v queries=%v", base.events, q.statements)
				}
			}
		})
	}
}

func (r *scriptedMigrationRunner) UpProductionDiscoveryScheduleReplay(context.Context) error {
	r.events = append(r.events, "up-schedule-replay")
	if r.errAt == "up-schedule-replay" {
		return migrations.ErrInvalidState
	}
	r.version = 60
	return nil
}

func (r *scriptedMigrationRunner) DownProductionDiscoveryScheduleReplay(context.Context) error {
	r.events = append(r.events, "down-schedule-replay")
	if r.errAt == "down-schedule-replay" {
		return migrations.ErrInvalidState
	}
	r.version = 59
	return nil
}

func TestProductionDiscoveryScheduleReplayCommands(t *testing.T) {
	for _, tc := range []struct {
		command, event string
		start, end     int64
	}{
		{"up-to-60", "up-schedule-replay", 59, 60}, {"down-from-60", "down-schedule-replay", 60, 59},
	} {
		for _, fail := range []bool{false, true} {
			base := &scriptedMigrationRunner{version: tc.start}
			if fail {
				base.errAt = tc.event
			}
			q := &releaseReadinessQueryer{}
			err := runReleaseMigration(context.Background(), &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q}, []string{tc.command})
			if fail {
				if !errors.Is(err, migrations.ErrInvalidState) || base.version != tc.start {
					t.Fatalf("failed command crossed release: %v", err)
				}
			} else if err != nil || base.version != tc.end {
				t.Fatalf("production wrapper %s: version=%d error=%v", tc.command, base.version, err)
			}
			if len(base.events) < 2 || base.events[1] != tc.event || len(q.statements) != 0 {
				t.Fatalf("wrong release path: %v", base.events)
			}
		}
	}
	if !isForwardMigration([]string{"up-to-60"}) {
		t.Fatal("release60 skips principal registration")
	}
}
