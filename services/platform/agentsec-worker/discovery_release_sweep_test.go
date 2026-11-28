package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)

// The scheduler releases abandoned discovery runs on a timer: once per
// interval, again after a failure, and with the processor's batch bound.
func TestScheduleProcessorReleasesAbandonedRunsOnATimer(t *testing.T) {
	at := time.Date(2026, 11, 14, 4, 0, 0, 0, time.UTC)
	var calls []int
	var fail error
	p := &temporalDiscoveryScheduleProcessor{limit: 25, now: func() time.Time { return at },
		release: func(_ context.Context, limit int) (int, error) { calls = append(calls, limit); return 0, fail }}
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 1 || calls[0] != 25 {
		t.Fatalf("first pass err=%v calls=%v", err, calls)
	}
	at = at.Add(discoveryReleaseInterval - time.Second)
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 1 {
		t.Fatalf("pass inside the interval err=%v calls=%v", err, calls)
	}
	at = at.Add(time.Second)
	fail = errors.New("database unavailable")
	if err := p.releaseDue(context.Background()); err == nil || len(calls) != 2 {
		t.Fatalf("failed sweep err=%v calls=%v", err, calls)
	}
	// A failed sweep does not wait for the next interval.
	fail = nil
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("retry after failure err=%v calls=%v", err, calls)
	}
	if err := p.releaseDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("pass after success err=%v calls=%v", err, calls)
	}
}

// The scheduler queues the due red team re-tests on its own timer, with the
// same retry rule, independently of the release sweep.
func TestScheduleProcessorQueuesRedTeamRetestsOnATimer(t *testing.T) {
	at := time.Date(2026, 11, 14, 4, 0, 0, 0, time.UTC)
	var calls []int
	var fail error
	p := &temporalDiscoveryScheduleProcessor{limit: 25, now: func() time.Time { return at },
		retest: func(_ context.Context, limit int) (int, error) { calls = append(calls, limit); return 1, fail }}
	if err := p.retestDue(context.Background()); err != nil || len(calls) != 1 || calls[0] != 25 {
		t.Fatalf("first pass err=%v calls=%v", err, calls)
	}
	at = at.Add(redTeamRetestInterval - time.Second)
	if err := p.retestDue(context.Background()); err != nil || len(calls) != 1 {
		t.Fatalf("pass inside the interval err=%v calls=%v", err, calls)
	}
	at = at.Add(time.Second)
	fail = errors.New("database unavailable")
	if err := p.retestDue(context.Background()); err == nil || len(calls) != 2 {
		t.Fatalf("failed pass err=%v calls=%v", err, calls)
	}
	fail = nil
	if err := p.retestDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("retry after failure err=%v calls=%v", err, calls)
	}
	if !p.lastRelease.IsZero() {
		t.Fatal("the re-test pass moved the release timer")
	}
}

// The scheduler looks after the hosted gateway's records on its own timer:
// with the configured retention (90 days when none is set) and the
// processor's batch bound, again at once after a pass that reached its bound
// or failed, and otherwise once per interval.
func TestScheduleProcessorMaintainsTheGatewayOnATimer(t *testing.T) {
	at := time.Date(2026, 11, 14, 4, 0, 0, 0, time.UTC)
	type call struct{ days, limit int }
	var calls []call
	var fail error
	done := gatewayMaintenance{Examined: 3, Projected: 2, Deleted: 1}
	p := &temporalDiscoveryScheduleProcessor{limit: 25, now: func() time.Time { return at },
		maintain: func(_ context.Context, days, limit int) (gatewayMaintenance, error) {
			calls = append(calls, call{days, limit})
			return done, fail
		}}
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 1 || calls[0] != (call{90, 25}) {
		t.Fatalf("first pass err=%v calls=%v", err, calls)
	}
	at = at.Add(gatewayMaintenanceInterval - time.Second)
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 1 {
		t.Fatalf("pass inside the interval err=%v calls=%v", err, calls)
	}
	at = at.Add(time.Second)
	p.gatewayRetentionDays = 30
	fail = errors.New("database unavailable")
	if err := p.maintainDue(context.Background()); err == nil || len(calls) != 2 || calls[1] != (call{30, 25}) {
		t.Fatalf("failed pass err=%v calls=%v", err, calls)
	}
	// A failed pass does not wait for the next interval, and neither does
	// one that deleted or examined as much as one pass may.
	fail, done = nil, gatewayMaintenance{Deleted: 2500}
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 3 {
		t.Fatalf("retry after failure err=%v calls=%v", err, calls)
	}
	done = gatewayMaintenance{Examined: 2500, Projected: 2500}
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 4 {
		t.Fatalf("pass after a full one err=%v calls=%v", err, calls)
	}
	done = gatewayMaintenance{Deleted: 2499}
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 5 {
		t.Fatalf("pass after a second full one err=%v calls=%v", err, calls)
	}
	if err := p.maintainDue(context.Background()); err != nil || len(calls) != 5 {
		t.Fatalf("pass after one that finished err=%v calls=%v", err, calls)
	}
	if !p.lastRelease.IsZero() || !p.lastRetest.IsZero() {
		t.Fatal("the gateway pass moved another timer")
	}
}

// The retention of gateway decisions is a setting of the scheduler: 90 days
// when it is not set, a whole number of days from 1 to 3650 when it is, and
// refused in any other mode.
func TestGatewayDecisionRetentionSetting(t *testing.T) {
	load := func(mode, value string) (workerRuntimeConfig, error) {
		environment := map[string]string{
			"ZASP_WORKER_MODE": "scheduler", "ZASP_POSTGRES_DSN": "postgres://scheduler@postgres.internal/zasp?sslmode=verify-full", "ZASP_DATABASE_AUTHORITY": "zasp_discovery_scheduler", "ZASP_WORKER_ID": "scheduler-01",
			"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "30s", "ZASP_BATCH_SIZE": "8", "ZASP_SHUTDOWN_TIMEOUT": "20s",
			"ZASP_DISCOVERY_PARSER_VERSION": "inventory-parser-2026.08.20", "ZASP_DISCOVERY_TOOL_VERSION": "collector-tool-2026.08.20",
		}
		if mode != "scheduler" {
			environment = map[string]string{
				"ZASP_WORKER_MODE": "attack-lab-outbox", "ZASP_POSTGRES_DSN": "postgres://attack_lab_outbox@postgres.internal/zasp?sslmode=verify-full",
				"ZASP_DATABASE_AUTHORITY": "zasp_attack_lab_outbox_worker", "ZASP_WORKER_ID": "attack-lab-outbox-01",
				"ZASP_POLL_INTERVAL": "250ms", "ZASP_LEASE_DURATION": "60s", "ZASP_BATCH_SIZE": "10", "ZASP_SHUTDOWN_TIMEOUT": "20s",
				"ZASP_ATTACK_LAB_QUEUE_URL": "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-attack-lab-jobs", "ZASP_AWS_REGION": "us-west-2",
				"ZASP_OUTBOX_ROLE_ARN": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-outbox", "ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
			}
		}
		if value != "" {
			environment["ZASP_GATEWAY_DECISION_RETENTION_DAYS"] = value
		}
		return loadWorkerRuntimeConfig(mapLookup(environment))
	}
	config, err := load("scheduler", "")
	if err != nil || config.GatewayDecisionRetentionDays != 90 {
		t.Fatalf("the default: days=%d err=%v", config.GatewayDecisionRetentionDays, err)
	}
	for value, want := range map[string]int{"1": 1, "30": 30, "3650": 3650} {
		if config, err := load("scheduler", value); err != nil || config.GatewayDecisionRetentionDays != want {
			t.Fatalf("%q: days=%d err=%v", value, config.GatewayDecisionRetentionDays, err)
		}
	}
	for _, value := range []string{"0", "-1", "3651", "ninety", "30d", " 30", "030", "1.5"} {
		if _, err := load("scheduler", value); err == nil {
			t.Fatalf("%q was accepted", value)
		}
	}
	if _, err := load("attack-lab-outbox", ""); err != nil {
		t.Fatalf("another mode without the setting: %v", err)
	}
	if _, err := load("attack-lab-outbox", "30"); err == nil {
		t.Fatal("another mode took the scheduler's setting")
	}
}

// The scheduler's own source runs the gateway's pass on the scheduler's
// login against a database that holds completion.sql section WS9. It needs
// ZASP_GATEWAY_SCHEDULER_DSN, the DSN of that login on an installed
// baseline with the section applied (TestHostedGatewayOnInstalledBaselinePostgres
// of the apiserver package applies it).
func TestGatewayMaintenanceInstalledScheduleSource(t *testing.T) {
	dsn := os.Getenv("ZASP_GATEWAY_SCHEDULER_DSN")
	if dsn == "" {
		t.Skip("requires an installed baseline with section WS9 and the scheduler's login")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source, err := newTemporalDiscoveryScheduleSource(ctx, dsn, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done, err := source.maintainGateway(ctx, 90, 25)
	if err != nil || done.Projected > done.Examined {
		t.Fatalf("pass=%+v err=%v", done, err)
	}
	// What the database refuses is a failure of the pass, not an empty one.
	if _, err := source.maintainGateway(ctx, 0, 25); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("a retention of no days: %v", err)
	}
	p := &temporalDiscoveryScheduleProcessor{source: source, limit: 25, gatewayRetentionDays: 30}
	if err := p.maintainDue(ctx); err != nil || p.lastMaintain.IsZero() {
		t.Fatalf("the processor's pass: %v", err)
	}
}

// A current baseline must not accept a missing sweep, a missing dependency
// inside the installed sweep, or a scheduler whose execute grant was revoked.
func TestScheduleReleaseSweepRefusesBrokenBaselinePostgres(t *testing.T) {
	adminDSN := startSingleRecoveryScalarPostgres(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err := admin.Exec(ctx, "CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE sweep_fixture OWNER zasp_operator TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	address, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	address.Path = "/sweep_fixture"
	migrationDSN := *address
	migrationDSN.User = url.User("zasp_operator")
	operator, err := pgx.Connect(ctx, migrationDSN.String())
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close(context.Background())
	if err := baseline.Install(ctx, operator); err != nil {
		t.Fatal(err)
	}
	owner, err := pgx.Connect(ctx, address.String())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	address.User = url.User("zasp_svc_scheduler")
	source := temporalDiscoveryScheduleSource{dsn: address.String(), timeout: 10 * time.Second}
	if released, err := source.releaseAbandoned(ctx, 1); err != nil || released != 0 {
		t.Fatalf("intact release sweep: released=%d err=%v", released, err)
	}
	for _, fault := range []struct{ name, statement string }{
		{"revoked_grant", "REVOKE EXECUTE ON FUNCTION zasp_temporal72.release_abandoned_due(integer) FROM zasp_discovery_scheduler"},
		{"missing_dependency", `GRANT EXECUTE ON FUNCTION zasp_temporal72.release_abandoned_due(integer) TO zasp_discovery_scheduler;
CREATE OR REPLACE FUNCTION zasp_temporal72.release_abandoned_due(limit_value integer) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN RETURN zasp_temporal72.uninstalled_sweep_dependency(); END $$`},
		{"missing_sweep", "DROP FUNCTION zasp_temporal72.release_abandoned_due(integer)"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := owner.Exec(ctx, fault.statement); err != nil {
				t.Fatal(err)
			}
			if _, err := source.releaseAbandoned(ctx, 1); !errors.Is(err, errWorkerExecution) {
				t.Fatalf("damaged baseline accepted by the scheduler: %v", err)
			}
		})
	}
}
