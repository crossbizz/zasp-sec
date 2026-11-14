package main

import (
	"context"
	"errors"
	"testing"
	"time"
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
