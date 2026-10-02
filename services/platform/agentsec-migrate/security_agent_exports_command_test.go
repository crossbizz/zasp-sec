package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *scriptedMigrationRunner) UpProductionSecurityAgentExports(context.Context) error {
	r.events = append(r.events, "up-agent-exports")
	if r.errAt == "up-agent-exports" {
		return migrations.ErrInvalidState
	}
	r.version = 58
	return nil
}

func (r *scriptedMigrationRunner) DownProductionSecurityAgentExports(context.Context) error {
	r.events = append(r.events, "down-agent-exports")
	if r.errAt == "down-agent-exports" {
		return migrations.ErrInvalidState
	}
	r.version = 57
	return nil
}

func TestSecurityAgentExportsExplicitReleaseCommands(t *testing.T) {
	for _, tc := range []struct {
		start   int64
		command string
		want    []string
		end     int64
	}{
		{56, "up-to-58", []string{"version", "up-attack-lab", "up-agent-exports", "version"}, 58},
		{57, "up-to-58", []string{"version", "up-agent-exports", "version"}, 58},
		{58, "up-to-58", []string{"version", "version"}, 58},
		{58, "down-from-58", []string{"version", "down-agent-exports"}, 57},
	} {
		r := &scriptedMigrationRunner{version: tc.start}
		if err := runReleaseMigration(context.Background(), r, []string{tc.command}); err != nil || r.version != tc.end || !reflect.DeepEqual(r.events, tc.want) {
			t.Errorf("%d %s: end=%d events=%v error=%v", tc.start, tc.command, r.version, r.events, err)
		}
	}
	if !isForwardMigration([]string{"up-to-58"}) {
		t.Error("schema58 bypasses principal registration")
	}
	for _, command := range []string{"up", "up-to-57", "down-from-57", "up-to-61"} {
		r := &scriptedMigrationRunner{version: 58}
		if err := runReleaseMigration(context.Background(), r, []string{command}); err == nil || r.version != 58 || !reflect.DeepEqual(r.events, []string{"version"}) {
			t.Errorf("command crossed schema58: %s %v %v", command, err, r.events)
		}
	}
	for _, tc := range []struct {
		start            int64
		command, failure string
	}{{57, "up-to-58", "up-agent-exports"}, {58, "down-from-58", "down-agent-exports"}} {
		r := &scriptedMigrationRunner{version: tc.start, errAt: tc.failure}
		if err := runReleaseMigration(context.Background(), r, []string{tc.command}); !errors.Is(err, migrations.ErrInvalidState) || r.version != tc.start || !reflect.DeepEqual(r.events, []string{"version", tc.failure}) {
			t.Errorf("failed migration escaped: %+v %v %v", tc, err, r.events)
		}
	}
	for _, start := range []int64{56, 57, 59} {
		r := &scriptedMigrationRunner{version: start}
		if err := runReleaseMigration(context.Background(), r, []string{"down-from-58"}); err == nil || !reflect.DeepEqual(r.events, []string{"version"}) {
			t.Errorf("rollback accepted %d: %v", start, err)
		}
	}
}

func TestSecurityAgentExportsForwardReadiness(t *testing.T) {
	q := &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-58"}); err != nil {
		t.Fatal(err)
	}
	if len(q.statements) != 17 || q.statements[16] != "SELECT zasp_sa_export_readiness($1,$2)" || !reflect.DeepEqual(q.arguments[16], []any{migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}) {
		t.Fatalf("unbound schema58 readiness: %v %v", q.statements, q.arguments)
	}
	for i := 1; i <= 17; i++ {
		for _, queryError := range []bool{false, true} {
			q := &releaseReadinessQueryer{failAt: i, queryError: queryError}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-58"}); !errors.Is(err, errReleasePrincipalRegistration) || len(q.statements) != i {
				t.Fatalf("failed authority/readiness not stopped: %d %v %v", i, err, q.statements)
			}
		}
	}
}

func (r *scriptedMigrationRunner) UpProductionSecurityAgentWebhooks(context.Context) error {
	r.events = append(r.events, "up-agent-webhooks")
	if r.errAt == "up-agent-webhooks" {
		return migrations.ErrInvalidState
	}
	r.version = 59
	return nil
}
func (r *scriptedMigrationRunner) DownProductionSecurityAgentWebhooks(context.Context) error {
	r.events = append(r.events, "down-agent-webhooks")
	if r.errAt == "down-agent-webhooks" {
		return migrations.ErrInvalidState
	}
	r.version = 58
	return nil
}
func TestSecurityAgentWebhooksExplicitReleaseCommands(t *testing.T) {
	for _, tc := range []struct {
		start   int64
		command string
		end     int64
		events  []string
	}{
		{57, "up-to-59", 59, []string{"version", "up-agent-exports", "up-agent-webhooks", "version"}},
		{58, "up-to-59", 59, []string{"version", "up-agent-webhooks", "version"}},
		{59, "up-to-59", 59, []string{"version", "version"}},
		{59, "down-from-59", 58, []string{"version", "down-agent-webhooks"}},
	} {
		r := &scriptedMigrationRunner{version: tc.start}
		if err := runReleaseMigration(context.Background(), r, []string{tc.command}); err != nil || r.version != tc.end || !reflect.DeepEqual(r.events, tc.events) {
			t.Fatalf("%+v version=%d events=%v error=%v", tc, r.version, r.events, err)
		}
	}
	if !isForwardMigration([]string{"up-to-59"}) || isForwardMigration([]string{"up-to-61"}) {
		t.Fatal("release59 command boundary")
	}
	for _, tc := range []struct {
		start            int64
		command, failure string
	}{{58, "up-to-59", "up-agent-webhooks"}, {59, "down-from-59", "down-agent-webhooks"}} {
		r := &scriptedMigrationRunner{version: tc.start, errAt: tc.failure}
		if err := runReleaseMigration(context.Background(), r, []string{tc.command}); !errors.Is(err, migrations.ErrInvalidState) || r.version != tc.start {
			t.Fatalf("failed59 escaped: %v", err)
		}
	}
	q := &releaseReadinessQueryer{}
	if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{}, []string{"up-to-59"}); err != nil || len(q.statements) != 17 || q.statements[16] != "SELECT zasp_sa_webhook_readiness($1,$2)" || !reflect.DeepEqual(q.arguments[16], []any{migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint()}) {
		t.Fatalf("release59 readiness=%v statements=%v", err, q.statements)
	}
}
