package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type maintenanceProfileRunner struct {
	*scriptedMigrationRunner
	approval, connector int
	failure             error
}

func (r *maintenanceProfileRunner) UpProductionApprovalMaintenanceProfile(context.Context) error {
	r.approval++
	return r.failure
}
func (r *maintenanceProfileRunner) UpProductionConnectorMaintenance(context.Context) error {
	r.connector++
	return r.failure
}

func TestMaintenanceProfileExplicitCommands(t *testing.T) {
	for _, command := range []string{"up-approval-maintenance-profile", "up-connector-maintenance-profile"} {
		t.Run(command, func(t *testing.T) {
			base := &maintenanceProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
			registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: &releaseReadinessQueryer{}, registration: discoveryPrincipalRegistration{migration: "profile_operator"}}
			args := []string{command}
			if !isForwardMigration(args) || isForwardMigration([]string{command, "extra"}) {
				t.Error("explicit finite forward command unavailable")
			}
			for range 2 {
				if err := runReleaseMigration(context.Background(), registered, args); err != nil {
					t.Errorf("guarded installer dispatch refused: %v", err)
				}
			}
			if command == "up-approval-maintenance-profile" && (base.approval != 2 || base.connector != 0) || command == "up-connector-maintenance-profile" && (base.connector != 2 || base.approval != 0) {
				t.Error("wrong installer or replay count", base.approval, base.connector)
			}
			before := base.approval + base.connector
			for _, version := range []int64{0, 60, 62, 80} {
				base.version = version
				if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) {
					t.Errorf("wrong version %d: %v", version, err)
				}
			}
			base.version = 61
			if base.approval+base.connector != before {
				t.Error("invalid version reached installer")
			}
			registered.queryer = &releaseReadinessQueryer{failAt: 1}
			if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, errReleasePrincipalRegistration) || base.approval+base.connector != before {
				t.Error("operator admission bypass", err)
			}
			registered.queryer = &releaseReadinessQueryer{}
			cause := errors.New("controlled installer refusal")
			base.failure = cause
			if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, cause) {
				t.Error("installer refusal changed", err)
			}
			registered.releaseMigrationRunner = base.scriptedMigrationRunner
			if err := runReleaseMigration(context.Background(), registered, args); !errors.Is(err, migrations.ErrInvalidState) {
				t.Error("missing installer fell back", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := runReleaseMigration(ctx, registered, args); !errors.Is(err, context.Canceled) {
				t.Error("cancelled command admitted", err)
			}
		})
	}
}

func TestMaintenanceProfilePostInstallCatalogOnly(t *testing.T) {
	for _, command := range []string{"up-approval-maintenance-profile", "up-connector-maintenance-profile"} {
		t.Run(command, func(t *testing.T) {
			q := &releaseReadinessQueryer{}
			if err := registerForwardRelease(context.Background(), q, discoveryPrincipalRegistration{migration: "profile_operator"}, []string{command}); err != nil {
				t.Fatalf("post-install catalog refused: %v", err)
			}
			if len(q.statements) != 1 || !strings.Contains(q.statements[0], "session_user=$1") || !strings.Contains(q.statements[0], "catalog_ready(") || strings.Contains(q.statements[0], "runtime_ready()") || strings.Contains(q.statements[0], "activate") {
				t.Error("wrong catalog-only postcheck", q.statements)
			}
			for _, queryError := range []bool{false, true} {
				if err := registerForwardRelease(context.Background(), &releaseReadinessQueryer{failAt: 1, queryError: queryError}, discoveryPrincipalRegistration{}, []string{command}); !errors.Is(err, errReleasePrincipalRegistration) {
					t.Error("catalog refusal escaped", err)
				}
			}
		})
	}
}
