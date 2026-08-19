package apiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionDiscoveryPostgresFreshUpgradeRestartDriftAndGuardedDown(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func(context.Context) error{runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance, runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection, runner.UpProductionDiscovery}
	for index, step := range steps {
		if err := step(ctx); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	if version, err := runner.Version(ctx); err != nil || version != 10 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
	var actualFingerprint string
	if err := connection.QueryRow(ctx, fingerprintQuery).Scan(&actualFingerprint); err != nil {
		t.Fatal(err)
	}
	if actualFingerprint != migrations.ProductionDiscoverySemanticFingerprint() {
		t.Fatalf("v10 semantic fingerprint=%q marker=%q", actualFingerprint, migrations.ProductionDiscoverySemanticFingerprint())
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_readiness()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("readiness=%v err=%v", ready, err)
	}
	var canonical1, canonical2 string
	args := []any{"pid_10000001-0000-4000-8000-000000000001", "pid_10000002-0000-4000-8000-000000000002", "pid_10000003-0000-4000-8000-000000000003", "aws_account", "123456789012"}
	if err := connection.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,$4,$5),zasp_discovery_canonical_id($1,$2,$3,$4,$5)`, args...).Scan(&canonical1, &canonical2); err != nil || canonical1 != canonical2 || !strings.HasPrefix(canonical1, "pid_") {
		t.Fatalf("canonical=%q/%q err=%v", canonical1, canonical2, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	connection, err = pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ = migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	if version, err := runner.Version(ctx); err != nil || version != 10 {
		t.Fatalf("restart version=%d err=%v", version, err)
	}
	if err := runner.UpProductionDiscovery(ctx); err == nil {
		t.Fatal("reapply unexpectedly succeeded")
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_integrations ADD COLUMN hostile_drift text`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionDiscovery(ctx); err == nil {
		t.Fatal("semantic drift did not block down")
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_integrations DROP COLUMN hostile_drift`); err != nil {
		t.Fatal(err)
	}
	if err := runner.DownProductionDiscovery(ctx); err != nil {
		t.Fatalf("empty guarded down: %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 9 {
		t.Fatalf("down version=%d err=%v", version, err)
	}
}
