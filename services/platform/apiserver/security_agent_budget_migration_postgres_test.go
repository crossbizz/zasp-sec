package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentBudgetMigrationRoundTripAndFences(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	installAuditExports(t, ctx, admin)
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	runner := precisionMigrationRunner(t, migrator)
	budget, ok := any(runner).(interface {
		UpProductionSecurityAgentBudgets(context.Context) error
		DownProductionSecurityAgentBudgets(context.Context) error
	})
	if !ok {
		t.Fatal("registered budget migration runner is missing")
	}
	for _, direction := range []struct {
		name          string
		run           func(context.Context) error
		before, after int64
	}{{"up", budget.UpProductionSecurityAgentBudgets, 52, 53}, {"down", budget.DownProductionSecurityAgentBudgets, 53, 52}} {
		tables := []string{"zasp_schema_versions", "zasp_security_agent_runs", "zasp_security_agent_steps", "zasp_security_agent_temporary_policy_targets"}
		if direction.name == "down" {
			tables = append(tables, "zasp_security_agent_provider_reservations")
		}
		for _, table := range tables {
			t.Run(direction.name+"/"+table, func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN ACCESS SHARE MODE"); err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 2*time.Second)
				err = direction.run(bounded)
				timedOut := bounded.Err() != nil
				stop()
				if timedOut || !errors.Is(err, migrations.ErrDatabase) {
					t.Fatal("cutover did not promptly refuse occupied fence", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if version, err := runner.Version(ctx); err != nil || version != direction.before {
					t.Fatal("failed cutover changed release", version, err)
				}
			})
		}
		if err := direction.run(ctx); err != nil {
			t.Fatal(direction.name, err)
		}
		if version, err := runner.Version(ctx); err != nil || version != direction.after {
			t.Fatal("wrong release after cutover", version, err)
		}
	}
	var restored bool
	if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&restored); err != nil || !restored {
		t.Fatal("exact predecessor not restored", restored, err)
	}
	if err := budget.UpProductionSecurityAgentBudgets(ctx); err != nil {
		t.Fatal("second up", err)
	}
	var inserted string
	if err := admin.QueryRow(ctx, `INSERT INTO zasp_security_agent_org_admissions(organization_id) SELECT id FROM zasp_organizations ORDER BY id LIMIT 1 RETURNING organization_id`).Scan(&inserted); err != nil {
		t.Fatal(err)
	}
	if err := budget.DownProductionSecurityAgentBudgets(ctx); err == nil {
		t.Fatal("rollback discarded retained admission authority")
	}
	if version, err := runner.Version(ctx); err != nil || version != 53 {
		t.Fatal("refused rollback changed release", version, err)
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_org_admissions WHERE organization_id=$1`, inserted).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback lost admission", count, err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE budget_migration_member LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT zasp_discovery_authority TO budget_migration_member`); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "budget_migration_member"
	member, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close(context.Background())
	if err := member.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_org_admissions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("fixture member must be subject to forced RLS", count, err)
	}
	probe, err := member.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(context.Background())
	_, err = probe.Exec(ctx, migrations.ProductionSecurityAgentBudgets().DownSQL())
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "55000" || postgresError.Message != "retained security agent budget authority" {
		t.Fatalf("forced-RLS member bypassed retention assertion: %v", err)
	}
}
