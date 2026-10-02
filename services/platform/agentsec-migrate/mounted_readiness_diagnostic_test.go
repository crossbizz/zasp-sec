package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This observer never commits. Only the mounted harness's owned database may
// opt in; no default integration fixture or host server is started.
func TestMountedReadinessDiagnostic(t *testing.T) {
	if os.Getenv("ZASP_COMBINED_E2E_EXISTING_TEST") != "true" {
		t.Skip("owned mounted diagnostic only")
	}
	u, err := url.Parse(os.Getenv("ZASP_POSTGRES_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" || u.User.Username() != "zasp_e2e" || u.Port() == "" {
		t.Fatal("owned database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	db := &mountedReadinessDatabase{migrationDatabase: migrationDatabase{connection: c}, t: t}
	runner, err := migrations.NewRunner(db)
	if err != nil {
		t.Fatal(err)
	}
	err = runner.UpProductionDiscoveryExecution(ctx)
	t.Logf("actual release13 runner result: %v", err)
	var version int
	if err := c.QueryRow(ctx, "SELECT max(version) FROM zasp_schema_versions").Scan(&version); err != nil || version != 12 {
		t.Fatalf("diagnostic changed installed release: %d %v", version, err)
	}
}

type mountedReadinessDatabase struct {
	migrationDatabase
	t *testing.T
}

func (d *mountedReadinessDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &mountedReadinessTransaction{migrationTransaction: migrationTransaction{transaction: tx}, t: d.t}, nil
}

type mountedReadinessTransaction struct {
	migrationTransaction
	t *testing.T
}

func (tx *mountedReadinessTransaction) Commit(ctx context.Context) error {
	if err := tx.transaction.Rollback(ctx); err != nil {
		return err
	}
	return errors.New("diagnostic always rolls back")
}
func (tx *mountedReadinessTransaction) Exec(ctx context.Context, sql string, args ...any) error {
	err := tx.migrationTransaction.Exec(ctx, sql, args...)
	if err != nil {
		tx.t.Logf("migration Exec failed: %v", err)
	}
	return err
}
func (tx *mountedReadinessTransaction) QueryRow(ctx context.Context, sql string, args ...any) migrations.Row {
	return &mountedReadinessRow{Row: tx.migrationTransaction.QueryRow(ctx, sql, args...), tx: tx, ctx: ctx, sql: sql}
}

type mountedReadinessRow struct {
	migrations.Row
	tx  *mountedReadinessTransaction
	ctx context.Context
	sql string
}

func (r *mountedReadinessRow) Scan(values ...any) error {
	err := r.Row.Scan(values...)
	if err != nil {
		r.tx.t.Logf("migration QueryRow %s failed: %v", r.sql, err)
	}
	if strings.Contains(r.sql, "SELECT zasp_execution_readiness(") {
		var live, expected string
		var security, reference bool
		diagnosticErr := r.tx.transaction.QueryRow(r.ctx, "SELECT zasp_execution_live_fingerprint(),(SELECT value FROM zasp_schema_metadata WHERE key='production_discovery_execution_fingerprint'),zasp_execution_security_ready(),zasp_reference_authorization_security_ready()").Scan(&live, &expected, &security, &reference)
		r.tx.t.Logf("release13 live=%s expected=%s security=%t reference=%t diagnostic=%v", live, expected, security, reference, diagnosticErr)
		var source string
		if err := r.tx.transaction.QueryRow(r.ctx, "SELECT prosrc FROM pg_proc WHERE oid='public.zasp_execution_live_fingerprint()'::regprocedure").Scan(&source); err != nil {
			return err
		}
		cSorted := strings.NewReplacer("ORDER BY kind,identity,definition", `ORDER BY kind COLLATE "C",identity COLLATE "C",definition`, "END,acl.privilege_type,acl.is_grantable,grantor.rolname)", `END COLLATE "C",acl.privilege_type COLLATE "C",acl.is_grantable,grantor.rolname COLLATE "C")`, "ORDER BY role.rolname)", `ORDER BY role.rolname COLLATE "C")`).Replace(source)
		for name, query := range map[string]string{"C-sort-only": cSorted, "without-PG18-notnull-only": strings.ReplaceAll(source, "FROM pg_constraint constraint_value", "FROM (SELECT * FROM pg_constraint WHERE contype<>'n') constraint_value")} {
			var value string
			err := r.tx.transaction.QueryRow(r.ctx, query).Scan(&value)
			r.tx.t.Logf("release13 diagnostic variant %s fingerprint=%s error=%v", name, value, err)
		}
	}
	return err
}
