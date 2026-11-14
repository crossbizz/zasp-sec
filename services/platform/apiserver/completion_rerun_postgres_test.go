package apiserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// completion.sql is re-runnable: the baseline build applies it again to a
// kept installation, in one transaction, as a superuser. This applies the
// WHOLE file, in file order, to the installed released baseline, and then a
// second time. The second run must succeed and must change no function, no
// constraint and no identity rule. The seal of the baseline is then
// refreshed, the way a rebuilt baseline is sealed with the sections, and the
// installation must be intact.
func TestCompletionRunsTwiceOnTheInstalledBaselinePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	connection := installedBaselineConnection(t, ctx)
	completion, err := os.ReadFile(filepath.Join("..", "migrations", "baseline", "completion.sql"))
	if err != nil {
		t.Fatal(err)
	}
	state := func() string {
		t.Helper()
		var functions, constraints, rules, metadata string
		if err := connection.QueryRow(ctx, `SELECT
 (SELECT md5(string_agg(pg_get_functiondef(p.oid),'' ORDER BY p.oid::regprocedure::text)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind='f' AND (n.nspname LIKE 'zasp%' OR n.nspname='public')),
 (SELECT md5(string_agg(c.conrelid::regclass::text||c.conname||pg_get_constraintdef(c.oid),'' ORDER BY c.conrelid::regclass::text,c.conname)) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname LIKE 'zasp%' OR n.nspname='public'),
 (SELECT md5(string_agg(rule::text,'' ORDER BY provider,source_kind)) FROM zasp_inventory_identity_rules rule),
 (SELECT md5(string_agg(key||'='||value,'' ORDER BY key)) FROM zasp_schema_metadata)`).Scan(&functions, &constraints, &rules, &metadata); err != nil {
			t.Fatal(err)
		}
		return functions + constraints + rules + metadata
	}
	run := func(pass string) {
		t.Helper()
		transaction, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback(context.Background())
		if _, err := transaction.Exec(ctx, string(completion), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatalf("%s run of completion.sql: %v", pass, err)
		}
		if err := transaction.Commit(ctx); err != nil {
			t.Fatalf("%s run of completion.sql: commit: %v", pass, err)
		}
	}
	run("first")
	first := state()
	run("second")
	if state() != first {
		t.Fatal("the second run of completion.sql changed a function, a constraint, an identity rule or the schema metadata")
	}
	run("third")
	if state() != first {
		t.Fatal("the third run of completion.sql changed the installation")
	}
	var rules int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_inventory_identity_rules`).Scan(&rules); err != nil || rules != 69 {
		t.Fatalf("identity rules after the completion = %d (%v)", rules, err)
	}
	// A section applied to an installed database breaks the seal by design;
	// it is refreshed as a rebuilt baseline is sealed.
	if _, err := connection.Exec(ctx, `UPDATE zasp_baseline.seal SET content=zasp_baseline.content(),marker=zasp_baseline.marker()`); err != nil {
		t.Fatal(err)
	}
	var intact bool
	if err := connection.QueryRow(ctx, `SELECT zasp_baseline.intact()`).Scan(&intact); err != nil || !intact {
		t.Fatalf("the installation is not intact after the completion ran twice: intact=%t err=%v", intact, err)
	}
}
