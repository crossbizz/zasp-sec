package baseline

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSplitStatements(t *testing.T) {
	script := "-- header; not a statement\n" +
		"SELECT ';' AS a, 'it''s; fine' AS b;\n" +
		"CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $body$ SELECT 'x;y'; -- $$ inside\n $body$;\n" +
		"/* block; /* nested; */ still */ SELECT \"odd;name\" FROM t;\n" +
		"DO $$ BEGIN PERFORM 1; END $$;\n" +
		"SELECT E'back\\'slash; quoted', $1 ;\n" +
		"  -- trailing comment only\n ;\n" +
		"SELECT 2"
	got, err := SplitStatements(script)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-- header; not a statement\nSELECT ';' AS a, 'it''s; fine' AS b",
		"CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $body$ SELECT 'x;y'; -- $$ inside\n $body$",
		"/* block; /* nested; */ still */ SELECT \"odd;name\" FROM t",
		"DO $$ BEGIN PERFORM 1; END $$",
		"SELECT E'back\\'slash; quoted', $1",
		"SELECT 2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %d statements:\n%q", len(got), got)
	}
	for _, broken := range []string{"SELECT 'open", "SELECT $a$ open", "/* open", `SELECT "open`} {
		if _, err := SplitStatements(broken); err == nil {
			t.Fatalf("unterminated input accepted: %q", broken)
		}
	}
}

func TestScriptEndsWithVerification(t *testing.T) {
	statements, err := Script(nil, "zasp_authorization80.ready('"+strings.Repeat("a", 64)+"')")
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) < 1000 {
		t.Fatalf("only %d statements", len(statements))
	}
	last := statements[len(statements)-1]
	if !strings.HasPrefix(last, "DO $verify$") || !strings.Contains(last, "zasp_baseline.seal('"+Checksum()+"')") || !strings.Contains(last, "RAISE EXCEPTION") {
		t.Fatalf("last statement does not verify: %s", last)
	}
	for _, statement := range statements {
		if strings.HasPrefix(statement, "BEGIN") && len(statement) < 8 || statement == "COMMIT" || statement == "ROLLBACK" {
			t.Fatalf("script controls its own transaction: %q", statement)
		}
	}
	if _, err := Script(nil, "true; DROP SCHEMA public"); err == nil {
		t.Fatal("a check with a statement separator was accepted")
	}
	skipped, err := Script([]string{"zasp_discovery_authority"})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range skipped {
		if statement == "CREATE ROLE zasp_discovery_authority" {
			t.Fatal("an existing role is created again")
		}
	}
}

// TestScriptInstallsStatementByStatement needs ZASP_BASELINE_SCRIPT_TEST_DSN:
// the same kind of database as ZASP_BASELINE_TEST_DSN. Each statement is sent
// on its own through the extended protocol, as an HTTPS SQL endpoint does.
func TestScriptInstallsStatementByStatement(t *testing.T) {
	dsn := os.Getenv("ZASP_BASELINE_SCRIPT_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BASELINE_SCRIPT_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var existing []string
	rows, err := conn.Query(ctx, `SELECT rolname::text FROM pg_roles WHERE rolname LIKE 'zasp\_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		existing = append(existing, name)
	}
	rows.Close()
	statements, err := Script(existing)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for index, statement := range statements {
		if _, err := tx.Exec(ctx, statement, pgx.QueryExecModeExec); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("statement %d failed: %v\n%.300s", index, err, statement)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := Verify(ctx, conn)
	if err != nil || !state.Sealed || !state.Intact || !state.Current {
		t.Fatalf("verify: %+v %v", state, err)
	}
}
