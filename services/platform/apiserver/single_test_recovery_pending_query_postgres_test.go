package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func singleRecoveryPendingFunctionSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../migrations/sql/0080_temporal_single_recovery.delivery.sql")
	if err != nil {
		t.Fatal(err)
	}
	const signature = "CREATE FUNCTION zasp_temporal_single_recovery.pending()"
	start := strings.Index(string(raw), signature)
	if start < 0 {
		t.Fatal("pending function absent")
	}
	end := strings.Index(string(raw[start:]), "$body$;")
	if end < 0 {
		t.Fatal("pending function terminator absent")
	}
	return string(raw[start : start+end+len("$body$;")])
}

func singleRecoveryPendingSQLState(err error) string {
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) {
		return "other"
	}
	switch postgres.Code {
	case "42702", "P0001":
		return postgres.Code
	default:
		return "other"
	}
}

func TestSingleRecoveryPendingActualBodyPostgres(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned PostgreSQL connection")
	}
	defer connection.Close(context.Background())

	setup := `
CREATE SCHEMA zasp_temporal_single_recovery;
CREATE TABLE zasp_temporal_single_recovery.commands(
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, command_id text NOT NULL, command jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,command_id));
CREATE TABLE zasp_temporal_single_recovery.deliveries(
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, command_id text NOT NULL, accepted_at timestamptz, last_attempt_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,command_id));
CREATE FUNCTION zasp_temporal_single_recovery.require_worker(text) RETURNS void LANGUAGE sql AS $$SELECT$$;
CREATE FUNCTION zasp_temporal_single_recovery.reference(c zasp_temporal_single_recovery.commands) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$SELECT c.command$$;
CREATE FUNCTION zasp_temporal_single_recovery.checked(q jsonb) RETURNS zasp_temporal_single_recovery.commands LANGUAGE plpgsql AS $fixture$
BEGIN
 IF q->>'run_id'='reject' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='fixture checked refusal';END IF;
 RETURN NULL::zasp_temporal_single_recovery.commands;
END $fixture$;`
	if _, err = connection.Exec(ctx, setup+singleRecoveryPendingFunctionSource(t)); err != nil {
		t.Fatal("pending component setup")
	}

	insert := `WITH values(command_id,run_id,accepted) AS (VALUES('cmd-b','run-b',false),('cmd-a','run-a',false),('cmd-c','run-c',true))
INSERT INTO zasp_temporal_single_recovery.commands SELECT 'org','workspace','environment',run_id,command_id,jsonb_build_object('run_id',run_id) FROM values;
WITH values(command_id,run_id,accepted) AS (VALUES('cmd-b','run-b',false),('cmd-a','run-a',false),('cmd-c','run-c',true))
INSERT INTO zasp_temporal_single_recovery.deliveries SELECT 'org','workspace','environment',run_id,command_id,CASE WHEN accepted THEN clock_timestamp() END,NULL FROM values;`
	if _, err = connection.Exec(ctx, insert); err != nil {
		t.Fatal("pending component rows")
	}

	var raw []byte
	if err = connection.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.pending()`).Scan(&raw); err != nil {
		t.Fatalf("pending stage SQLSTATE=%s", singleRecoveryPendingSQLState(err))
	}
	var ordered []map[string]any
	if json.Unmarshal(raw, &ordered) != nil || len(ordered) != 2 || ordered[0]["run_id"] != "run-a" || ordered[1]["run_id"] != "run-b" || strings.Contains(string(raw), "run-c") {
		t.Fatal("pending selection, exclusion, or deterministic order changed")
	}

	if _, err = connection.Exec(ctx, `INSERT INTO zasp_temporal_single_recovery.commands VALUES('org','workspace','environment','reject','cmd-0','{"run_id":"reject"}');INSERT INTO zasp_temporal_single_recovery.deliveries VALUES('org','workspace','environment','reject','cmd-0',NULL,NULL)`); err != nil {
		t.Fatal("validation refusal row")
	}
	if err = connection.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.pending()`).Scan(&raw); singleRecoveryPendingSQLState(err) != "P0001" {
		t.Fatal("pending selected-row validation refusal changed")
	}
	if _, err = connection.Exec(ctx, `TRUNCATE zasp_temporal_single_recovery.commands,zasp_temporal_single_recovery.deliveries`); err != nil {
		t.Fatal("pending bound reset")
	}
	if _, err = connection.Exec(ctx, `INSERT INTO zasp_temporal_single_recovery.commands SELECT 'org','workspace','environment','run-'||lpad(n::text,3,'0'),'cmd-'||lpad(n::text,3,'0'),jsonb_build_object('run_id','run-'||lpad(n::text,3,'0')) FROM generate_series(1,101)n;INSERT INTO zasp_temporal_single_recovery.deliveries SELECT organization_id,workspace_id,environment_id,run_id,command_id,NULL,NULL FROM zasp_temporal_single_recovery.commands`); err != nil {
		t.Fatal("pending row bound fixture")
	}
	if err = connection.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.pending()`).Scan(&raw); err != nil || json.Unmarshal(raw, &ordered) != nil || len(ordered) != 100 || len(raw) > 65536 {
		t.Fatal("pending row or byte bound changed")
	}
	if _, err = connection.Exec(ctx, `TRUNCATE zasp_temporal_single_recovery.commands,zasp_temporal_single_recovery.deliveries;
INSERT INTO zasp_temporal_single_recovery.commands VALUES
 ('org','workspace','environment','run-a','cmd-a',jsonb_build_object('run_id','run-a','padding',repeat('a',40000))),
 ('org','workspace','environment','run-b','cmd-b',jsonb_build_object('run_id','run-b','padding',repeat('b',40000)));
INSERT INTO zasp_temporal_single_recovery.deliveries SELECT organization_id,workspace_id,environment_id,run_id,command_id,NULL,NULL FROM zasp_temporal_single_recovery.commands`); err != nil {
		t.Fatal("pending cumulative byte fixture")
	}
	if err = connection.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.pending()`).Scan(&raw); err != nil || json.Unmarshal(raw, &ordered) != nil || len(ordered) != 1 || ordered[0]["run_id"] != "run-a" || len(raw) > 65536 {
		t.Fatal("pending cumulative byte cutoff changed")
	}
	if _, err = connection.Exec(ctx, `TRUNCATE zasp_temporal_single_recovery.commands,zasp_temporal_single_recovery.deliveries;
INSERT INTO zasp_temporal_single_recovery.commands VALUES('org','workspace','environment','run-a','cmd-a',jsonb_build_object('run_id','run-a','padding',repeat('a',70000)));
INSERT INTO zasp_temporal_single_recovery.deliveries SELECT organization_id,workspace_id,environment_id,run_id,command_id,NULL,NULL FROM zasp_temporal_single_recovery.commands`); err != nil {
		t.Fatal("pending oversized-first fixture")
	}
	if err = connection.QueryRow(ctx, `SELECT zasp_temporal_single_recovery.pending()`).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatal("pending oversized first item was emitted")
	}
}
