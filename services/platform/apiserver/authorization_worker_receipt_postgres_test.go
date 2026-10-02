package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func assertWorkerCompletedReceiptNative(t *testing.T, ctx context.Context, owner *pgx.Conn, pool *pgxpool.Pool, child string) {
	t.Helper()
	var q json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'parent_run_id',x.run_id,'test_run_id',j.test_run_id,'step_id',x.step_id,'effect_key',j.effect_key,'generation',1,'category',j.category,'input_digest',encode(j.input_digest,'hex'),'request_digest',encode(j.request_digest,'hex')) FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id) WHERE j.test_run_id=$1`, child).Scan(&q); err != nil {
		t.Fatal("native receipt request", err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	assertWorkerAdapterProofBindings(t, ctx, conn.Conn(), q, authorization.Revision{}, true, true)
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "parent_run_id", "test_run_id", "step_id", "effect_key", "generation", "category", "input_digest", "request_digest"} {
		var m map[string]any
		_ = json.Unmarshal(q, &m)
		switch field {
		case "generation":
			m[field] = 2
		case "category":
			m[field] = "unknown"
		case "effect_key", "input_digest", "request_digest":
			m[field] = strings.Repeat("0", 64)
		default:
			m[field] = "pid_7d000099-0000-4000-8000-000000000099"
		}
		bad, _ := json.Marshal(m)
		var raw json.RawMessage
		err := conn.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_receipt_source('receipt',$1::jsonb)`, bad).Scan(&raw)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "22023" && native.Code != "42501" && native.Code != "40001" {
			t.Fatal("receipt source mismatch not refused", field, err)
		}
	}
	assertWorkerReceiptCatalogNative(t, ctx, owner)
	t.Log("completed receipt native positive control, proof/isolation, exact source and private catalog mutations")
}

func assertWorkerReceiptCatalogNative(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	for _, statement := range []string{
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_receipt_parent(o text,w text,e text,r text,c text,k text) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_receipt_parent(text,text,text,text,text,text) TO zasp_temporal_compensation`,
		`ALTER FUNCTION zasp_authorization80_worker.test74_receipt_parent(text,text,text,text,text,text) OWNER TO zasp_temporal_executor`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_receipt_read(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_receipt_request(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_receipt_source(phase text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.require_test74_receipt(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$BEGIN RETURN '{}'::jsonb;END$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_receipt(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_receipt_read(jsonb) TO zasp_temporal_compensation`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_receipt_request(jsonb) TO zasp_red_team_adapter`,
		`ALTER FUNCTION zasp_authorization80_worker.test74_receipt_read(jsonb) OWNER TO zasp_temporal_executor`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready()`).Scan(&refused)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil || !refused {
			t.Fatal("receipt catalog drift accepted", statement, err)
		}
	}
	t.Log("private completed-receipt catalog rejects body, owner and grant drift")
}
