package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestP7OrderedTestInstalledCatalog(t *testing.T) {
	runOrdered68PolicyBoundary(t, true, false, false)
}

func assertOrderedTestInstalledCatalog(t *testing.T, ctx context.Context, owner, executor *pgx.Conn) {
	t.Helper()
	private := []string{"ordered68_progress_facts(jsonb)", "ordered68_adapter_facts(boolean,jsonb)", "require_ordered68_test(text,jsonb)", "ordered68_test_exit(text,jsonb)", "ordered68_linked_start(jsonb)", "ordered68_progress_native(jsonb)", "ordered68_linked_native(jsonb)", "ordered68_invocation_native(jsonb)", "ordered68_completion_native(jsonb)", "ordered68_test_settle_native(jsonb)", "ordered68_test_stop_native(jsonb)"}
	for _, signature := range private {
		var sealed bool
		if err := owner.QueryRow(ctx, `SELECT p.proowner='zasp_discovery_authority'::regrole AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}' AND NOT has_function_privilege('zasp_temporal_executor',p.oid,'EXECUTE') AND NOT has_function_privilege('zasp_temporal_compensation',p.oid,'EXECUTE') AND NOT has_function_privilege('zasp_red_team_adapter',p.oid,'EXECUTE') FROM pg_proc p WHERE p.oid=$1::regprocedure`, "zasp_authorization80_worker."+signature).Scan(&sealed); err != nil || !sealed {
			t.Fatal("downstream private ACL/owner", signature, err)
		}
	}
	var readbackACL bool
	if err := owner.QueryRow(ctx, `SELECT p.proowner='zasp_discovery_authority'::regrole AND has_function_privilege('zasp_temporal_executor',p.oid,'EXECUTE') AND NOT has_function_privilege('zasp_temporal_compensation',p.oid,'EXECUTE') AND NOT has_function_privilege('zasp_red_team_adapter',p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p WHERE p.oid='zasp_authorization80_worker.ordered68_dispatch_readback(jsonb)'::regprocedure`).Scan(&readbackACL); err != nil || !readbackACL {
		t.Fatal("dispatch readback ACL/owner", err)
	}
	for _, statement := range []string{
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(jsonb) TO zasp_temporal_compensation`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(jsonb) TO PUBLIC`,
		`ALTER FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(jsonb) OWNER TO zasp_temporal_executor`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.ordered68_dispatch_readback(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_completion_native(jsonb) TO zasp_temporal_compensation`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_progress_facts(jsonb) TO zasp_temporal_executor`,
		`ALTER FUNCTION zasp_authorization80_worker.ordered68_linked_native(jsonb) OWNER TO zasp_temporal_executor`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.ordered68_completion_native(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.ordered68_progress_facts(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_temporal68.linked(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_temporal68.test_settle(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered68_test_complete(jsonb) TO zasp_red_team_adapter`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("downstream catalog mutation", err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready()`).Scan(&refused)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollbackErr := tx.Rollback(cleanup)
		cancel()
		if err != nil || rollbackErr != nil || !refused {
			t.Fatal("downstream catalog drift accepted", err, rollbackErr)
		}
	}
	compConfig := owner.Config().Copy()
	compConfig.User = "temporal_compensation_test_login"
	compensation, err := pgx.ConnectConfig(ctx, compConfig)
	if err != nil {
		t.Fatal("registered compensation connection", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = compensation.Close(cleanup)
	}()
	for _, entry := range []struct {
		statement  string
		connection *pgx.Conn
	}{
		{`SELECT zasp_authorization80_worker.ordered68_dispatch_readback($1::jsonb)`, executor},
		{`SELECT zasp_temporal68.progress($1::jsonb)`, executor},
		{`SELECT zasp_temporal68.linked($1::jsonb)`, executor},
		{`SELECT zasp_temporal68.test_settle($1::jsonb)`, executor},
		{`SELECT zasp_temporal68.test_stop($1::jsonb)`, compensation},
		{`SELECT zasp_authorization80_worker.ordered68_test_complete($1::jsonb)`, compensation},
		{`SELECT zasp_authorization80_worker.ordered68_test_replay($1::jsonb)`, compensation},
		{`SELECT zasp_authorization80_worker.ordered68_test_state($1::jsonb)`, compensation},
	} {
		var raw json.RawMessage
		err := entry.connection.QueryRow(ctx, entry.statement, json.RawMessage(`{"operation":"read"}`)).Scan(&raw)
		var native *pgconn.PgError
		// The fixed entries reach the signed proof fence and reject the missing
		// envelope before exposing or mutating native Test state.
		if !errors.As(err, &native) || native.Code != "42501" {
			t.Fatal("unsigned downstream entry admitted", entry.statement, err)
		}
	}
	var closed bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND NOT zasp_authorization80_worker.runtime_ready()`).Scan(&closed); err != nil || !closed {
		t.Fatal("downstream catalog not restored", err)
	}
}
