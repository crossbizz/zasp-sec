package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentExistingTestScopeDiscoveryPostgres(t *testing.T) {
	t.Setenv("ZASP_RECONCILE_SCOPE_DISCOVERY", "true")
	TestSecurityAgentExistingTestReconcileLeasePostgres(t)
}

// Catches missing discovery, leaked payload fields, cursor wraparound, invalid
// authority, and selection of deferred, live-leased or settled work.
func assertExistingTestScopeDiscovery(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, o, w, e, run, step string) {
	t.Helper()
	const query = `SELECT zasp_production_security_agent_existing_tests_reconcile_scopes($1,$2,$3,$4,$5,$6)`
	args := []any{"", "", "", "existing-test-reconciler", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
	var raw json.RawMessage
	expect := func(values []any, want bool) {
		t.Helper()
		if err := worker.QueryRow(ctx, query, values...).Scan(&raw); err != nil {
			t.Fatalf("guarded scope discovery unavailable: %v", err)
		}
		var scopes []map[string]string
		if err := json.Unmarshal(raw, &scopes); err != nil || scopes == nil {
			t.Fatalf("scope array=%s: %v", raw, err)
		}
		if !want {
			if len(scopes) != 0 {
				t.Fatalf("ineligible scope returned: %s", raw)
			}
			return
		}
		if len(scopes) != 1 || len(scopes[0]) != 3 || scopes[0]["organization_id"] != o || scopes[0]["workspace_id"] != w || scopes[0]["environment_id"] != e {
			t.Fatalf("scope identity or projection differs: %s", raw)
		}
	}
	deny := func(conn *pgx.Conn, values []any, code string) {
		t.Helper()
		err := conn.QueryRow(ctx, query, values...).Scan(&raw)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("scope refusal want %s: %v", code, err)
		}
	}
	if _, err := worker.Exec(ctx, `BEGIN READ ONLY`); err != nil {
		t.Fatal(err)
	}
	func() {
		defer worker.Exec(context.Background(), `ROLLBACK`)
		expect(args, true)
	}()
	var private bool
	if err := owner.QueryRow(ctx, `SELECT has_function_privilege('zasp_security_agent_worker','public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('public','public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)','EXECUTE')
 AND NOT has_function_privilege('zasp_security_agent_api','public.zasp_production_security_agent_existing_tests_reconcile_scopes(text,text,text,text,text,text)','EXECUTE')
 AND NOT has_table_privilege('security_agent_v33_worker_login','public.zasp_security_agent_test_links','SELECT')
 AND NOT has_table_privilege('security_agent_v33_worker_login','public.zasp_security_agent_org_admissions','SELECT')`).Scan(&private); err != nil || !private {
		t.Fatalf("scope discovery broadens grants: %t %v", private, err)
	}
	deny(owner, args, "42501")
	config := owner.Config().Copy()
	config.User = "security_agent_v33_api_login"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	deny(api, args, "42501")
	if _, err := owner.Exec(ctx, `CREATE ROLE scope_discovery_unregistered LOGIN INHERIT; GRANT zasp_security_agent_worker TO scope_discovery_unregistered`); err != nil {
		t.Fatal(err)
	}
	config.User = "scope_discovery_unregistered"
	unregistered, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		unregistered.Close(context.Background())
		if _, err := owner.Exec(ctx, `DROP ROLE scope_discovery_unregistered`); err != nil {
			t.Errorf("restore scope fixture principal: %v", err)
		}
	}()
	deny(unregistered, args, "42501")
	if _, err := owner.Exec(ctx, `GRANT zasp_security_agent_api TO security_agent_v33_worker_login`); err != nil {
		t.Fatal(err)
	}
	deny(worker, args, "42501")
	if _, err := owner.Exec(ctx, `REVOKE zasp_security_agent_api FROM security_agent_v33_worker_login`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `REVOKE zasp_security_agent_worker FROM scope_discovery_unregistered`); err != nil {
		t.Fatal(err)
	}
	for _, cursor := range [][]any{
		{o, "", ""}, {"", w, e}, {o, w, ""}, {nil, nil, nil},
		{strings.ToUpper(o), w, e}, {"not-a-product-id", w, e},
		{o, o, e}, {o, w, o}, {o, w, w},
	} {
		bad := append(append([]any(nil), cursor...), args[3:]...)
		deny(worker, bad, "22023")
	}
	for _, value := range []any{"", "UPPER", "ab", "bad worker", strings.Repeat("a", 129), nil} {
		bad := append([]any(nil), args...)
		bad[3] = value
		deny(worker, bad, "22023")
	}
	for _, index := range []int{4, 5} {
		for _, value := range []any{"wrong", nil} {
			bad := append([]any(nil), args...)
			bad[index] = value
			deny(worker, bad, "55000")
		}
	}
	assertExistingTestScopeAuthorityAfterWait(t, ctx, owner, worker, query, args, false)
	assertExistingTestScopeAuthorityAfterWait(t, ctx, owner, worker, query, args, true)
	expect(append([]any{o, w, e}, args[3:]...), false)
	expect(append([]any{"pid_ffffffff-0000-4000-8000-000000000001", "pid_ffffffff-0000-4000-8000-000000000002", "pid_ffffffff-0000-4000-8000-000000000003"}, args[3:]...), false)
	expect(append([]any{"pid_00000001-0000-4000-8000-000000000001", "pid_00000001-0000-4000-8000-000000000002", "pid_00000001-0000-4000-8000-000000000003"}, args[3:]...), true)
	expect(append([]any{o, "pid_00000001-0000-4000-8000-000000000002", e}, args[3:]...), true)
	expect(append([]any{o, w, "pid_00000001-0000-4000-8000-000000000003"}, args[3:]...), true)
	expect(append([]any{o, "pid_ffffffff-0000-4000-8000-000000000002", e}, args[3:]...), false)
	expect(append([]any{o, w, "pid_ffffffff-0000-4000-8000-000000000003"}, args[3:]...), false)
	const where = ` WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=($1,$2,$3,$4,$5)`
	ids := []any{o, w, e, run, step}
	var next time.Time
	var before, after string
	if err := owner.QueryRow(ctx, `SELECT reconcile_next_at,to_jsonb(l)::text FROM zasp_security_agent_test_links l`+where, ids...).Scan(&next, &before); err != nil {
		t.Fatal(err)
	}
	update := func(set string, values ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET `+set+where, append(append([]any(nil), ids...), values...)...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		update(`reconcile_state='pending',reconcile_worker=NULL,reconcile_token=NULL,reconcile_expires_at=NULL,reconcile_next_at=$6`, next)
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(l)::text FROM zasp_security_agent_test_links l`+where, ids...).Scan(&after); err != nil || before != after {
			t.Errorf("scope test did not restore exact link: %v", err)
		}
	}()
	update(`reconcile_next_at=clock_timestamp()+interval '1 hour'`)
	expect(args, false)
	update(`reconcile_state='leased',reconcile_worker='scope-fixture',reconcile_token=decode(repeat('ab',32),'hex'),reconcile_expires_at=clock_timestamp()+interval '1 hour'`)
	expect(args, false)
	update(`reconcile_expires_at=clock_timestamp()-interval '1 second'`)
	expect(args, true)
	if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_org_admissions WHERE organization_id=$1`, o); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES($1)`, o); err != nil {
				t.Fatal(err)
			}
		}()
		expect(args, false)
	}()
	expect(args, true)
	update(`reconcile_state='settled',reconcile_worker=NULL,reconcile_token=NULL,reconcile_expires_at=NULL`)
	expect(args, false)
}

// A worker that passed admission must not receive a scope after authority
// changes while its SELECT waits for the owned table lock.
func assertExistingTestScopeAuthorityAfterWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, query string, args []any, principal bool) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `LOCK TABLE zasp_security_agent_test_links IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	joined := false
	go func() { var raw json.RawMessage; done <- worker.QueryRow(callCtx, query, args...).Scan(&raw) }()
	defer func() {
		if !joined {
			cancel()
			_ = tx.Rollback(context.Background())
			<-done
		}
	}()
	observed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, worker.PgConn().PID()).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("scope SELECT did not reach controlled lock wait")
	}
	mutation := `UPDATE zasp_schema_metadata SET value='scope-discovery-drift' WHERE key='production_security_agent_existing_tests_checksum'`
	if principal {
		mutation = `ALTER ROLE security_agent_v33_worker_login NOLOGIN`
	}
	if _, err := tx.Exec(ctx, mutation); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	callErr := <-done
	joined = true
	code := "55000"
	if principal {
		code = "42501"
		_, err = owner.Exec(ctx, `ALTER ROLE security_agent_v33_worker_login LOGIN`)
	} else {
		_, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_existing_tests_checksum'`, migrations.ProductionSecurityAgentExistingTests().Checksum())
	}
	if err != nil {
		t.Fatal(err)
	}
	var pg *pgconn.PgError
	if !errors.As(callErr, &pg) || pg.Code != code {
		t.Fatalf("scope authority drift after wait want %s: %v", code, callErr)
	}
}
