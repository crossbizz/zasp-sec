package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const globalControlSetSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_set($1,$2,$3,$4,$5,$6)`
const globalControlReadSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_read($1,$2)`

func globalControlSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('control',(SELECT jsonb_agg(to_jsonb(c) ORDER BY organization_id,workspace_id,environment_id,action_key) FROM zasp_security_agent_kill_switches c),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY request_id) FROM zasp_security_agent_global_control_receipts r),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY organization_id,audit_id) FROM zasp_security_agent_audit a))`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Removing the operator transaction must fail at the real SQL boundary, after
// the complete registered release has passed its compiled readiness checks.
func TestSecurityAgentGlobalControlPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		assertGlobalInheritedValidator(t, ctx, owner)
		var raw json.RawMessage
		if err := owner.QueryRow(ctx, globalControlSetSQL, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint(), false, int64(1), "pid_7f560001-0000-4000-8000-000000000001", "global-stop-test").Scan(&raw); err != nil {
			t.Fatalf("registered operator stop: %v", err)
		}
		if !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":false}`)) {
			t.Fatalf("stop result: %s", raw)
		}
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		stop := append(append([]any(nil), pins...), false, int64(1), "pid_7f560001-0000-4000-8000-000000000001", "global-stop-test")
		refuse := func(conn *pgx.Conn, query, code string, args ...any) {
			t.Helper()
			before := globalControlSnapshot(t, ctx, owner)
			_, err := conn.Exec(ctx, query, args...)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != code {
				t.Fatalf("refusal wanted %s: %v", code, err)
			}
			if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
				t.Fatal("refusal changed control, receipt, or audit authority")
			}
		}
		read := func(want string) {
			t.Helper()
			if err := owner.QueryRow(ctx, globalControlReadSQL, pins...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(want)) {
				t.Fatalf("read=%s err=%v", raw, err)
			}
		}
		read(`{"enabled":false,"version":2,"replayed":false}`)
		beforeReplay := globalControlSnapshot(t, ctx, owner)
		if err := owner.QueryRow(ctx, globalControlSetSQL, stop...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":true}`)) || !equalIntegrationJSON(beforeReplay, globalControlSnapshot(t, ctx, owner)) {
			t.Fatalf("exact replay=%s err=%v", raw, err)
		}
		for _, changed := range []struct {
			index int
			value any
		}{{2, true}, {3, int64(2)}, {5, "different-correlation"}} {
			args := append([]any(nil), stop...)
			args[changed.index] = changed.value
			refuse(owner, globalControlSetSQL, "40001", args...)
		}
		for _, invalid := range []struct {
			index int
			value any
		}{{2, nil}, {3, nil}, {3, int64(0)}, {3, int64(-1)}, {3, int64(9223372036854775807)}, {4, nil}, {4, ""}, {4, "*"}, {4, "pid_7F560001-0000-4000-8000-000000000001"}, {5, nil}, {5, ""}, {5, "has space"}, {5, "line\nbreak"}, {5, "tab\tbreak"}, {5, "nonascii-é"}, {5, strings.Repeat("x", 129)}} {
			args := append([]any(nil), stop...)
			args[invalid.index] = invalid.value
			refuse(owner, globalControlSetSQL, "22023", args...)
		}
		stale := append([]any(nil), stop...)
		stale[4] = "pid_7f560001-0000-4000-8000-000000000002"
		refuse(owner, globalControlSetSQL, "40001", stale...)
		for _, index := range []int{0, 1} {
			args := append([]any(nil), stop...)
			args[index] = "wrong"
			refuse(owner, globalControlSetSQL, "55000", args...)
			args[index] = nil
			refuse(owner, globalControlSetSQL, "55000", args...)
		}
		// Forged GUCs cannot create the effective capability or durable association.
		if _, err := owner.Exec(ctx, `SELECT set_config('zasp.global_operator','true',false),set_config('zasp.global_request_id','pid_7f560001-0000-4000-8000-000000000001',false)`); err != nil {
			t.Fatal(err)
		}
		for _, query := range []string{
			`UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE organization_id='*'`,
			`UPDATE zasp_security_agent_kill_switches SET organization_id='pid_7f560001-0000-4000-8000-000000000003' WHERE organization_id='*'`,
			`DELETE FROM zasp_security_agent_kill_switches WHERE organization_id='*'`,
			`UPDATE zasp_security_agent_audit SET body='{}' WHERE organization_id='*'`,
			`DELETE FROM zasp_security_agent_audit WHERE organization_id='*'`,
			`UPDATE zasp_security_agent_global_control_receipts SET enabled=true`,
			`DELETE FROM zasp_security_agent_global_control_receipts`,
			`INSERT INTO zasp_security_agent_global_control_receipts SELECT 'pid_7f560001-0000-4000-8000-000000000004',caller_session,enabled,expected_version,correlation_id,resulting_version,result,transaction_id,created_at FROM zasp_security_agent_global_control_receipts`,
			`INSERT INTO zasp_security_agent_audit SELECT organization_id,workspace_id,environment_id,'pid_7f560001-0000-4000-8000-000000000005',correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body,created_at FROM zasp_security_agent_audit WHERE organization_id='*'`,
		} {
			refuse(owner, query, "42501")
		}
		for mask := 1; mask < 8; mask++ {
			scope := []string{org, ws, env}
			for n := range scope {
				if mask&(1<<n) != 0 {
					scope[n] = "*"
				}
			}
			for _, action := range []string{"*", "run_test"} {
				refuse(owner, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,updated_by) VALUES($1,$2,$3,$4,'forged')`, "42501", scope[0], scope[1], scope[2], action)
			}
			refuse(owner, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,'pid_7f560001-0000-4000-8000-000000000006','forged','forged','kill_switch_changed',decode(repeat('ab',32),'hex'),'{}')`, "42501", scope[0], scope[1], scope[2])
		}
		// Tenant checks retain the same hold behavior through both new guards.
		tenantCheck := func() {
			t.Helper()
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,updated_by) VALUES($1,$2,$3,'global-test','fixture') ON CONFLICT DO NOTHING`, org, ws, env); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_recovery_holds(organization_id,workspace_id,environment_id,epoch,operation_id,state,held_at) VALUES($1,$2,$3,1,'pid_7f560001-0000-4000-8000-000000000007','held',transaction_timestamp())`, org, ws, env); err != nil {
				t.Fatal(err)
			}
			refuse(owner, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'global-test')`, "55000", org, ws, env)
			refuse(owner, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,'pid_7f560001-0000-4000-8000-000000000008','tenant-check',$4,'kill_switch_changed',decode(repeat('ab',32),'hex'),'{}')`, "55000", org, ws, env, actor)
			if _, err := owner.Exec(ctx, `DELETE FROM zasp_recovery_holds WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3); UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'global-test')`, pgx.QueryExecModeSimpleProtocol, org, ws, env); err != nil {
				t.Fatal(err)
			}
		}
		tenantCheck()
		enable := append(append([]any(nil), pins...), true, int64(2), "pid_7f560001-0000-4000-8000-000000000009", strings.Repeat("~", 128))
		if err := owner.QueryRow(ctx, globalControlSetSQL, enable...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":true,"version":3,"replayed":false}`)) {
			t.Fatalf("re-enable=%s err=%v", raw, err)
		}
		beforeReplay = globalControlSnapshot(t, ctx, owner)
		if err := owner.QueryRow(ctx, globalControlSetSQL, stop...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":true}`)) || !equalIntegrationJSON(beforeReplay, globalControlSnapshot(t, ctx, owner)) {
			t.Fatalf("historical stop replay=%s err=%v", raw, err)
		}
		read(`{"enabled":true,"version":3,"replayed":false}`)
		tenantCheck()
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=2 FROM zasp_security_agent_global_control_receipts) AND (SELECT count(*)=2 FROM zasp_security_agent_audit WHERE organization_id='*') AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_global_control_receipts r LEFT JOIN zasp_security_agent_audit a ON a.organization_id='*' AND a.audit_id=r.request_id WHERE a.audit_id IS NULL OR r.caller_session<>session_user OR a.actor_id<>session_user OR a.body<>zasp_production_security_agent_existing_tests_global_intent(r) OR a.event_digest<>digest(convert_to(a.body::text,'UTF8'),'sha256'))`).Scan(&valid); err != nil || !valid {
			t.Fatalf("durable intent/audit mismatch: %t %v", valid, err)
		}
		beforeDown := globalControlSnapshot(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentExistingTests(ctx); err == nil {
			t.Fatal("used global authority rolled back")
		}
		if !equalIntegrationJSON(beforeDown, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("rollback refusal changed global authority")
		}
		read(`{"enabled":true,"version":3,"replayed":false}`)
		// Every fixture API/worker login must refuse execution and role assumption.
		rows, err := owner.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolname<>session_user ORDER BY rolname`)
		if err != nil {
			t.Fatal(err)
		}
		var logins []string
		for rows.Next() {
			var login string
			if err := rows.Scan(&login); err != nil {
				t.Fatal(err)
			}
			logins = append(logins, login)
		}
		rows.Close()
		if len(logins) < 8 {
			t.Fatalf("fixture principal coverage unexpectedly small: %v", logins)
		}
		for _, login := range logins {
			config := owner.Config().Copy()
			config.User = login
			conn, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			refuse(conn, globalControlReadSQL, "42501", pins...)
			refuse(conn, globalControlSetSQL, "42501", stop...)
			refuse(conn, `SELECT * FROM zasp_security_agent_global_control_receipts`, "42501")
			refuse(conn, `SET ROLE zasp_security_agent_global_operator`, "42501")
			conn.Close(ctx)
		}
		t.Logf("refused %d API/worker login identities", len(logins))
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname LIKE 'zasp_%' AND NOT rolcanlogin AND rolname NOT IN('zasp_discovery_authority','zasp_security_agent_global_operator') AND (has_function_privilege(rolname,'public.zasp_production_security_agent_existing_tests_global_read(text,text)','EXECUTE') OR has_function_privilege(rolname,'public.zasp_production_security_agent_existing_tests_global_set(text,text,boolean,bigint,text,text)','EXECUTE') OR has_table_privilege(rolname,'public.zasp_security_agent_global_control_receipts','SELECT,INSERT,UPDATE,DELETE') OR pg_has_role(rolname,'zasp_security_agent_global_operator','MEMBER'))) AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='zasp_security_agent_global_operator'::regrole OR member='zasp_security_agent_global_operator'::regrole)`).Scan(&valid); err != nil || !valid {
			t.Fatalf("API/worker authority or role membership leaked: %t %v", valid, err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE global_unregistered LOGIN INHERIT; GRANT zasp_discovery_authority TO global_unregistered`); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "global_unregistered"
		unregistered, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		refuse(unregistered, globalControlReadSQL, "42501", pins...)
		refuse(unregistered, globalControlSetSQL, "42501", stop...)
		unregistered.Close(ctx)
		if _, err := owner.Exec(ctx, `DROP ROLE global_unregistered`); err != nil {
			t.Fatal(err)
		}
	})
}

func assertGlobalInheritedValidator(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	var inherited bool
	if err := owner.QueryRow(ctx, `SELECT has_function_privilege('zasp_security_agent_global_operator','public.zasp_valid_product_id(text)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='public.zasp_valid_product_id(text)'::regprocedure AND a.grantee='zasp_security_agent_global_operator'::regrole)`).Scan(&inherited); err != nil || !inherited {
		t.Fatalf("canonical validator execution is not inherited without an installation-specific grant: %t %v", inherited, err)
	}
}

// Each mutation must invalidate exact55 readiness; no new privilege is inferred
// from a role name, a surviving guard function, or a disabled trigger.
func TestSecurityAgentGlobalControlCatalogPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		for index, mutation := range []string{
			`ALTER ROLE zasp_security_agent_global_operator LOGIN`,
			`ALTER ROLE zasp_security_agent_global_operator BYPASSRLS`,
			`GRANT zasp_security_agent_global_operator TO zasp_security_agent_api`,
			`GRANT zasp_security_agent_api TO zasp_security_agent_global_operator`,
			`GRANT SELECT ON zasp_security_agent_global_control_receipts TO zasp_security_agent_api`,
			`GRANT UPDATE ON zasp_security_agent_kill_switches TO zasp_security_agent_global_operator`,
			`ALTER TABLE zasp_security_agent_global_control_receipts NO FORCE ROW LEVEL SECURITY`,
			`DO $drift$ DECLARE name text; BEGIN SELECT conname INTO STRICT name FROM pg_constraint WHERE conrelid='zasp_security_agent_global_control_receipts'::regclass AND contype='c' AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='zasp_security_agent_global_control_receipts'::regclass AND attname='correlation_id')]; EXECUTE format('ALTER TABLE zasp_security_agent_global_control_receipts DROP CONSTRAINT %I',name); END $drift$`,
			`ALTER POLICY global_operator_control_write ON zasp_security_agent_kill_switches USING(true)`,
			`ALTER TABLE zasp_security_agent_kill_switches ENABLE ALWAYS TRIGGER zasp_security_agent_kill_switches_recovery_hold`,
			`ALTER TABLE zasp_security_agent_audit ENABLE ALWAYS TRIGGER zasp_security_agent_audit_recovery_hold`,
			`ALTER TABLE zasp_security_agent_global_control_receipts ENABLE ALWAYS TRIGGER global_receipt_complete`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_global_control_guard() SECURITY DEFINER`,
			`UPDATE zasp_existing_tests_predecessor.global_control_triggers SET definition='corrupt'`,
			`CREATE FUNCTION public.unrelated_global_capability() RETURNS boolean LANGUAGE sql AS 'SELECT true'; ALTER FUNCTION public.unrelated_global_capability() OWNER TO zasp_security_agent_global_operator`,
			`CREATE TABLE public.unrelated_global_owned(id int); ALTER TABLE public.unrelated_global_owned OWNER TO zasp_security_agent_global_operator`,
		} {
			t.Run(fmt.Sprintf("drift_%02d", index), func(t *testing.T) {
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, "ROLLBACK")
				if _, err := owner.Exec(ctx, mutation); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || ready {
					t.Fatalf("catalog drift accepted: %t %v", ready, err)
				}
			})
		}
	})
}

// The disposable database's pgcrypto digest is the fault-injection seam. The
// exact extension definition is restored even on failure. No guard, ACL, pin,
// or release identity is relaxed to make the request reach its audit INSERT.
func TestSecurityAgentGlobalControlAuditFailurePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		var definition, identityBefore string
		const identitySQL = `SELECT concat_ws('|',pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_proc p WHERE p.oid='public.digest(bytea,text)'::regprocedure`
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.digest(bytea,text)'::regprocedure)`).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, identitySQL).Scan(&identityBefore); err != nil {
			t.Fatal(err)
		}
		alias := strings.Replace(definition, "FUNCTION public.digest(", "FUNCTION public.zasp_task1_digest_original(", 1)
		if alias == definition {
			t.Fatal("pgcrypto injection signature absent")
		}
		if _, err := owner.Exec(ctx, alias); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := owner.Exec(context.Background(), definition+`; DROP FUNCTION public.zasp_task1_digest_original(bytea,text)`); err != nil {
				t.Error(err)
			}
			var restored string
			if err := owner.QueryRow(context.Background(), identitySQL).Scan(&restored); err != nil || restored != identityBefore {
				t.Errorf("pgcrypto identity not restored: %v", err)
			}
		}()
		if _, err := owner.Exec(ctx, `CREATE OR REPLACE FUNCTION public.digest(bytea,text) RETURNS bytea LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $fault$
 BEGIN
  IF strpos(encode($1,'escape'),'pid_7f560001-0000-4000-8000-000000000080')>0 THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='owned audit insertion failure',DETAIL=(SELECT 'control='||version||',receipt='||(SELECT count(*) FROM public.zasp_security_agent_global_control_receipts WHERE request_id='pid_7f560001-0000-4000-8000-000000000080') FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*'));
  END IF;
  RETURN public.zasp_task1_digest_original($1,$2);
 END $fault$`); err != nil {
			t.Fatal(err)
		}
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)`, pins...).Scan(&ready); err != nil || !ready {
			t.Fatalf("fault seam altered preflight: %t %v", ready, err)
		}
		before := globalControlSnapshot(t, ctx, owner)
		_, err := owner.Exec(ctx, globalControlSetSQL, append(pins, false, int64(1), "pid_7f560001-0000-4000-8000-000000000080", "audit-insertion-failure")...)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "P0001" || pg.Message != "owned audit insertion failure" || pg.Detail != "control=2,receipt=1" {
			t.Fatalf("fault did not reach audit INSERT after control/receipt writes: %#v", err)
		}
		if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("audit insertion failure retained authority")
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_readiness($1,$2)`, pins...).Scan(&ready); err != nil || !ready {
			t.Fatalf("post-failure readiness changed: %t %v", ready, err)
		}
	})
}

func TestSecurityAgentGlobalControlUnusedRollbackPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const catalogSQL = `SELECT jsonb_build_object('tables',(SELECT jsonb_agg(jsonb_build_object('name',c.relname,'acl',c.relacl::text,'columns',(SELECT jsonb_agg(jsonb_build_object('name',a.attname,'acl',a.attacl::text) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)) ORDER BY c.relname) FROM pg_class c WHERE c.oid IN('zasp_security_agent_kill_switches'::regclass,'zasp_security_agent_audit'::regclass,'zasp_discovery_principal_bindings'::regclass)),'triggers',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_triggerdef(t.oid,true),'enabled',t.tgenabled) ORDER BY t.tgname) FROM pg_trigger t WHERE t.tgrelid IN('zasp_security_agent_kill_switches'::regclass,'zasp_security_agent_audit'::regclass) AND NOT t.tgisinternal))`
		var before, after json.RawMessage
		if err := owner.QueryRow(ctx, catalogSQL).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, catalogSQL).Scan(&after); err != nil || !equalIntegrationJSON(before, after) {
			t.Fatalf("unused rollback did not restore exact ACL/trigger state: %s vs %s %v", before, after, err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_security_agent_global_operator') AND to_regclass('public.zasp_security_agent_global_control_receipts') IS NULL AND to_regnamespace('zasp_existing_tests_predecessor') IS NULL`).Scan(&absent); err != nil || !absent {
			t.Fatalf("unused rollback retained authority: %t %v", absent, err)
		}
	})
}

func TestSecurityAgentGlobalControlDownFenceBeforeReadinessPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		var original string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_production_security_agent_existing_tests_readiness(text,text)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE SEQUENCE public.task1_readiness_witness; ALTER SEQUENCE public.task1_readiness_witness OWNER TO zasp_discovery_authority;
 CREATE OR REPLACE FUNCTION public.zasp_production_security_agent_existing_tests_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $witness$
 BEGIN
  IF (SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND granted AND mode='AccessExclusiveLock' AND relation IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass))<>3 THEN
   RAISE EXCEPTION 'rollback readiness preceded its global relation fences';
  END IF;
  PERFORM nextval('public.task1_readiness_witness');
  RETURN false;
 END $witness$`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := owner.Exec(context.Background(), original+`; DROP SEQUENCE public.task1_readiness_witness`); err != nil {
				t.Error(err)
			}
		}()
		before := globalControlSnapshot(t, ctx, owner)
		// The witness only refuses. It never authorizes a modified release.
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentExistingTests(ctx); !errors.Is(err, migrations.ErrInvalidState) {
			t.Fatalf("readiness must observe all three fences before refusing: %v", err)
		}
		if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("refused fenced rollback changed authority")
		}
	})
}

func TestSecurityAgentGlobalControlNonSuperuserPostgres(t *testing.T) {
	var custodian *pgx.Conn
	start := func(t *testing.T) string {
		dsn := startDisposablePostgresAs(t, "zasp_test")
		setup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var err error
		custodian, err = pgx.Connect(setup, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := custodian.Close(cleanup); err != nil {
				t.Error(err)
			}
		})
		var directory string
		var owned bool
		if err := custodian.QueryRow(setup, `SELECT current_setting('data_directory'),session_user='zasp_test' AND current_user=session_user AND current_database()='postgres' AND (SELECT oid=10 AND rolsuper FROM pg_roles WHERE rolname=session_user)`).Scan(&directory, &owned); err != nil || !owned || custodian.Config().Host != "127.0.0.1" || !strings.HasPrefix(directory, "/tmp/TestSecurityAgentGlobalControlNonSuperuserPostgres") || !strings.HasSuffix(directory, "/data") {
			t.Fatalf("refusing non-owned bootstrap setup: %t %s %v", owned, directory, err)
		}
		if _, err := custodian.Exec(setup, `CREATE ROLE global_operator_migration LOGIN SUPERUSER`); err != nil {
			t.Fatal(err)
		}
		config := custodian.Config().Copy()
		config.User = "global_operator_migration"
		migrationDSN := fmt.Sprintf("postgres://global_operator_migration@127.0.0.1:%d/postgres?sslmode=disable", config.Port)
		probe, err := pgx.Connect(setup, migrationDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close(context.Background())
		if err := probe.QueryRow(setup, `SELECT session_user='global_operator_migration' AND current_user=session_user AND (SELECT oid<>10 AND rolcanlogin FROM pg_roles WHERE rolname=session_user)`).Scan(&owned); err != nil || !owned {
			t.Fatalf("migration DSN does not select the real non-bootstrap login: %t %v", owned, err)
		}
		return migrationDSN
	}
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		var directory, session string
		if err := owner.QueryRow(ctx, `SELECT current_setting('data_directory'),session_user`).Scan(&directory, &session); err != nil {
			t.Fatal(err)
		}
		if session != "global_operator_migration" || config.User != "global_operator_migration" || config.Host != "127.0.0.1" || config.Database != "postgres" || !strings.HasPrefix(directory, "/tmp/TestSecurityAgentGlobalControlNonSuperuserPostgres") || !strings.HasSuffix(directory, "/data") {
			t.Fatalf("refusing maintenance setup outside exact owned fixture: user=%s host=%s database=%s directory=%s", session, config.Host, config.Database, directory)
		}
		const attributesSQL = `SELECT to_jsonb(r) FROM pg_roles r WHERE rolname='global_operator_migration'`
		var attributes, binding json.RawMessage
		var superuser, bypass bool
		if err := owner.QueryRow(ctx, attributesSQL).Scan(&attributes); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='global_operator_migration' AND oid<>10`).Scan(&superuser, &bypass); err != nil || !superuser {
			t.Fatalf("fixture migration login is not separate from bootstrap: %v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(b) FROM zasp_discovery_principal_bindings b WHERE principal_name='global_operator_migration' AND authority_role='zasp_discovery_authority'`).Scan(&binding); err != nil {
			t.Fatal(err)
		}
		var login *pgx.Conn
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if login != nil {
				if err := login.Close(cleanup); err != nil {
					t.Error(err)
				}
			}
			superFlag, bypassFlag := "NOSUPERUSER", "NOBYPASSRLS"
			if superuser {
				superFlag = "SUPERUSER"
			}
			if bypass {
				bypassFlag = "BYPASSRLS"
			}
			if _, err := custodian.Exec(cleanup, `ALTER ROLE global_operator_migration `+superFlag+` `+bypassFlag); err != nil {
				t.Error(err)
				return
			}
			if _, err := custodian.Exec(cleanup, `INSERT INTO zasp_discovery_principal_bindings SELECT * FROM jsonb_populate_record(NULL::zasp_discovery_principal_bindings,$1::jsonb) ON CONFLICT(principal_name) DO UPDATE SET authority_role=excluded.authority_role,registered_at=excluded.registered_at`, binding); err != nil {
				t.Error(err)
				return
			}
			var restoredAttributes, restoredBinding json.RawMessage
			if err := custodian.QueryRow(cleanup, attributesSQL).Scan(&restoredAttributes); err != nil || !equalIntegrationJSON(attributes, restoredAttributes) {
				t.Errorf("migration login attributes not restored: %v", err)
			}
			if err := custodian.QueryRow(cleanup, `SELECT to_jsonb(b) FROM zasp_discovery_principal_bindings b WHERE principal_name='global_operator_migration'`).Scan(&restoredBinding); err != nil || !equalIntegrationJSON(binding, restoredBinding) {
				t.Errorf("registered binding not restored: %v", err)
			}
		}()
		if _, err := custodian.Exec(ctx, `ALTER ROLE global_operator_migration NOSUPERUSER NOBYPASSRLS`); err != nil {
			t.Fatalf("owned migration login demotion: %#v", err)
		}
		var err error
		login, err = pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		var bounded bool
		if err := login.QueryRow(ctx, `SELECT session_user='global_operator_migration' AND current_user=session_user AND NOT r.rolsuper AND NOT r.rolbypassrls AND r.rolcanlogin AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND NOT pg_has_role(session_user,'zasp_security_agent_global_operator','MEMBER') AND EXISTS(SELECT 1 FROM zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') FROM pg_roles r WHERE rolname=session_user`).Scan(&bounded); err != nil || !bounded {
			t.Fatalf("fresh migration login is not bounded/registered: %t %v", bounded, err)
		}
		assertGlobalInheritedValidator(t, ctx, login)
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		var raw json.RawMessage
		if err := login.QueryRow(ctx, globalControlReadSQL, pins...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":true,"version":1,"replayed":false}`)) {
			t.Fatalf("bounded read=%s err=%v", raw, err)
		}
		args := append(append([]any(nil), pins...), false, int64(1), "pid_7f560001-0000-4000-8000-000000000090", "bounded-login-stop")
		if err := login.QueryRow(ctx, globalControlSetSQL, args...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":false}`)) {
			t.Fatalf("bounded committed stop=%s err=%v", raw, err)
		}
		if err := login.QueryRow(ctx, globalControlSetSQL, args...).Scan(&raw); err != nil || !equalIntegrationJSON(raw, json.RawMessage(`{"enabled":false,"version":2,"replayed":true}`)) {
			t.Fatalf("bounded replay=%s err=%v", raw, err)
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_security_agent_global_control_receipts WHERE caller_session='global_operator_migration') AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE organization_id='*' AND actor_id='global_operator_migration') AND (SELECT version=2 AND NOT execution_enabled FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*'))`).Scan(&bounded); err != nil || !bounded {
			t.Fatalf("non-superuser commit lost durable associations: %t %v", bounded, err)
		}
		before := globalControlSnapshot(t, ctx, owner)
		invalidArgs := append([]any(nil), args...)
		invalidArgs[4] = "*"
		if _, err := login.Exec(ctx, globalControlSetSQL, invalidArgs...); err != nil {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "22023" {
				t.Fatalf("bounded malformed ID refusal: %v", err)
			}
		} else {
			t.Fatal("bounded malformed request accepted")
		}
		if _, err := custodian.Exec(ctx, `DELETE FROM zasp_discovery_principal_bindings WHERE principal_name='global_operator_migration' AND authority_role='zasp_discovery_authority'`); err != nil {
			t.Fatal(err)
		}
		for _, call := range []struct {
			query string
			args  []any
		}{{globalControlReadSQL, pins}, {globalControlSetSQL, args}} {
			_, err := login.Exec(ctx, call.query, call.args...)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("revoked real binding accepted: %v", err)
			}
		}
		if !equalIntegrationJSON(before, globalControlSnapshot(t, ctx, owner)) {
			t.Fatal("binding refusal changed control/receipt/audit")
		}
	}, start)
}
