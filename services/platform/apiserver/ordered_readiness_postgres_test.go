package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// One owned installed group. The direct API call comes first so an ancestry or
// ACL failure cannot be misreported as another adapter-routing failure.
func TestP7OrderedReadinessPostgres(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, agent *pgx.Conn, _, _, _, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Minute)
		defer cancel()
		runner, err := migrations.NewRunner(&auditProfileMigrationDB{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}})
		if err != nil {
			t.Fatal(err)
		}
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, query, args...); err != nil {
				t.Fatal(err)
			}
		}
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		exec(`CREATE ROLE ready_scheduler LOGIN INHERIT; CREATE ROLE ready_risk LOGIN INHERIT; CREATE ROLE ready_graph LOGIN INHERIT; CREATE ROLE ready_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'ready_scheduler','security_agent_v33_discovery_worker_login','ready_risk','ready_graph','ready_search')`)
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalAuditProfile} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var installed bool
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.ready($1) AND zasp_authorization80_temporal.catalog_ready() AND zasp_authorization80_audit.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='source52-canonical61-audit-v1')`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&installed); err != nil || !installed {
			t.Fatalf("guarded composed fixture=%t %v", installed, err)
		}
		var actualPrincipal bool
		if err := agent.QueryRow(ctx, `SELECT session_user=current_user AND session_user='security_agent_v33_api_login' AND NOT rolsuper AND NOT rolbypassrls AND public.zasp_security_agent_principal_ready('zasp_security_agent_api') FROM pg_roles WHERE rolname=session_user`).Scan(&actualPrincipal); err != nil || !actualPrincipal {
			t.Fatalf("registered API principal=%t %v", actualPrincipal, err)
		}
		t.Log("guarded composed80 ready; registered security_agent_v33_api_login nonsuper/nobypass confirmed")
		effects := func() string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM public.zasp_security_agent_runs),(SELECT count(*) FROM public.zasp_security_agent_request_receipts),(SELECT count(*) FROM zasp_temporal68.effects),(SELECT count(*) FROM public.zasp_admin_audit))::text`).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := effects()
		defer func() {
			if after := effects(); after != before {
				t.Errorf("readiness created product effects/receipts: before=%s after=%s", before, after)
			} else {
				t.Logf("product runs/request receipts/executor effects/admin audit unchanged=%s", after)
			}
		}()
		direct := func(conn *pgx.Conn, c, f string) ([]byte, error) {
			var raw []byte
			err := conn.QueryRow(ctx, securityAgentPublicSQL, c, f, json.RawMessage(`{"operation":"deployment_ready"}`)).Scan(&raw)
			return raw, err
		}
		c, f := migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()
		raw, err := direct(agent, c, f)
		if err != nil || !equalIntegrationJSON(raw, []byte(`{"contract_version":62,"ready":true}`)) {
			t.Logf("direct registered public62 failed: %v response=%s", err, raw)
			orderedReadinessAncestry(t, ctx, owner)
			t.Fatal("direct installed positive failed before typed adapter; do not amend SQL or repin")
		}
		t.Log("direct registered public62 deployment_ready accepted exact compiled62 pins")
		db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: agent})
		if err := db.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		positive := func() {
			t.Helper()
			if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != nil {
				t.Fatal("typed installed positive", err)
			}
		}
		positive()
		core := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "security_agent_v33_discovery_api_login")
		defer core.Close(context.Background())
		coreDB, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: core})
		if err := coreDB.RequireCurrentAuthorization(); err != nil {
			t.Fatal(err)
		}
		t.Run("wrong discovery principal", func(t *testing.T) {
			if _, err := direct(core, c, f); err == nil {
				t.Fatal("wrong direct principal admitted")
			}
			if err := coreDB.VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
				t.Fatal("wrong typed principal admitted", err)
			}
		})
		t.Run("wrong public62 pins", func(t *testing.T) {
			for _, pins := range [][2]string{{strings.Repeat("0", 64), f}, {c, strings.Repeat("0", 64)}} {
				if _, err := direct(agent, pins[0], pins[1]); err == nil {
					t.Fatal("wrong compiled62 pin admitted")
				}
			}
		})
		t.Run("generic SQL denied", func(t *testing.T) {
			if _, err := db.QueryJSON(ctx, securityAgentPublicSQL, c, f, json.RawMessage(`{"operation":"deployment_ready"}`)); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatal("readiness granted product SQL", err)
			}
		})
		positive()
		definition := func(signature string) string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		apiDefinition := definition("zasp_ordered_public62.api(text,text,jsonb)")
		readyDefinition := definition("zasp_ordered_public62.ready(text,text)")
		allowAPI := `CREATE OR REPLACE FUNCTION zasp_ordered_public62.api(c text,f text,q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT ''{"contract_version":62,"ready":true}''::jsonb'`
		allowReady := `CREATE OR REPLACE FUNCTION zasp_ordered_public62.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT true'`
		cases := []struct{ name, change, restore string }{
			{"public62 absent", `ALTER SCHEMA zasp_ordered_public62 RENAME TO readiness_hidden62`, `ALTER SCHEMA readiness_hidden62 RENAME TO zasp_ordered_public62`},
			{"current80 absent", `ALTER SCHEMA zasp_authorization80 RENAME TO readiness_hidden80`, `ALTER SCHEMA readiness_hidden80 RENAME TO zasp_authorization80`},
			{"registration absent", `DELETE FROM zasp_ordered_public62.registration`, `INSERT INTO zasp_ordered_public62.registration VALUES(true,'` + c + `','` + f + `')`},
			{"registration drift", `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`, `UPDATE zasp_ordered_public62.registration SET checksum='` + c + `'`},
			{"API ACL drift", `REVOKE EXECUTE ON FUNCTION zasp_ordered_public62.api(text,text,jsonb) FROM zasp_security_agent_api`, `GRANT EXECUTE ON FUNCTION zasp_ordered_public62.api(text,text,jsonb) TO zasp_security_agent_api`},
			{"allow-valued API", allowAPI, apiDefinition},
			{"allow-valued ready", allowReady, readyDefinition},
			{"allow-valued API and ready", allowAPI + `;` + allowReady, apiDefinition + `;` + readyDefinition},
			{"executor68 catalog drift", `ALTER FUNCTION zasp_temporal68.current_ready() COST 101`, `ALTER FUNCTION zasp_temporal68.current_ready() COST 100`},
			{"profile catalog drift", `ALTER FUNCTION zasp_authorization80_temporal.catalog_ready() COST 101`, `ALTER FUNCTION zasp_authorization80_temporal.catalog_ready() COST 100`},
			{"audit catalog drift", `ALTER TABLE public.zasp_admin_audit DISABLE TRIGGER zasp_authorization80_audit_write_guard`, `ALTER TABLE public.zasp_admin_audit ENABLE TRIGGER zasp_authorization80_audit_write_guard`},
		}
		for _, test := range cases {
			if !t.Run(test.name, func(t *testing.T) {
				exec(test.change)
				defer exec(test.restore)
				if err := db.VerifySecurityAgentOrderedHTTPRelease(ctx); err != ErrRepositoryUnavailable {
					t.Fatal("catalog drift admitted", err)
				}
			}) {
				return
			}
			positive()
			t.Logf("restored positive after %s", test.name)
		}
		t.Run("cancellation while schema lock blocked", func(t *testing.T) {
			locked, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer locked.Rollback(context.Background())
			if _, err := locked.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
				t.Fatal(err)
			}
			connection := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "security_agent_v33_api_login")
			defer connection.Close(context.Background())
			blocked, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: connection})
			if err := blocked.RequireCurrentAuthorization(); err != nil {
				t.Fatal(err)
			}
			bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
			defer stop()
			if err := blocked.VerifySecurityAgentOrderedHTTPRelease(bounded); err != ErrRepositoryUnavailable || bounded.Err() != context.DeadlineExceeded {
				t.Fatalf("blocked cancellation=%v context=%v", err, bounded.Err())
			}
		})
		positive()
	}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
}

// Failure-only observations retain the effective chain without changing a pin.
func orderedReadinessAncestry(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	for _, probe := range []struct {
		name, query string
		args        []any
	}{
		{"public62 ready", `SELECT zasp_ordered_public62.ready($1,$2)::text`, []any{migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()}},
		{"domain67 current", `SELECT zasp_temporal67.current_ready()::text`, nil},
		{"executor68 current", `SELECT zasp_temporal68.current_ready()::text`, nil},
		{"executor68 predecessor", `SELECT zasp_temporal68.predecessor_ready($1,$2)::text`, []any{migrations.ProductionTemporalDomain().Checksum(), migrations.TemporalDomainFingerprint()}},
		{"executor68 base", `SELECT zasp_temporal68.base_ready()::text`, nil},
		{"executor68 fingerprint", `SELECT (zasp_temporal68.fingerprint()=$1)::text`, []any{migrations.TemporalExecutorFingerprint()}},
		{"domain67 projected fingerprint", `SELECT (zasp_temporal67.fingerprint()=$1)::text`, []any{migrations.TemporalExecutorDomainFingerprint()}},
		{"profile catalog", `SELECT zasp_authorization80_temporal.catalog_ready()::text`, nil},
		{"audit catalog", `SELECT zasp_authorization80_audit.catalog_ready()::text`, nil},
	} {
		var value string
		err := owner.QueryRow(ctx, probe.query, probe.args...).Scan(&value)
		t.Logf("ancestry %s=%s error=%v", probe.name, value, err)
	}
}
