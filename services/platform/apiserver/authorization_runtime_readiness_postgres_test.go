package apiserver

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestP7GuardedRuntimeReadinessPostgres(t *testing.T) {
	for _, profile := range []string{"composed-guarded", "base-guarded", "composed-none"} {
		t.Run(profile, func(t *testing.T) {
			multistepVersionedExistingTestFixture(t, func(parent context.Context, owner, agent *pgx.Conn, _, _, _, _, _ string) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Minute)
				defer cancel()
				db := &auditProfileMigrationDB{policyLineageDatabase: &policyLineageDatabase{connection: owner, t: t}}
				runner, err := migrations.NewRunner(db)
				if err != nil {
					t.Fatal(err)
				}
				for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
					if err := up(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if profile != "base-guarded" {
					if _, err := owner.Exec(ctx, `CREATE ROLE ready_scheduler LOGIN INHERIT; CREATE ROLE ready_risk LOGIN INHERIT; CREATE ROLE ready_graph LOGIN INHERIT; CREATE ROLE ready_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'ready_scheduler','security_agent_v33_discovery_worker_login','ready_risk','ready_graph','ready_search')`); err != nil {
						t.Fatal(err)
					}
					for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse} {
						if err := up(ctx); err != nil {
							t.Fatal(err)
						}
					}
				}
				install := runner.UpProductionAuthorizationTemporalAuditProfile
				if profile == "base-guarded" {
					install = runner.UpProductionAuthorizationAuditProfile
				}
				if profile == "composed-none" {
					install = runner.UpProductionAuthorizationTemporalProfile
				}
				if profile != "composed-none" {
					var original57 string
					if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure)`).Scan(&original57); err != nil {
						t.Fatal(err)
					}
					db.fail = true
					if err := install(ctx); err == nil || !db.faultReached {
						t.Fatal("selected audit registration fault was not reached/refused")
					}
					var clean bool
					if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization79') IS NULL AND to_regnamespace('zasp_authorization80') IS NULL AND to_regnamespace('zasp_authorization80_audit') IS NULL AND to_regnamespace('zasp_authorization80_temporal') IS NULL AND pg_get_functiondef('public.zasp_sa_attack_lab_live_fingerprint()'::regprocedure)=$1`, original57).Scan(&clean); err != nil || !clean {
						t.Fatalf("atomic rollback=%t %v", clean, err)
					}
					db.fail = false
				}
				if err := install(ctx); err != nil {
					t.Fatal("install", err)
				}
				if err := install(ctx); err != nil {
					t.Fatal("exact replay", err)
				}
				var healthy bool
				if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.ready($1)`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&healthy); err != nil || !healthy {
					t.Fatalf("fixture80 ready=%t %v", healthy, err)
				}
				core := connectRuntimeDataPlanePrincipal(t, ctx, owner.Config().ConnString(), "security_agent_v33_discovery_api_login")
				defer core.Close(context.Background())
				for _, conn := range []*pgx.Conn{core, agent} {
					var valid bool
					if err := conn.QueryRow(ctx, `SELECT session_user=current_user AND session_user=$1 AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`, conn.Config().User).Scan(&valid); err != nil || !valid {
						t.Fatalf("actual API role=%t %v", valid, err)
					}
					t.Logf("registered API principal=%s nonsuper/nobypass confirmed", conn.Config().User)
				}
				coreDB, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: core})
				agentDB, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: agent})
				if coreDB.RequireCurrentAuthorization() != nil || agentDB.RequireCurrentAuthorization() != nil {
					t.Fatal("enforcing adapter")
				}
				key := authorizationFixtureAttestor(t)
				check := func(want bool) {
					t.Helper()
					for _, c := range []struct {
						db   *PostgresJSONDatabase
						role string
					}{{coreDB, "zasp_discovery_api"}, {agentDB, "zasp_security_agent_api"}} {
						started := time.Now()
						err := c.db.CurrentAuthorizationRuntimeReady(ctx, c.role, key.Version())
						if (err == nil) != want {
							t.Fatalf("typed role=%s ready=%t want=%t error=%v", c.role, err == nil, want, err)
						}
						t.Logf("typed role=%s ready=%t elapsed=%s", c.role, err == nil, time.Since(started))
					}
				}
				check(false) // No verifier exists yet.
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()); err != nil {
					t.Fatal(err)
				}
				if profile != "composed-guarded" {
					check(false)
					t.Log("valid compatibility profile remains refused by production readiness")
					return
				}
				check(true)
				if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err == nil {
					t.Fatal("none installer adopted guarded profile")
				}
				for _, c := range []struct {
					db   *PostgresJSONDatabase
					role string
				}{{coreDB, "zasp_security_agent_api"}, {agentDB, "zasp_discovery_api"}} {
					if c.db.CurrentAuthorizationRuntimeReady(ctx, c.role, key.Version()) == nil {
						t.Fatal("argument role replaced actual session authority")
					}
				}
				for _, conn := range []*pgx.Conn{core, agent} {
					for _, query := range []string{`SELECT checksum FROM zasp_authorization80_audit.registration`, `SELECT name FROM zasp_authorization80.runtime_profile`, `SELECT zasp_authorization80_audit.catalog_ready()`} {
						_, err := conn.Exec(ctx, query)
						var pgErr *pgconn.PgError
						if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
							t.Fatalf("private metadata access sqlstate=%v", err)
						}
					}
				}
				if _, err := coreDB.QueryJSON(ctx, `SELECT true`); !errors.Is(err, ErrAuthorizationDenied) {
					t.Fatal("generic QueryJSON bypass")
				}
				// Mutations are confined to this owned disposable database and are
				// restored before the next case, with a real positive each time.
				var endpoint string
				if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_authorization80_audit.production_ready(text,text,text,text)'::regprocedure)`).Scan(&endpoint); err != nil {
					t.Fatal(err)
				}
				cases := []struct{ name, change, restore string }{
					{"audit namespace absent", `ALTER SCHEMA zasp_authorization80_audit RENAME TO readiness_hidden_audit`, `ALTER SCHEMA readiness_hidden_audit RENAME TO zasp_authorization80_audit`},
					{"composed namespace absent", `ALTER SCHEMA zasp_authorization80_temporal RENAME TO readiness_hidden_profile`, `ALTER SCHEMA readiness_hidden_profile RENAME TO zasp_authorization80_temporal`},
					{"source52 invalid", `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`, `UPDATE zasp_schema_metadata SET value='` + migrations.ProductionAuditExportsSemanticFingerprint() + `' WHERE key='production_audit_exports_fingerprint'`},
					{"audit guard disabled", `ALTER TABLE zasp_admin_audit DISABLE TRIGGER zasp_authorization80_audit_write_guard`, `ALTER TABLE zasp_admin_audit ENABLE TRIGGER zasp_authorization80_audit_write_guard`},
					{"allow-valued endpoint", `CREATE OR REPLACE FUNCTION zasp_authorization80_audit.production_ready(expected80 text,expected_audit text,key_version text,api_authority text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT true'`, endpoint},
				}
				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						if _, err := owner.Exec(ctx, c.change); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if _, err := owner.Exec(context.Background(), c.restore); err != nil {
								t.Error(err)
							}
						}()
						check(false)
					})
				}
				check(true)
				rotated, err := authorization.NewAttestationKey(bytes.Repeat([]byte{0x95}, 32))
				if err != nil {
					t.Fatal(err)
				}
				if rotated.Version() == key.Version() {
					t.Fatal("rotation fixture must use distinct key versions")
				}
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, rotated.Version(), rotated.Verifier()); err != nil {
					t.Fatal(err)
				}
				check(false)
				if err := coreDB.CurrentAuthorizationRuntimeReady(ctx, "zasp_discovery_api", rotated.Version()); err != nil {
					t.Fatal("new verifier refused", err)
				}
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier()); err != nil {
					t.Fatal(err)
				}
				guardedReadinessOldSource(t, ctx, owner, core, coreDB, key.Version(), install)
				check(true)
			}, func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_e2e") })
		})
	}
}

func guardedReadinessOldSource(t *testing.T, ctx context.Context, owner, api *pgx.Conn, db *PostgresJSONDatabase, key string, install func(context.Context) error) {
	t.Helper()
	// Synthetic compatibility fixture: all self-checksum literals and the
	// immutable registration agree on an older source identity. This is not
	// evidence of an external deployment or permission to rewrite one.
	current, older := migrations.AuthorizationAuditProfileChecksum(), strings.Repeat("b", 64)
	rows, err := owner.Query(ctx, `SELECT pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace='zasp_authorization80_audit'::regnamespace AND position($1 in pg_get_functiondef(oid))>0 ORDER BY oid`, current)
	if err != nil {
		t.Fatal(err)
	}
	var definitions []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, d)
	}
	rows.Close()
	if rows.Err() != nil || len(definitions) < 2 {
		t.Fatal("missing self-bound audit functions", rows.Err())
	}
	refresh := func(checksum string) {
		t.Helper()
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE zasp_authorization80_audit.registration SET checksum=$1,fingerprint=zasp_authorization80_audit.fingerprint()`, checksum); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, d := range definitions {
			if _, err := owner.Exec(context.Background(), d); err != nil {
				t.Error(err)
			}
		}
		refresh(current)
	}()
	for _, d := range definitions {
		if _, err := owner.Exec(ctx, strings.ReplaceAll(d, current, older)); err != nil {
			t.Fatal(err)
		}
	}
	refresh(older)
	var independent, oldReady bool
	if err := api.QueryRow(ctx, postgresAuthorizationRuntimeReadySQL, migrations.ProductionAuthorizationEnforcement().Checksum(), older, key, "zasp_discovery_api").Scan(&independent, &oldReady); err != nil || !independent || !oldReady {
		t.Fatalf("internally valid older source: independent=%t endpoint=%t error=%v", independent, oldReady, err)
	}
	t.Log("synthetic older-source positive: independent80=true old-checksum endpoint=true")
	if err := db.CurrentAuthorizationRuntimeReady(ctx, "zasp_discovery_api", key); err == nil {
		t.Fatal("current binary accepted older consistent audit source")
	}
	if err := install(ctx); err == nil {
		t.Fatal("installer adopted older consistent source")
	}
}
