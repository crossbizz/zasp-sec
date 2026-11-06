package apiserver

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Installed owner/ACL gates, not source fingerprints or fixture promotion.
// The shared fixture installs the actual normal/Audit current parents and addon.
func TestEnvironmentClassProfileNativeCatalogControls(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
				t.Skip("requires actual PostgreSQL and OpenFGA")
			}
			if audit {
				t.Setenv("ZASP_P7_AUDIT_TEST", "1")
				t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
			} else {
				t.Setenv("ZASP_P7_AUDIT_TEST", "")
				t.Setenv("ZASP_P7_IDENTITY_TEST", "")
			}
			f := newEnvironmentClassNativeFixture(t)
			runner := precisionMigrationRunner(t, f.owner)
			install := runner.UpProductionEnvironmentClassProfile
			wrong := runner.UpProductionEnvironmentClassAuditProfile
			if audit {
				install, wrong = wrong, install
			}
			if err := install(f.ctx); err != nil {
				t.Fatal("exact installed recipe idempotency refused", err)
			}
			if err := wrong(f.ctx); err == nil {
				t.Fatal("other parent recipe overwrote installed namespace")
			}
			observe := func(conn *pgx.Conn, mutate string) bool {
				t.Helper()
				tx, err := conn.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if mutate != "" {
					if _, err = tx.Exec(f.ctx, mutate); err != nil {
						t.Fatal("native own-profile drift setup", err)
					}
				}
				if _, err = tx.Exec(f.ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err = tx.QueryRow(f.ctx, `SELECT zasp_environment_class_v1.catalog_ready($1)`, f.pin).Scan(&ready); err != nil {
					t.Fatal("native catalog gate", err)
				}
				return ready
			}
			if !observe(f.owner, "") {
				t.Fatal("matching installed profile unavailable")
			}
			t.Run("closed_private_privileges", func(t *testing.T) {
				var valid bool
				if err := f.bootstrap.QueryRow(f.ctx, `SELECT NOT has_function_privilege('auth80_api','zasp_environment_class_v1.write_update_environment(text,text,text,text,text,text,bigint,text,text)','EXECUTE') AND NOT has_function_privilege('auth80_api','zasp_environment_class_v1.require_api(text,text,text,text,text,text)','EXECUTE') AND NOT has_table_privilege('auth80_api','zasp_environment_class_v1.registration','SELECT,INSERT,UPDATE,DELETE') AND has_function_privilege('zasp_e2e','zasp_environment_class_v1.require_api(text,text,text,text,text,text)','EXECUTE') AND NOT has_schema_privilege('zasp_e2e','zasp_environment_class_v1','CREATE') AND EXISTS(SELECT 1 FROM pg_class WHERE oid='zasp_environment_class_v1.registration'::regclass AND relrowsecurity AND relforcerowsecurity)`).Scan(&valid); err != nil || !valid {
					t.Fatal("installed private privilege or RLS contract", err)
				}
				_, err := f.owner.Exec(f.ctx, `SELECT zasp_environment_class_v1.require_api('x','x','x','x','updateEnvironment',$1)`, f.pin)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatal("source LOGIN session became browser actor", err)
				}
				api := connectRuntimeDataPlanePrincipal(t, f.ctx, f.configDSN, "auth80_api")
				defer api.Close(context.Background())
				_, err = api.Exec(f.ctx, `SELECT zasp_environment_class_v1.write_update_environment('x','x','x','x','Name','production',1,'x','x')`)
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatal("API directly invoked physical writer", err)
				}
			})
			for _, change := range []struct{ name, sql string }{
				{"nonpublic_inner_execute", `GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.write_update_environment(text,text,text,text,text,text,bigint,text,text) TO zasp_discovery_api`},
				{"helper_execute", `GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.require_api(text,text,text,text,text,text) TO zasp_discovery_api`},
				{"table_read", `GRANT SELECT ON zasp_environment_class_v1.registration TO zasp_discovery_api`},
				{"column_read", `GRANT SELECT(checksum) ON zasp_environment_class_v1.registration TO zasp_discovery_api`},
				{"schema_create", `GRANT CREATE ON SCHEMA zasp_environment_class_v1 TO zasp_discovery_api`},
				{"changed_body", `CREATE OR REPLACE FUNCTION zasp_environment_class_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT true'`},
			} {
				t.Run(change.name, func(t *testing.T) {
					if observe(f.bootstrap, change.sql) {
						t.Fatal("changed own-profile authority remained ready")
					}
					if !observe(f.owner, "") {
						t.Fatal("rolled-back drift changed original registration")
					}
				})
			}
			// Even an internally recomputed fingerprint cannot bless initial unwanted
			// default privileges: exact ACL admission is independent of the stored seal.
			t.Run("unwanted_initial_acl_not_sealable", func(t *testing.T) {
				if observe(f.bootstrap, `GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.write_update_environment(text,text,text,text,text,text,bigint,text,text) TO zasp_discovery_api;UPDATE zasp_environment_class_v1.registration SET fingerprint=zasp_environment_class_v1.fingerprint()`) {
					t.Fatal("self-consistent fingerprint blessed bypassing inner writer grant")
				}
				if observe(f.bootstrap, `GRANT SELECT(checksum) ON zasp_environment_class_v1.registration TO zasp_discovery_api;UPDATE zasp_environment_class_v1.registration SET fingerprint=zasp_environment_class_v1.fingerprint()`) {
					t.Fatal("self-consistent fingerprint blessed forbidden column grant")
				}

			})
		})
	}
}
