package apiserver

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

func auditProfileCatalogDrifts(t *testing.T, ctx context.Context, owner, api *pgx.Conn, read func(context.Context, bool) error, probe func() error, composed bool, install func(context.Context) error) {
	t.Helper()
	query := func(q string) string {
		t.Helper()
		var s string
		if err := owner.QueryRow(ctx, q).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	guard := query(`SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='public.zasp_admin_audit'::regclass AND tgname='zasp_authorization80_audit_write_guard'`)
	value := query(`SELECT zasp_authorization80_audit.projected57()`)
	checksum := query(`SELECT checksum FROM zasp_authorization80_audit.registration`)
	tableOwner := query(`SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.zasp_admin_audit'::regclass`)
	if _, err := owner.Exec(ctx, `CREATE ROLE audit_catalog_drift_owner NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, change, restore string }{
		{"guard disabled", `ALTER TABLE public.zasp_admin_audit DISABLE TRIGGER zasp_authorization80_audit_write_guard`, `ALTER TABLE public.zasp_admin_audit ENABLE TRIGGER zasp_authorization80_audit_write_guard`},
		{"guard missing", `DROP TRIGGER zasp_authorization80_audit_write_guard ON public.zasp_admin_audit`, guard},
		{"guard wrong arguments", `DROP TRIGGER zasp_authorization80_audit_write_guard ON public.zasp_admin_audit; CREATE TRIGGER zasp_authorization80_audit_write_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.zasp_admin_audit FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_audit.write_guard('wrong_owner')`, `DROP TRIGGER zasp_authorization80_audit_write_guard ON public.zasp_admin_audit; ` + guard},
		{"extra trigger", `CREATE TRIGGER audit_extra BEFORE INSERT ON public.zasp_admin_audit FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_audit.write_guard('zasp_e2e')`, `DROP TRIGGER audit_extra ON public.zasp_admin_audit`},
		{"guard security definer", `ALTER FUNCTION zasp_authorization80_audit.write_guard() SECURITY DEFINER`, `ALTER FUNCTION zasp_authorization80_audit.write_guard() SECURITY INVOKER`},
		{"guard public execute", `GRANT EXECUTE ON FUNCTION zasp_authorization80_audit.write_guard() TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_authorization80_audit.write_guard() FROM PUBLIC`},
		{"guard config", `ALTER FUNCTION zasp_authorization80_audit.write_guard() SET search_path=public`, `ALTER FUNCTION zasp_authorization80_audit.write_guard() SET search_path=pg_catalog,public`},
		{"guard owner", `ALTER FUNCTION zasp_authorization80_audit.write_guard() OWNER TO audit_catalog_drift_owner`, `ALTER FUNCTION zasp_authorization80_audit.write_guard() OWNER TO zasp_discovery_authority`},
		{"source owner", `ALTER TABLE public.zasp_admin_audit OWNER TO audit_catalog_drift_owner`, `ALTER TABLE public.zasp_admin_audit OWNER TO ` + pgx.Identifier{tableOwner}.Sanitize()},
		{"source RLS", `ALTER TABLE public.zasp_admin_audit ENABLE ROW LEVEL SECURITY`, `ALTER TABLE public.zasp_admin_audit DISABLE ROW LEVEL SECURITY`},
		{"source ACL", `GRANT SELECT ON public.zasp_admin_audit TO PUBLIC`, `REVOKE SELECT ON public.zasp_admin_audit FROM PUBLIC`},
		{"source column ACL", `GRANT SELECT(actor_id) ON public.zasp_admin_audit TO PUBLIC`, `REVOKE SELECT(actor_id) ON public.zasp_admin_audit FROM PUBLIC`},
		{"source default", `ALTER TABLE public.zasp_admin_audit ALTER COLUMN action SET DEFAULT 'unknown'`, `ALTER TABLE public.zasp_admin_audit ALTER COLUMN action DROP DEFAULT`},
		{"source constraint", `ALTER TABLE public.zasp_admin_audit ADD CONSTRAINT audit_extra CHECK(true)`, `ALTER TABLE public.zasp_admin_audit DROP CONSTRAINT audit_extra`},
		{"source index", `CREATE INDEX audit_extra ON public.zasp_admin_audit(actor_id)`, `DROP INDEX public.audit_extra`},
		{"source policy", `CREATE POLICY audit_extra ON public.zasp_admin_audit USING(true)`, `DROP POLICY audit_extra ON public.zasp_admin_audit`},
		{"source52 pin", `UPDATE public.zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`, `UPDATE public.zasp_schema_metadata SET value='` + migrations.ProductionAuditExportsSemanticFingerprint() + `' WHERE key='production_audit_exports_fingerprint'`},
		{"saved source", `ALTER TABLE zasp_authorization80_audit.predecessor_functions DISABLE TRIGGER immutable; UPDATE zasp_authorization80_audit.predecessor_functions SET definition=definition||' '`, `UPDATE zasp_authorization80_audit.predecessor_functions SET definition=left(definition,length(definition)-1); ALTER TABLE zasp_authorization80_audit.predecessor_functions ENABLE TRIGGER immutable`},
		{"audit mode downgrade", `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; UPDATE zasp_authorization80.runtime_profile SET audit_mode='none'; ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`, `ALTER TABLE zasp_authorization80.runtime_profile DISABLE TRIGGER immutable; UPDATE zasp_authorization80.runtime_profile SET audit_mode='source52-canonical61-audit-v1'; ALTER TABLE zasp_authorization80.runtime_profile ENABLE TRIGGER immutable`},
		{"audit namespace missing", `ALTER SCHEMA zasp_authorization80_audit RENAME TO audit_profile_hidden`, `ALTER SCHEMA audit_profile_hidden RENAME TO zasp_authorization80_audit`},
		{"audit registration missing", `ALTER TABLE zasp_authorization80_audit.registration RENAME TO hidden_registration`, `ALTER TABLE zasp_authorization80_audit.hidden_registration RENAME TO registration`},
		{"audit catalog entry missing", `ALTER FUNCTION zasp_authorization80_audit.catalog_ready() RENAME TO hidden_catalog_ready`, `ALTER FUNCTION zasp_authorization80_audit.hidden_catalog_ready() RENAME TO catalog_ready`},
		{"old audit checksum", `ALTER TABLE zasp_authorization80_audit.registration DISABLE TRIGGER immutable; UPDATE zasp_authorization80_audit.registration SET checksum=repeat('0',64)`, `UPDATE zasp_authorization80_audit.registration SET checksum='` + checksum + `'; ALTER TABLE zasp_authorization80_audit.registration ENABLE TRIGGER immutable`},
	}
	prior := "zasp_sa_attack_lab_prior.audit_fingerprint()"
	cases = append(cases, struct{ name, change, restore string }{"retained source query", `CREATE OR REPLACE FUNCTION ` + prior + ` RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT NULL::text'`, query(`SELECT pg_get_functiondef('` + prior + `'::regprocedure)`)})
	for _, name := range []string{"audit_fingerprint", "budget_fingerprint", "run_context_fingerprint", "existing_tests_fingerprint", "compliance_fingerprint", "projected57"} {
		signature := "zasp_authorization80_audit." + name + "()"
		original := query(`SELECT pg_get_functiondef('` + signature + `'::regprocedure)`)
		cases = append(cases, struct{ name, change, restore string }{"constant projector " + name, fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT ''%s''::text'`, signature, value), original})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := read(ctx, true); err != nil {
				t.Fatal("pre-drift API", err)
			}
			if err := probe(); err != nil {
				t.Fatal("pre-drift native78", err)
			}
			defer func() {
				if _, err := owner.Exec(context.Background(), c.restore); err != nil {
					t.Error("restore owned drift", err)
				}
			}()
			if _, err := owner.Exec(ctx, c.change); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_audit.catalog_ready()`).Scan(&ready); err == nil && ready {
				t.Error("audit catalog drift accepted")
			}
			if err := read(ctx, false); err == nil {
				t.Error("audit drift passed signed API")
			}
			if composed {
				if err := probe(); err == nil {
					t.Error("audit drift passed native78")
				}
				if err := api.QueryRow(ctx, `SELECT zasp_temporal78.api_ready($1,$2)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint()).Scan(&ready); err == nil && ready {
					t.Error("audit drift passed78 API")
				}
			}
			if c.name == "old audit checksum" && install(ctx) == nil {
				t.Error("obsolete audit silently adopted")
			}
		})
	}
	t.Run("current binary refuses old audit source despite allow catalog", func(t *testing.T) {
		original := query(`SELECT pg_get_functiondef('zasp_authorization80_audit.catalog_ready()'::regprocedure)`)
		defer func() {
			if _, err := owner.Exec(context.Background(), original+`; UPDATE zasp_authorization80_audit.registration SET checksum='`+checksum+`'; ALTER TABLE zasp_authorization80_audit.registration ENABLE TRIGGER immutable`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := owner.Exec(ctx, `ALTER TABLE zasp_authorization80_audit.registration DISABLE TRIGGER immutable; UPDATE zasp_authorization80_audit.registration SET checksum=repeat('0',64); CREATE OR REPLACE FUNCTION zasp_authorization80_audit.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT true'`); err != nil {
			t.Fatal(err)
		}
		if install(ctx) == nil {
			t.Error("current binary adopted obsolete audit source via allow catalog")
		}
	})
}
