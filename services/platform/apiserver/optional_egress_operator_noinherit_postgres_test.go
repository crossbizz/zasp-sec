package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestOptionalEgressOperatorNoInheritPostgres(t *testing.T) {
	runOptionalEgressOperatorNoInherit(t, false)
}
func TestOptionalEgressOperatorNoInheritAuditPostgres(t *testing.T) {
	runOptionalEgressOperatorNoInherit(t, true)
}

// Actual installed SQL and committed Runner transactions under the original
// restricted LOGIN. CLI processes and provider delivery remain separate proof.
func runOptionalEgressOperatorNoInherit(t *testing.T, audit bool) {
	t.Helper()
	if audit {
		t.Setenv("ZASP_P7_AUDIT_TEST", "1")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	} else {
		t.Setenv("ZASP_P7_AUDIT_TEST", "")
		t.Setenv("ZASP_P7_IDENTITY_TEST", "")
	}
	f := newEnvironmentClassNativeFixture(t)
	ctx := f.ctx
	runner := precisionMigrationRunner(t, f.owner)
	selected, wrong := runner.UpProductionOptionalEgressProfile, runner.UpProductionOptionalEgressAuditProfile
	pin := migrations.OptionalEgressProfileChecksum()
	if audit {
		selected, wrong = wrong, selected
		pin = migrations.OptionalEgressAuditProfileChecksum()
	}
	type operatorState struct{ session, current, role, path, lock string }
	observe := func(q maintenanceNativeQueryer) operatorState {
		t.Helper()
		var state operatorState
		if err := q.QueryRow(ctx, `SELECT session_user::text,current_user::text,current_setting('role'),current_setting('search_path'),current_setting('lock_timeout')`).Scan(&state.session, &state.current, &state.role, &state.path, &state.lock); err != nil {
			t.Fatal("optional operator state unavailable")
		}
		return state
	}
	unchanged := func(q maintenanceNativeQueryer, before operatorState) {
		t.Helper()
		if after := observe(q); after != before {
			t.Fatal("optional installer changed incoming role or GUC state")
		}
	}
	privateDenied := func() {
		t.Helper()
		var ready bool
		err := f.owner.QueryRow(ctx, `SELECT zasp_authorization80.ready($1)`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "42501" {
			t.Fatal("optional operator acquired direct private80 permission")
		}
	}
	parents := func() string {
		t.Helper()
		var result string
		if err := f.bootstrap.QueryRow(ctx, `SELECT jsonb_build_object('79',zasp_authorization79.fingerprint(),'80',zasp_authorization80.fingerprint(),'temporal',zasp_authorization80_temporal.fingerprint(),'worker',zasp_authorization80_worker.fingerprint(),'runtime',zasp_authorization80_runtime.fingerprint(),'versions',(SELECT jsonb_agg(jsonb_build_array(version,name,checksum) ORDER BY version) FROM public.zasp_schema_versions),'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) ORDER BY n.nspname,p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','zasp_authorization79','zasp_authorization80','zasp_authorization80_temporal','zasp_authorization80_worker','zasp_authorization80_runtime','zasp_environment_class_v1')))::text`).Scan(&result); err != nil {
			t.Fatal("optional immutable parent snapshot unavailable")
		}
		return result
	}
	initialState, initialParents := observe(f.owner), parents()
	unavailable := func() {
		t.Helper()
		var valid bool
		if err := f.bootstrap.QueryRow(ctx, `SELECT zasp_optional_egress_v1.catalog_ready($1) AND EXISTS(SELECT 1 FROM zasp_optional_egress_v1.registration WHERE singleton AND checksum=$1 AND fingerprint=zasp_optional_egress_v1.fingerprint()) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.principals) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.approved_profiles) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.policies) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.requests) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.events) AND NOT EXISTS(SELECT 1 FROM zasp_optional_egress_v1.mutations)`, pin).Scan(&valid); err != nil || !valid {
			t.Fatal("optional installation activated or configured an external flow")
		}
		if parents() != initialParents {
			t.Fatal("optional installation changed immutable parent SQL, ACLs or compiled catalogs")
		}
	}
	t.Run("restricted_original_login_private80_denied", func(t *testing.T) {
		var valid bool
		if err := f.owner.QueryRow(ctx, `SELECT session_user=current_user AND current_setting('role')='none' AND p.rolcanlogin AND NOT(p.rolinherit OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls) AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND has_database_privilege(session_user,current_database(),'CREATE') AND NOT has_database_privilege('zasp_discovery_authority',current_database(),'CREATE') AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') FROM pg_roles p WHERE p.rolname=session_user`).Scan(&valid); err != nil || !valid {
			t.Fatal("optional original NOINHERIT operator prerequisite is not genuine")
		}
		privateDenied()
	})
	t.Run("selected_recipe_installs_unconfigured_and_restores_role", func(t *testing.T) {
		before := observe(f.owner)
		if err := selected(ctx); err != nil {
			t.Fatal("selected optional recipe refused restricted original owner")
		}
		unchanged(f.owner, before)
		privateDenied()
		unavailable()
	})
	t.Run("idempotent_recipe_preserves_explicit_incoming_role", func(t *testing.T) {
		if _, err := f.owner.Exec(ctx, `SET ROLE zasp_e2e`); err != nil {
			t.Fatal("optional explicit self role selection refused")
		}
		defer func() {
			if _, err := f.owner.Exec(ctx, `RESET ROLE`); err != nil {
				t.Error("optional explicit self role restoration refused")
			}
		}()
		before := observe(f.owner)
		if before.role != "zasp_e2e" || before.current != before.session {
			t.Fatal("optional explicit incoming self role not observed")
		}
		if err := selected(ctx); err != nil {
			t.Fatal("selected optional recipe idempotence refused")
		}
		unchanged(f.owner, before)
		privateDenied()
		unavailable()
	})
	t.Run("other_parent_recipe_refuses_without_effects", func(t *testing.T) {
		before := observe(f.owner)
		if err := wrong(ctx); err == nil {
			t.Fatal("other optional parent variant silently replaced the selected recipe")
		}
		unchanged(f.owner, before)
		privateDenied()
		unavailable()
	})
	t.Run("rejected_private_parent_rolls_back_role_and_effects", func(t *testing.T) {
		outer, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal("optional rollback-only parent transaction unavailable")
		}
		defer outer.Rollback(context.Background())
		before := observe(outer)
		if _, err = outer.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;GRANT EXECUTE ON FUNCTION zasp_authorization80.ready(text) TO PUBLIC`); err != nil {
			t.Fatal("optional rollback-only parent drift refused")
		}
		if err = outer.QueryRow(ctx, `SELECT set_config('role',$1,true)`, before.role).Scan(new(string)); err != nil {
			t.Fatal("optional owned incoming role restoration refused")
		}
		rejected, err := migrations.NewRunner(&maintenanceNativeSavepointDatabase{tx: outer})
		if err != nil {
			t.Fatal("optional actual savepoint runner unavailable")
		}
		run := rejected.UpProductionOptionalEgressProfile
		if audit {
			run = rejected.UpProductionOptionalEgressAuditProfile
		}
		if err := run(ctx); err == nil {
			t.Fatal("optional private parent drift accepted")
		}
		unchanged(outer, before)
		if err := outer.Rollback(ctx); err != nil {
			t.Fatal("optional owned parent rollback unconfirmed")
		}
		unchanged(f.owner, initialState)
		privateDenied()
		unavailable()
	})
}
