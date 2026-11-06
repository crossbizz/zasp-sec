package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestMaintenanceOperatorNoInheritPostgres(t *testing.T) {
	runMaintenanceOperatorNoInherit(t, false)
}
func TestMaintenanceOperatorNoInheritAuditPostgres(t *testing.T) {
	runMaintenanceOperatorNoInherit(t, true)
}

// These are actual Runner/SQL transactions under the original restricted LOGIN.
// They do not execute the separately required CLI process or any provider flow.
func runMaintenanceOperatorNoInherit(t *testing.T, audit bool) {
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
	// The original installer may create this one existing purpose role. The
	// restricted operator intentionally lacks CREATEROLE; provision only that
	// prerequisite using the owned bootstrap, never a runtime LOGIN/membership.
	if _, err := f.bootstrap.Exec(ctx, `DO $role$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_approval_maintenance_worker') THEN CREATE ROLE zasp_approval_maintenance_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;END IF;END $role$`); err != nil {
		t.Fatal("owned purpose role prerequisite refused")
	}
	runner := precisionMigrationRunner(t, f.owner)
	type roleState struct{ session, current, role, path, lock string }
	observe := func(q maintenanceNativeQueryer) roleState {
		t.Helper()
		var result roleState
		if err := q.QueryRow(ctx, `SELECT session_user::text,current_user::text,current_setting('role'),current_setting('search_path'),current_setting('lock_timeout')`).Scan(&result.session, &result.current, &result.role, &result.path, &result.lock); err != nil {
			t.Fatal("native operator state unavailable")
		}
		return result
	}
	assertState := func(q maintenanceNativeQueryer, before roleState) {
		t.Helper()
		if after := observe(q); after != before {
			t.Fatal("installer changed incoming operator role or GUC state")
		}
	}
	privateDenied := func() {
		t.Helper()
		var ready bool
		err := f.owner.QueryRow(ctx, `SELECT zasp_authorization80.ready($1)`, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "42501" {
			t.Fatal("restricted LOGIN unexpectedly acquired private80 access")
		}
	}
	// Include every original public function as well as the composed parent
	// namespaces. REFERENCES(id) is the one separately checked owner DDL delta.
	parentState := func() string {
		t.Helper()
		var state string
		if err := f.bootstrap.QueryRow(ctx, `SELECT jsonb_build_object('79',zasp_authorization79.fingerprint(),'80',zasp_authorization80.fingerprint(),'worker',zasp_authorization80_worker.fingerprint(),'runtime',zasp_authorization80_runtime.fingerprint(),'temporal',zasp_authorization80_temporal.fingerprint(),'versions',(SELECT jsonb_agg(jsonb_build_array(version,name,checksum) ORDER BY version) FROM public.zasp_schema_versions),'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) ORDER BY n.nspname,p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','zasp_authorization79','zasp_authorization80','zasp_authorization80_worker','zasp_authorization80_runtime','zasp_authorization80_temporal')))::text`).Scan(&state); err != nil {
			t.Fatal("immutable native parent snapshot unavailable")
		}
		return state
	}
	initialParents := parentState()
	initial := observe(f.owner)
	connectorPin, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		t.Fatal("compiled connector pin unavailable")
	}
	activationPin, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal("compiled activation pin unavailable")
	}
	settlementPin, err := migrations.ApprovalSettlementAuditProfileChecksum()
	if err != nil {
		t.Fatal("compiled settlement pin unavailable")
	}
	installed := func(query string, args ...any) {
		t.Helper()
		var ready bool
		if err := f.bootstrap.QueryRow(ctx, query, args...).Scan(&ready); err != nil || !ready {
			t.Fatal("installed native catalog or inactive boundary refused")
		}
	}
	install := func(up func(context.Context) error) {
		t.Helper()
		before := observe(f.owner)
		if err := up(ctx); err != nil {
			t.Fatal("restricted original operator installer refused")
		}
		assertState(f.owner, before)
		privateDenied()
	}
	t.Run("restricted_original_login_private80_denied", func(t *testing.T) {
		var bound bool
		if err := f.owner.QueryRow(ctx, `SELECT session_user=current_user AND current_setting('role')='none' AND p.rolname=session_user AND p.rolcanlogin AND NOT(p.rolinherit OR p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls) AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND has_database_privilege(session_user,current_database(),'CREATE') AND NOT has_database_privilege('zasp_discovery_authority',current_database(),'CREATE') AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b WHERE b.principal_name=session_user AND b.authority_role='zasp_discovery_authority') AND (SELECT relowner=p.oid FROM pg_class WHERE oid='public.zasp_organizations'::regclass) FROM pg_roles p WHERE p.rolname=session_user`).Scan(&bound); err != nil || !bound {
			t.Fatal("original NOINHERIT operator prerequisite is not genuine")
		}
		privateDenied()
	})
	t.Run("approval_installs_as_original_owner_and_restores_role", func(t *testing.T) {
		install(runner.UpProductionApprovalMaintenanceProfile)
		installed(`SELECT zasp_approval_maintenance.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE singleton AND checksum=$1 AND NOT active)`, migrations.ApprovalMaintenanceProfileChecksum())
	})
	t.Run("connector_installs_as_original_owner_and_restores_role", func(t *testing.T) {
		install(runner.UpProductionConnectorMaintenance)
		installed(`SELECT zasp_connector_maintenance.catalog_ready($1) AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND checksum=$1 AND NOT active)`, connectorPin)
	})
	t.Run("activation_installs_as_original_owner_and_restores_role", func(t *testing.T) {
		install(runner.UpProductionApprovalActivationProfile)
		installed(`SELECT zasp_approval_activation_v1.catalog_ready($1) AND NOT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations)`, activationPin)
	})
	t.Run("settlement_installs_as_original_owner_and_restores_role", func(t *testing.T) {
		install(runner.UpProductionApprovalSettlementAuditProfile)
		installed(`SELECT zasp_approval_settlement_v1.catalog_ready($1) AND EXISTS(SELECT 1 FROM zasp_approval_settlement_v1.registration WHERE singleton AND checksum=$1)`, settlementPin)
	})
	t.Run("idempotent_install_preserves_explicit_incoming_role", func(t *testing.T) {
		if _, err := f.owner.Exec(ctx, `SET ROLE zasp_e2e`); err != nil {
			t.Fatal("self role selection refused")
		}
		defer func() {
			if _, err := f.owner.Exec(ctx, `RESET ROLE`); err != nil {
				t.Error("self role restoration refused")
			}
		}()
		before := observe(f.owner)
		if before.role != "zasp_e2e" || before.current != before.session {
			t.Fatal("explicit incoming self role not observed")
		}
		for _, up := range []func(context.Context) error{runner.UpProductionApprovalMaintenanceProfile, runner.UpProductionConnectorMaintenance, runner.UpProductionApprovalActivationProfile, runner.UpProductionApprovalSettlementAuditProfile} {
			install(up)
			assertState(f.owner, before)
		}
	})
	t.Run("rejected_parent_rolls_back_role_and_effects", func(t *testing.T) {
		outer, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal("owned rejection transaction unavailable")
		}
		defer outer.Rollback(context.Background())
		before := observe(outer)
		if _, err = outer.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;GRANT EXECUTE ON FUNCTION zasp_authorization80.ready(text) TO PUBLIC`); err != nil {
			t.Fatal("owned rollback-only parent drift refused")
		}
		if err = outer.QueryRow(ctx, `SELECT set_config('role',$1,true)`, before.role).Scan(new(string)); err != nil {
			t.Fatal("owned incoming role restoration refused")
		}
		rejected, err := migrations.NewRunner(&maintenanceNativeSavepointDatabase{tx: outer})
		if err != nil {
			t.Fatal("real savepoint rejection runner unavailable")
		}
		for _, up := range []func(context.Context) error{rejected.UpProductionApprovalMaintenanceProfile, rejected.UpProductionConnectorMaintenance, rejected.UpProductionApprovalActivationProfile, rejected.UpProductionApprovalSettlementAuditProfile} {
			if err := up(ctx); err == nil {
				t.Fatal("drifted private parent accepted")
			}
			assertState(outer, before)
		}
		if err := outer.Rollback(ctx); err != nil {
			t.Fatal("owned parent drift rollback unconfirmed")
		}
		assertState(f.owner, initial)
		if after := parentState(); after != initialParents {
			t.Fatal("rollback-only parent drift survived transaction")
		}
	})
	t.Run("immutable_parents_and_inactive_fk_owner_effects", func(t *testing.T) {
		assertState(f.owner, initial)
		privateDenied()
		if after := parentState(); after != initialParents {
			t.Fatal("maintenance installation changed original parent source, ACL or compiled catalog")
		}
		installed(`SELECT zasp_approval_maintenance.catalog_ready() AND zasp_connector_maintenance.catalog_ready($1) AND zasp_approval_activation_v1.catalog_ready($2) AND zasp_approval_settlement_v1.catalog_ready($3) AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE active) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE active) AND NOT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations) AND has_column_privilege('zasp_discovery_authority','public.zasp_organizations','id','REFERENCES') AND EXISTS(SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_approval_activation_v1' AND k.contype='f' AND k.confrelid='public.zasp_organizations'::regclass)`, connectorPin, activationPin, settlementPin)
	})
}

type maintenanceNativeQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Negative tests use actual pgx SAVEPOINT transactions inside an owned rollback
// scope; positive installer cases above use genuine committed owner connections.
type maintenanceNativeSavepointDatabase struct{ tx pgx.Tx }

func (d *maintenanceNativeSavepointDatabase) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return d.tx.QueryRow(ctx, q, args...)
}
func (d *maintenanceNativeSavepointDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &maintenanceNativeSavepointTransaction{tx: tx}, nil
}

type maintenanceNativeSavepointTransaction struct{ tx pgx.Tx }

func (t *maintenanceNativeSavepointTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	return t.tx.QueryRow(ctx, q, args...)
}
func (t *maintenanceNativeSavepointTransaction) Exec(ctx context.Context, q string, args ...any) error {
	_, err := t.tx.Exec(ctx, q, args...)
	return err
}
func (t *maintenanceNativeSavepointTransaction) Commit(ctx context.Context) error {
	return t.tx.Commit(ctx)
}
func (t *maintenanceNativeSavepointTransaction) Rollback(ctx context.Context) error {
	return t.tx.Rollback(ctx)
}
