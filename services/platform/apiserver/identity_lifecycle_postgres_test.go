package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These calls must refuse on the actual registered API connection, including
// retained SECURITY DEFINER helpers. Each attempt rolls back even in RED.
func TestP7IdentityNativeForgeryPostgres(t *testing.T) {
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Identity','identity.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Identity')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Identity','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-identity80','member-identity80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Identity','[]',true)`, p, o, w, e)
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	var registered bool
	if err := api.QueryRow(ctx, `SELECT session_user='auth80_api' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&registered); err != nil || !registered {
		t.Fatalf("registered API role=%t %v", registered, err)
	}
	cases := []struct {
		name, q string
		args    []any
	}{
		{"fabricated-provider-groups", `SELECT zasp_identity_admin_resolve_session('organization-identity80','member-identity80','["scim-group-test-forged80"]')`, nil},
		{"forged-provider-session", `SELECT zasp_create_product_session($1,$2,$3,$4,$5,$6,'[]',clock_timestamp()+interval '1 hour')`, []any{strings.Repeat("t", 43), strings.Repeat("c", 43), p, o, w, e}},
		{"unsigned-deprovision", `SELECT zasp_identity_admin_reconcile_deprovision('project-test-identity80','webhook-event-test-identity80','organization-identity80','member-identity80',digest('fixture','sha256'),'pid_98000001-0000-4000-8000-000000000001')`, nil},
		{"raw-state", `INSERT INTO zasp_identity_states(state_digest,return_path,expires_at) VALUES(digest('forged-state','sha256'),'/',clock_timestamp()+interval '10 minutes')`, nil},
		{"raw-membership", `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, []any{o, p}},
		{"zero-row-session-update", `UPDATE zasp_product_sessions SET csrf_token=repeat('x',43) WHERE false`, nil},
		{"zero-row-token-update", `UPDATE zasp_product_api_tokens SET permissions='["manage_identity"]' WHERE false`, nil},
		{"zero-row-group-mapping-update", `UPDATE zasp_group_mappings SET role='organization_admin' WHERE false`, nil},
		{"zero-row-state-delete", `DELETE FROM zasp_identity_states WHERE false`, nil},
		{"raw-membership-delete", `DELETE FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2`, []any{o, p}},
		{"raw-state-truncate", `TRUNCATE zasp_identity_states`, nil},
		{"forged-guc-membership", `SELECT set_config('zasp.identity80','{"purpose":"admin","operation":"updateMemberRole"}',true); UPDATE zasp_identity_memberships SET role='organization_admin'`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, c.q, c.args...)
			if rollback := tx.Rollback(ctx); rollback != nil {
				t.Fatal(rollback)
			}
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Errorf("native identity forgery admitted or wrong refusal: err=%v", err)
			}
		})
	}
	var pristine bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT active FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_identity_member_groups) AND NOT EXISTS(SELECT 1 FROM zasp_product_sessions) AND NOT EXISTS(SELECT 1 FROM zasp_identity_webhook_events) AND NOT EXISTS(SELECT 1 FROM zasp_identity_states)`, o, p).Scan(&pristine); err != nil || !pristine {
		t.Fatalf("rollback effects=%t %v", pristine, err)
	}
}
