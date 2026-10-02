package apiserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"os"
	"testing"
	"time"
)

// This batch uses a private PostgreSQL cluster. It never mutates a retained DB.
func TestAuthorizationProjectionPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := startDisposablePostgres(t)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, conn)
	for _, up := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAuthorizationProjection} {
		if err := up(ctx); err != nil {
			t.Fatalf("projection prerequisites/install: %v", err)
		}
	}
	identity := fixtureRequestIdentity(t)
	o, p := identity.Scope.OrganizationID().String(), identity.PrincipalID.String()
	if _, err := conn.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-projection','member-projection','security_admin',true)`, p, o); err != nil {
		t.Fatal(err)
	}
	var desired, applied int64
	if err := conn.QueryRow(ctx, `SELECT desired,applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&desired, &applied); err != nil || desired < 1 || applied != 0 {
		t.Fatalf("grant must atomically pend: desired=%d applied=%d err=%v", desired, applied, err)
	}
	w, e := identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Projection','projection.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Projection')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	for _, name := range []string{"auth_api_login", "auth_discovery_login", "auth_ingest_login", "auth_runtime_login", "auth_outbox_login", "auth_gateway_login"} {
		exec(fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, name))
	}
	exec(`SELECT zasp_discovery_register_principals(session_user,'auth_api_login','auth_discovery_login','auth_ingest_login','auth_runtime_login','auth_outbox_login','auth_gateway_login')`)
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.User = "auth_outbox_login"
	poolConfig.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repository, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth_api_login")
	defer api.Close(context.Background())
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	var writer authorization.TupleWriter = &authorizationTestWriter{}
	var checker authorization.Checker = &authorizationTestChecker{model: model}
	if os.Getenv("ZASP_P6_MODEL_TEST") == "1" {
		client, config := newAuthorizationProjectionFGA(t)
		store, model = config.StoreID, config.ModelID
		writer, err = authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
		checker, err = authorization.NewOpenFGA(client, config)
		if err != nil {
			t.Fatal(err)
		}
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	request := authorization.CheckRequest{PrincipalKind: "user", PrincipalID: p, OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ResourceType: "environment", ResourceID: e, Permission: "manage_identity"}
	if _, err := authorization.CheckRevision(ctx, repository, checker, request, store, model); !errors.Is(err, authorization.ErrPending) {
		t.Fatalf("pending grant usable: %v", err)
	}
	reconcile := func() {
		t.Helper()
		receipt, err := authorization.Reconcile(ctx, repository, writer, o, store, model)
		if err != nil || !receipt.Applied {
			t.Fatalf("reconcile: %#v %v", receipt, err)
		}
	}
	reconcile()
	proof, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
	if err != nil || !proof.Decision.Allowed {
		t.Fatalf("applied grant: %#v %v", proof, err)
	}
	tx, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.RevalidateDecision(ctx, tx, proof, request); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exerciseAuthorizationProjectionConflict(t, ctx, conn, api, dsn, repository, checker, request, store, model)
	exerciseAuthorizationProjectionMachines(t, ctx, conn, repository, writer, checker, request, store, model, os.Getenv("ZASP_P6_MODEL_TEST") == "1")
	// Same-model repair is still a new generation. An old proof cannot cross it.
	exec(`SELECT zasp_authorization79.configure($1,$2,$3,true)`, o, store, model)
	tx, err = api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.RevalidateDecision(ctx, tx, proof, request); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("stale generation accepted: %v", err)
	}
	_ = tx.Rollback(ctx)
	reconcile()
	currentProof, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
	if err != nil {
		t.Fatal(err)
	}
	currentProof.Revision.Generation--
	tx, err = api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.RevalidateDecision(ctx, tx, currentProof, request); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("same revision with stale generation accepted: %v", err)
	}
	_ = tx.Rollback(ctx)
	// Registered verified-login write changes desired state, not just a fake event.
	exec(`INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-audit','compliance_viewer',$2,$3)`, o, w, e)
	var resolved []byte
	if err := api.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-projection','member-projection','["scim-group-test-audit"]'::jsonb)`).Scan(&resolved); err != nil {
		t.Fatalf("registered verified groups: %v", err)
	}
	tx, err = api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.RevalidateDecision(ctx, tx, proof, request); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("stale fence: %v", err)
	}
	_ = tx.Rollback(ctx)
	// A completed external write followed by a crash leaves pending state and a
	// durable union inventory. The next run repairs the current SQL snapshot.
	crash := &authorizationCrashRepository{delegate: repository}
	if receipt, err := authorization.Reconcile(ctx, crash, writer, o, store, model); err == nil || receipt.Applied {
		t.Fatal("crashed delivery acknowledged")
	}
	var staged int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization79.inventory WHERE organization_id=$1`, o).Scan(&staged); err != nil || staged == 0 {
		t.Fatal("stage missing", err)
	}
	reconcile()
	// Reordering is harmless: an obsolete snapshot cannot replace a newer CAS.
	var obsolete authorization.ProjectionSnapshot
	err = repository.WithOrganization(ctx, o, func(session authorization.ProjectionSession) error {
		var err error
		obsolete, err = session.Snapshot(ctx)
		if err != nil {
			return err
		}
		exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, o, p)
		tuples, _ := authorization.Project(obsolete)
		return session.Stage(ctx, obsolete.Revision, tuples)
	})
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("obsolete stage accepted: %v", err)
	}
	if _, err := authorization.CheckRevision(ctx, repository, checker, request, store, model); !errors.Is(err, authorization.ErrPending) {
		t.Fatal("pending revoke allowed", err)
	}
	reconcile()
	if os.Getenv("ZASP_P6_MODEL_TEST") == "1" {
		result, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
		if err != nil || result.Decision.Allowed {
			t.Fatal("revoked role survived", err)
		}
	}
	// Immediate membership/session/PAT revocation remains SQL-owned while FGA is unavailable.
	exec(`INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('projection-session','sha256'),$1,$2,$3,$4,'["view"]',repeat('c',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('projection-token','sha256'),$1,$2,$3,$4,'["view"]',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	deprovision := `SELECT zasp_identity_admin_reconcile_deprovision('project-test-projection','webhook-event-test-projection','organization-projection','member-projection',digest('projection-event','sha256'),'pid_79000001-0000-4000-8000-000000000001')`
	if err := api.QueryRow(ctx, deprovision).Scan(&resolved); err != nil {
		t.Fatal("registered deprovision", err)
	}
	if err := api.QueryRow(ctx, deprovision).Scan(&resolved); err != nil || !jsonContainsBoolean(resolved, "replayed", true) {
		t.Fatal("deprovision replay", err)
	}
	var active, sessionActive, tokenActive bool
	if err := conn.QueryRow(ctx, `SELECT (SELECT active FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2),EXISTS(SELECT 1 FROM zasp_product_sessions WHERE organization_id=$1 AND principal_id=$2 AND revoked_at IS NULL),EXISTS(SELECT 1 FROM zasp_product_api_tokens WHERE organization_id=$1 AND principal_id=$2 AND revoked_at IS NULL)`, o, p).Scan(&active, &sessionActive, &tokenActive); err != nil || active || sessionActive || tokenActive {
		t.Fatal("immediate SQL revocation failed", err)
	}
	if _, err := authorization.CheckRevision(ctx, repository, checker, request, store, model); !errors.Is(err, authorization.ErrPending) {
		t.Fatal("deactivated principal not fenced", err)
	}
	if receipt, err := authorization.Reconcile(ctx, repository, &authorizationTestWriter{fail: true}, o, store, model); err == nil || receipt.Applied {
		t.Fatal("incomplete batch acknowledged")
	}
	reconcile()
	if os.Getenv("ZASP_P6_MODEL_TEST") == "1" {
		request.Permission = "view"
		result, err := authorization.CheckRevision(ctx, repository, checker, request, store, model)
		if err != nil || result.Decision.Allowed {
			t.Fatal("inactive membership retained", err)
		}
	}
	var receipts int
	var fingerprint string
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization79.receipts WHERE organization_id=$1`, o).Scan(&receipts); err != nil || receipts < 4 {
		t.Fatal("delivery receipts absent", err)
	}
	if err := conn.QueryRow(ctx, `SELECT zasp_authorization79.fingerprint()`).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	t.Logf("registered projection: %d durable receipts, fingerprint=%s", receipts, fingerprint)
	if err := runner.UpProductionAuthorizationProjection(ctx); err != nil {
		t.Fatalf("non-destructive install replay: %v", err)
	}
	var ready bool
	if err := conn.QueryRow(ctx, `SELECT zasp_authorization79.ready($1)`, migrations.ProductionAuthorizationProjection().Checksum()).Scan(&ready); err != nil || !ready {
		t.Fatal("readiness", err)
	}
}

type authorizationTestWriter struct{ fail bool }

func (w *authorizationTestWriter) Replace(context.Context, authorization.Revision, []fga.ClientTupleKey, []fga.ClientTupleKey) error {
	if w.fail {
		return authorization.ErrUnavailable
	}
	return nil
}

type authorizationTestChecker struct{ model string }

func (c *authorizationTestChecker) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	return authorization.Decision{Allowed: true, ModelID: c.model}, nil
}

type authorizationCrashRepository struct {
	delegate authorization.ProjectionRepository
}

func (r *authorizationCrashRepository) WithOrganization(ctx context.Context, o string, fn func(authorization.ProjectionSession) error) error {
	return r.delegate.WithOrganization(ctx, o, func(s authorization.ProjectionSession) error { return fn(authorizationCrashSession{s}) })
}

type authorizationCrashSession struct {
	authorization.ProjectionSession
}

func (authorizationCrashSession) Acknowledge(context.Context, authorization.Revision, []fga.ClientTupleKey) error {
	return authorization.ErrUnavailable
}
