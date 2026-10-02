package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Controlled Check/signer, real mounted application and registered PostgreSQL.
// Removing current routing, exact proof checks, atomic audit or native version
// checks must fail this batch. It is not live provider/deployment evidence.
func TestP7DataControlsPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	// The initdb bootstrap superuser cannot be demoted. Root approved this
	// bounded fixture starter exception so zasp_e2e is a real demotable owner.
	bootstrapDSN := startDisposablePostgresAs(t, "zasp_test")
	probe, err := pgx.Connect(ctx, bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	if _, err = probe.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	ownerConfig, err := pgx.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	ownerConfig.User = "zasp_e2e"
	dsn := ownerConfig.ConnString()
	admin, err := pgx.ConnectConfig(ctx, ownerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	migrateP7Authorization(t, ctx, admin)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	identity := fixtureRequestIdentity(t)
	identity.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	foreign := "pid_79000002-0000-4000-8000-000000000002"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Controls','controls.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Controls')`, o, w)
	for _, env := range []string{e, foreign} {
		exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,$3,'production')`, o, w, env)
		days := 30
		if env == foreign {
			days = 999
		}
		exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',$4,true)`, o, w, env, days)
	}
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-controls80','member-controls80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Controls','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('controls80-credential','sha256'),'session-controls80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	config, _ := pgxpool.ParseConfig(dsn)
	config.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	reconcile := func() {
		t.Helper()
		if _, err := authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	// Root-authorized probe in this disposable cluster only. Keep a separate
	// privileged connection until the original owner attributes are restored.
	var priorSuper, priorBypass bool
	if err := admin.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&priorSuper, &priorBypass); err != nil {
		t.Fatal(err)
	}
	defer func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		super, bypass := "NOSUPERUSER", "NOBYPASSRLS"
		if priorSuper {
			super = "SUPERUSER"
		}
		if priorBypass {
			bypass = "BYPASSRLS"
		}
		if _, err := probe.Exec(restoreCtx, `ALTER ROLE zasp_e2e `+super+` `+bypass); err != nil {
			t.Errorf("disposable owner restoration: %v", err)
		} else {
			var restored bool
			if err := admin.QueryRow(restoreCtx, `SELECT rolsuper=$1 AND rolbypassrls=$2 FROM pg_roles WHERE rolname=session_user`, priorSuper, priorBypass).Scan(&restored); err != nil || !restored {
				t.Errorf("owner restoration verification=%v %v", restored, err)
			} else {
				t.Log("restored disposable registered owner's original role attributes")
			}
		}
	}()
	if _, err := probe.Exec(ctx, `ALTER ROLE zasp_e2e NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var noBypass bool
	if err := admin.QueryRow(ctx, `SELECT session_user='zasp_e2e' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&noBypass); err != nil || !noBypass {
		t.Fatalf("registered owner non-superuser admission=%v %v", noBypass, err)
	}
	t.Log("committed disposable registered owner demotion; original session_user/current_user=zasp_e2e, NOSUPERUSER NOBYPASSRLS")
	t.Run("registered API cannot use proofless raw CRUD or assume owner", func(t *testing.T) {
		var count int
		if err := api.QueryRow(ctx, `SELECT count(*) FROM zasp_data_controls`).Scan(&count); err == nil && count != 0 {
			t.Errorf("proofless raw SELECT disclosed %d rows", count)
		}
		for _, q := range []string{`UPDATE zasp_data_controls SET retention_days=retention_days+1 RETURNING environment_id`, `DELETE FROM zasp_data_controls RETURNING environment_id`, `INSERT INTO zasp_data_controls SELECT organization_id,workspace_id,'pid_79000009-0000-4000-8000-000000000009',environment_class,collection_mode,retention_days,deletion_enabled,version,migration_seeded,updated_at FROM zasp_data_controls LIMIT 1 RETURNING environment_id`} {
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := tx.Query(ctx, q)
			exposed := false
			if err == nil {
				exposed = rows.Next()
				rows.Close()
			}
			tx.Rollback(ctx)
			if exposed {
				t.Errorf("proofless raw CRUD accepted: %s", q)
			}
		}
		for _, role := range []string{"zasp_e2e", "zasp_discovery_authority"} {
			if _, err := api.Exec(ctx, `SET ROLE `+role); err == nil {
				api.Exec(ctx, `RESET ROLE`)
				t.Errorf("API assumed %s", role)
			}
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,'pid_79000009-0000-4000-8000-000000000009','production','metadata_only',30,true)`, o, w)
		tx.Rollback(ctx)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("raw VALUES INSERT rejection=%v", err)
		}
	})
	t.Run("retained owner seed and compliance helper", func(t *testing.T) {
		// Exercise the actual non-superuser owner policy and source56 reader.
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var boundOwner bool
		if err = tx.QueryRow(ctx, `SELECT c.relowner=current_user::regrole AND p.proowner=c.relowner FROM pg_class c JOIN pg_proc p ON p.oid='public.zasp_compliance_configuration(text,text,text)'::regprocedure WHERE c.oid='public.zasp_data_controls'::regclass`).Scan(&boundOwner); err != nil || !boundOwner {
			t.Fatalf("owner/helper binding: %v %v", boundOwner, err)
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM public.zasp_compliance_configuration($1,$2,$3)`, o, w, e).Scan(&count); err != nil || count != 1 {
			t.Fatalf("retained configuration helper=%d %v", count, err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,'pid_79000009-0000-4000-8000-000000000009','development','metadata_only',30,true)`, o, w); err != nil {
			t.Fatalf("owner seed rejected: %v", err)
		}
	})
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	repository, _ := NewPostgresRepository(database)
	resolver, _ := NewPostgresAuthorizationResolver(database)
	allow := true
	checker := authorizationDecisionFunc(func(_ context.Context, req authorization.CheckRequest) (authorization.Decision, error) {
		if req.ResourceType != "environment" || req.ResourceID != e || (req.Permission != "view_compliance" && req.Permission != "manage_data_controls") {
			t.Fatalf("unexpected Check target/permission: %s %s %s", req.ResourceType, req.ResourceID, req.Permission)
		}
		return authorization.Decision{Allowed: allow, ModelID: model}, nil
	})
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	identity.credentialBinding = CredentialBinding{Kind: CredentialBrowserSession, ID: "session-controls80", Digest: sha256.Sum256([]byte("controls80-credential"))}
	barrier := &sensorCheckBarrier{inner: authorizer}
	handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
	var operations []Operation
	for _, name := range []string{"getDataControls", "updateDataControls"} {
		policy, _ := authorization.LookupOperation(name)
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: policy.Method != "GET", RequireFreshAuth: policy.FreshAuth, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = barrier
	body := fmt.Sprintf(`{"environment_id":%q,"environment_class":"production","collection_mode":"metadata_only","retention_days":60,"deletion_enabled":false}`, e)
	call := func(method string, version int, change func(*httptest.ResponseRecorder, *RequestIdentity, map[string]string)) *httptest.ResponseRecorder {
		id := identity
		headers := map[string]string{"Content-Type": "application/json", expectedScopeHeader: expectedScopeValue(identity.Scope), "Origin": "https://console.example", "X-CSRF-Token": identity.CSRFToken, "If-Match": fmt.Sprintf("%q", fmt.Sprint(version))}
		response := httptest.NewRecorder()
		if change != nil {
			change(response, &id, headers)
		}
		input := ""
		if method == "PATCH" {
			input = body
		}
		request := httptest.NewRequest(method, "/api/v1/settings/data-controls", strings.NewReader(input))
		for k, v := range headers {
			request.Header.Set(k, v)
		}
		c := context.WithValue(ctx, identityContextKey{}, id)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		router.ServeHTTP(response, request.WithContext(c))
		return response
	}
	assertState := func(version, days, audits int) {
		t.Helper()
		var v, d, a int
		if err := admin.QueryRow(ctx, `SELECT version,retention_days,(SELECT count(*) FROM zasp_admin_audit WHERE action='data_controls.update') FROM zasp_data_controls WHERE environment_id=$1`, e).Scan(&v, &d, &a); err != nil || v != version || d != days || a != audits {
			t.Fatalf("effect/audit=%d/%d/%d error=%v want%d/%d/%d", v, d, a, err, version, days, audits)
		}
	}
	if !t.Run("mounted current read and fresh update", func(t *testing.T) {
		read := call("GET", 0, nil)
		var value struct {
			RetentionDays int    `json:"retention_days"`
			EnvironmentID string `json:"environment_id"`
			Version       int    `json:"version"`
		}
		if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &value) != nil || value.RetentionDays != 30 || value.EnvironmentID != e || value.Version != 1 || strings.Contains(read.Body.String(), "999") {
			t.Fatalf("read status=%d body=%s", read.Code, read.Body.String())
		}
		update := call("PATCH", 1, nil)
		if update.Code != 200 {
			t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
		}
		assertState(2, 60, 1)
		var matched bool
		if err := admin.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_admin_audit WHERE (organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome)=($1,$2,$3,$4,'data_controls.update',$3,'succeeded') AND metadata='{"collection_mode":"metadata_only","retention_days":"60"}'::jsonb`, o, w, e, p).Scan(&matched); err != nil || !matched {
			t.Fatalf("audit mismatch %v %v", matched, err)
		}
		if response := call("PATCH", 1, nil); response.Code != 409 {
			t.Fatalf("precondition status=%d", response.Code)
		}
		assertState(2, 60, 1)
	}) {
		return
	}
	t.Run("deny permission bearer stale scope CSRF and freshness", func(t *testing.T) {
		allow = false
		for _, method := range []string{"GET", "PATCH"} {
			if r := call(method, 2, nil); r.Code != 403 {
				t.Fatalf("denied %s status=%d", method, r.Code)
			}
		}
		allow = true
		if r := call("GET", 0, func(_ *httptest.ResponseRecorder, id *RequestIdentity, _ map[string]string) {
			id.FreshAuthenticated = false
		}); r.Code != 200 {
			t.Fatalf("read incorrectly requires fresh authentication: %d", r.Code)
		}
		for _, tc := range []struct {
			name   string
			change func(*httptest.ResponseRecorder, *RequestIdentity, map[string]string)
		}{
			{"PAT", func(_ *httptest.ResponseRecorder, id *RequestIdentity, h map[string]string) {
				id.CredentialKind = CredentialBearerToken
			}},
			{"scope", func(_ *httptest.ResponseRecorder, id *RequestIdentity, h map[string]string) {
				h[expectedScopeHeader] = "foreign"
			}},
			{"CSRF", func(_ *httptest.ResponseRecorder, id *RequestIdentity, h map[string]string) {
				h["X-CSRF-Token"] = "wrong"
			}},
			{"freshness", func(_ *httptest.ResponseRecorder, id *RequestIdentity, h map[string]string) {
				id.FreshAuthenticated = false
			}},
		} {
			r := call("PATCH", 2, tc.change)
			if r.Code < 400 || r.Code >= 500 {
				t.Fatalf("%s status=%d", tc.name, r.Code)
			}
		}
		assertState(2, 60, 1)
	})
	t.Run("current credential and revision rollback then fresh Check retry", func(t *testing.T) {
		barrier.after = func() {
			exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-controls80'`)
		}
		response := call("PATCH", 2, nil)
		barrier.after = nil
		exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-controls80'`)
		if response.Code != 409 {
			t.Fatalf("revoked status=%d", response.Code)
		}
		assertState(2, 60, 1)
		mutation := administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 90, DeletionEnabled: true, ExpectedVersion: 2, EnvironmentClass: "production", AuditID: "pid_79000003-0000-4000-8000-000000000003"}
		for _, change := range []string{
			`UPDATE zasp_product_sessions SET environment_id='` + foreign + `' WHERE session_id='session-controls80'`,
			`UPDATE zasp_product_sessions SET csrf_token=repeat('y',32) WHERE session_id='session-controls80'`,
			`UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 day' WHERE session_id='session-controls80'`,
		} {
			barrier.after = func() { exec(change); reconcile() }
			r := call("PATCH", 2, nil)
			barrier.after = nil
			exec(`UPDATE zasp_product_sessions SET environment_id=$1,csrf_token=repeat('x',32),authenticated_at=clock_timestamp() WHERE session_id='session-controls80'`, e)
			reconcile()
			if r.Code != 409 {
				t.Fatalf("current browser binding drift status=%d", r.Code)
			}
			assertState(2, 60, 1)
		}
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "updateDataControls"})
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$1`, p)
		reconcile()
		if _, err := repository.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), identity, mutation); err == nil {
			t.Fatal("stale revision accepted")
		}
		assertState(2, 60, 1)
		grant, err = authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "updateDataControls"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), identity, mutation); err != nil {
			t.Fatal(err)
		}
		assertState(3, 90, 2)
	})
	t.Run("direct native operation environment actor and permission binding", func(t *testing.T) {
		for _, tc := range []struct{ name, op, target, actor string }{
			{"read proof cannot update", "getDataControls", e, p}, {"foreign environment", "updateDataControls", foreign, p}, {"wrong actor", "updateDataControls", e, "pid_79000004-0000-4000-8000-000000000004"},
		} {
			grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: tc.op})
			if err != nil {
				t.Fatal(err)
			}
			proof, err := authorizationProofJSON(grant)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
				tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SELECT zasp_authorization80.update_data_controls($1,$2,$3,'metadata_only',120,true,3,'production',$4,$5)`, o, w, tc.target, "pid_79000005-0000-4000-8000-000000000005", tc.actor)
			tx.Rollback(ctx)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "42501" {
				t.Fatalf("%s rejection=%v", tc.name, err)
			}
		}
		assertState(3, 90, 2)
		if _, err := api.Exec(ctx, `SELECT zasp_authorization80.get_data_controls($1,$2,$3)`, o, w, e); err == nil {
			t.Fatal("missing proof disclosed controls")
		}
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "getDataControls"})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := authorizationProofJSON(grant)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		var rawCount int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM zasp_data_controls`).Scan(&rawCount); err != nil || rawCount != 0 {
			t.Fatalf("checked proof enabled raw table reads: %d %v", rawCount, err)
		}
		_, err = tx.Exec(ctx, `SELECT zasp_authorization80.get_data_controls($1,$2,$3)`, o, w, foreign)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("foreign native read rejection=%v", err)
		}
	})
	t.Run("native validation conflict and audit failure remain atomic", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			days         int
			class, audit string
		}{
			{"class precondition", 120, "development", "pid_79000006-0000-4000-8000-000000000006"},
			{"retention validation", 0, "production", "pid_79000006-0000-4000-8000-000000000006"},
			{"audit collision", 120, "production", "pid_79000003-0000-4000-8000-000000000003"},
		} {
			grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "updateDataControls"})
			if err != nil {
				t.Fatal(err)
			}
			m := administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: tc.days, DeletionEnabled: true, ExpectedVersion: 3, EnvironmentClass: tc.class, AuditID: tc.audit}
			if _, err = repository.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), identity, m); err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			assertState(3, 90, 2)
		}
	})
	t.Run("source identity security and canonical pins fail closed", func(t *testing.T) {
		for _, tc := range []struct{ name, change, restore string }{
			{"source7 checksum", `UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=7`, `UPDATE zasp_schema_versions SET checksum='aaeb8cc70a5a6dec76496e4c0f49aa4311dea32b6a1d416eae00d1f07431d0d6' WHERE version=7`},
			{"source RLS", `ALTER TABLE zasp_data_controls DISABLE ROW LEVEL SECURITY`, `ALTER TABLE zasp_data_controls ENABLE ROW LEVEL SECURITY`},
			{"source ACL", `GRANT SELECT ON zasp_data_controls TO PUBLIC`, `REVOKE SELECT ON zasp_data_controls FROM PUBLIC`},
		} {
			exec(tc.change)
			r := call("PATCH", 3, nil)
			exec(tc.restore)
			if r.Code < 400 {
				t.Fatalf("%s accepted", tc.name)
			}
			assertState(3, 90, 2)
		}
		var checksum string
		if err := admin.QueryRow(ctx, `SELECT checksum FROM zasp_schema_versions WHERE version=61`).Scan(&checksum); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`)
		r := call("PATCH", 3, nil)
		exec(`UPDATE zasp_schema_versions SET checksum=$1 WHERE version=61`, checksum)
		if r.Code < 400 {
			t.Fatal("canonical drift accepted")
		}
		assertState(3, 90, 2)
		if r := call("GET", 0, nil); r.Code != 200 {
			t.Fatalf("restoration status=%d", r.Code)
		}
	})
	// Confirm the foreign scope stayed untouched, not just absent from JSON.
	var foreignDays int
	if err := admin.QueryRow(ctx, `SELECT retention_days FROM zasp_data_controls WHERE environment_id=$1`, foreign).Scan(&foreignDays); err != nil || foreignDays != 999 {
		t.Fatalf("foreign controls changed %d %v", foreignDays, err)
	}
}
