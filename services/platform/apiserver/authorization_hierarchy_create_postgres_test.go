package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Actual FGA Check, canonical migrations and registered API/outbox sessions.
// The signer and browser credential are controlled; no live Stytch/deployment claim.
func TestP7HierarchyCreatePostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	bootstrapDSN := startDisposablePostgresAs(t, "zasp_test")
	bootstrap, err := pgx.Connect(ctx, bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close(context.Background())
	if _, err = bootstrap.Exec(ctx, `CREATE ROLE zasp_e2e LOGIN SUPERUSER`); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "zasp_e2e"
	owner, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const foreign = "pid_78000009-0000-4000-8000-000000000009"
	const foreignEnvironment = "pid_78000007-0000-4000-8000-000000000007"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Hierarchy','hierarchy.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Selected'),($1,$3,'Foreign')`, o, w, foreign)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production'),($1,$4,$5,'Foreign','production')`, o, w, e, foreign, foreignEnvironment)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-hierarchy80','member-hierarchy80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('hierarchy80-session','sha256'),'session-hierarchy80',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'production','metadata_only',30,true)`, o, w, e)
	exec(`INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,'session_bootstrap:'||$4,'{}')`, o, w, e, p)
	pc, err := pgxpool.ParseConfig(config.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	client, fgaConfig := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, fgaConfig)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, fgaConfig)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, fgaConfig.StoreID, fgaConfig.ModelID)
	reconcile := func() {
		t.Helper()
		receipt, err := authorization.Reconcile(ctx, projection, writer, o, fgaConfig.StoreID, fgaConfig.ModelID)
		if err != nil || !receipt.Applied {
			t.Fatalf("reconcile=%+v %v", receipt, err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, config.ConnString(), "auth80_api")
	defer api.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewPostgresRepository(db)
	i, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "hierarchy80-session"})
	if err != nil {
		t.Fatal(err)
	}
	if len(i.Permissions) != 0 {
		t.Fatal("current identity carries legacy permissions")
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	a := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: fgaConfig.StoreID, ModelID: fgaConfig.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	barrier := &sensorCheckBarrier{inner: a}
	handler := &identityHTTPHandler{administration: repo, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
	var ops []Operation
	for _, op := range []string{"createWorkspace", "createEnvironment"} {
		policy, _ := authorization.LookupOperation(op)
		ops = append(ops, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: op, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: true, RequireFreshAuth: true, Handler: handler})
	}
	router, err := NewRouter(ops)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = barrier
	// Only this owned disposable cluster is demoted. Restore through bootstrap,
	// verify using the original registered owner session, then join cluster cleanup.
	var priorSuper, priorBypass bool
	if err = owner.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&priorSuper, &priorBypass); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		super, bypass := "NOSUPERUSER", "NOBYPASSRLS"
		if priorSuper {
			super = "SUPERUSER"
		}
		if priorBypass {
			bypass = "BYPASSRLS"
		}
		if _, err := bootstrap.Exec(c, `ALTER ROLE zasp_e2e `+super+` `+bypass); err != nil {
			t.Error(err)
			return
		}
		var ok bool
		if err := owner.QueryRow(c, `SELECT rolsuper=$1 AND rolbypassrls=$2 FROM pg_roles WHERE rolname=session_user`, priorSuper, priorBypass).Scan(&ok); err != nil || !ok {
			t.Errorf("owner restoration=%v %v", ok, err)
		} else {
			t.Log("restored disposable registered owner role attributes")
		}
	}()
	if _, err = bootstrap.Exec(ctx, `ALTER ROLE zasp_e2e NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	var ownerBound bool
	if err = owner.QueryRow(ctx, `SELECT session_user='zasp_e2e' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&ownerBound); err != nil || !ownerBound {
		t.Fatalf("nonsuper owner=%v %v", ownerBound, err)
	}
	t.Log("committed owner demotion; original session_user/current_user=zasp_e2e NOSUPERUSER NOBYPASSRLS")
	sequence := 100
	id := func() string { sequence++; return fmt.Sprintf("pid_78000000-0000-4000-8000-%012d", sequence) }
	mutation := func(op string) administrationMutation {
		return administrationMutation{Operation: op, ID: id(), InitialEnvironmentID: id(), AuditID: id(), WorkspaceID: w, Name: fmt.Sprintf("Created %d", sequence)}
	}
	grant := func(op string) RequestAuthorization {
		t.Helper()
		g, err := a.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: op})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	mutate := func(m administrationMutation) (json.RawMessage, error) {
		g := grant(m.Operation)
		return repo.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, m)
	}
	call := func(op, name, workspace string, change func(*RequestIdentity, map[string]string)) *httptest.ResponseRecorder {
		identity := i
		headers := map[string]string{"Content-Type": "application/json", expectedScopeHeader: expectedScopeValue(i.Scope), "Origin": "https://console.example", "X-CSRF-Token": i.CSRFToken}
		if change != nil {
			change(&identity, headers)
		}
		path, body := "/api/v1/workspaces", fmt.Sprintf(`{"name":%q}`, name)
		if op == "createEnvironment" {
			path = "/api/v1/environments"
			body = fmt.Sprintf(`{"name":%q,"workspace_id":%q}`, name, workspace)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		c := context.WithValue(ctx, identityContextKey{}, identity)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, r.WithContext(c))
		return response
	}
	// Snapshot all effect families plus revision; failed writes must roll back even
	// source79 BEFORE triggers. Test fixtures themselves are outside snapshots.
	state := func() string {
		t.Helper()
		var result string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM zasp_workspaces),(SELECT count(*) FROM zasp_environments),(SELECT count(*) FROM zasp_authorized_scopes),(SELECT count(*) FROM zasp_core_payloads),(SELECT count(*) FROM zasp_data_controls),(SELECT count(*) FROM zasp_admin_audit),(SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1))::text`, o).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	unchanged := func(before string) {
		t.Helper()
		if after := state(); before != after {
			t.Fatalf("partial effects before=%s after=%s", before, after)
		}
	}
	check := func(workspace, environment, permission string, want bool) {
		t.Helper()
		d, err := checker.Check(ctx, authorization.CheckRequest{OrganizationID: o, WorkspaceID: workspace, EnvironmentID: environment, ResourceType: "environment", ResourceID: environment, PrincipalKind: "user", PrincipalID: p, Permission: permission})
		if err != nil || d.Allowed != want {
			t.Fatalf("Check %s on %s=%v want%v %v", permission, environment, d.Allowed, want, err)
		}
	}
	effects := func(m administrationMutation, body []byte) {
		t.Helper()
		var got map[string]any
		if json.Unmarshal(body, &got) != nil {
			t.Fatalf("invalid response %s", body)
		}
		nw, ne, envName, action, aw, ae, target, metadata := w, m.ID, m.Name, "environment.create", w, m.ID, m.ID, `{}`
		if m.Operation == "createWorkspace" {
			nw, ne, envName, action, aw, ae, target = m.ID, m.InitialEnvironmentID, "Development", "workspace.onboard", w, e, m.ID
			metadata = fmt.Sprintf(`{"initial_environment_id":%q}`, ne)
			if got["initial_environment_id"] != ne {
				t.Fatalf("initial environment response=%s", body)
			}
		} else if got["workspace_id"] != w || got["environment_class"] != "development" {
			t.Fatalf("environment response=%s", body)
		}
		if got["id"] != m.ID || got["organization_id"] != o || got["name"] != m.Name || got["version"] != float64(1) || got["audit_correlation_id"] != m.AuditID {
			t.Fatalf("response identity=%s", body)
		}
		var ok bool
		err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_workspaces WHERE organization_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2 AND id=$3 AND name=$4 AND environment_class='development' AND version=1) AND EXISTS(SELECT 1 FROM zasp_authorized_scopes WHERE principal_id=$5 AND organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND permissions='[]'::jsonb AND NOT is_default) AND EXISTS(SELECT 1 FROM zasp_core_payloads WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND operation='session_bootstrap:'||$5 AND payload=jsonb_build_object('correlation_id',$6::text)) AND EXISTS(SELECT 1 FROM zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND environment_class='development' AND collection_mode='metadata_only' AND retention_days=30 AND deletion_enabled AND version=1) AND EXISTS(SELECT 1 FROM zasp_admin_audit WHERE organization_id=$1 AND workspace_id=$7 AND environment_id=$8 AND id=$6 AND actor_id=$5 AND action=$9 AND target_id=$10 AND outcome='succeeded' AND metadata=$11::jsonb) AND EXISTS(SELECT 1 FROM zasp_authorized_scopes WHERE principal_id=$5 AND organization_id=$1 AND workspace_id=$12 AND environment_id=$13 AND is_default) AND EXISTS(SELECT 1 FROM zasp_product_sessions WHERE session_id='session-hierarchy80' AND workspace_id=$12 AND environment_id=$13)`, o, nw, ne, envName, p, m.AuditID, aw, ae, action, target, metadata, w, e).Scan(&ok)
		if err != nil || !ok {
			t.Fatalf("atomic hierarchy/grant/bootstrap/control/audit/default/session effects=%v %v", ok, err)
		}
		if strings.Contains(string(body), "credential") || strings.Contains(string(body), "csrf") {
			t.Fatal("secret metadata in response")
		}
	}
	t.Run("registered API raw hierarchy writes are refused before any effect", func(t *testing.T) {
		for _, tc := range []struct{ table, insert, update, remove string }{
			{"zasp_workspaces", `INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Raw workspace')`, `UPDATE zasp_workspaces SET name='Raw renamed' WHERE organization_id=$1 AND id=$2`, `DELETE FROM zasp_workspaces WHERE organization_id=$1 AND id=$2`},
			{"zasp_environments", `INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,'pid_78000008-0000-4000-8000-000000000008','Raw environment','development')`, `UPDATE zasp_environments SET name='Raw renamed' WHERE organization_id=$1 AND workspace_id=$2`, `DELETE FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2`},
			{"zasp_authorized_scopes", `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES('pid_78000008-0000-4000-8000-000000000008',$1,$2,'pid_78000008-0000-4000-8000-000000000008','Raw scope','[]')`, `UPDATE zasp_authorized_scopes SET label='Raw renamed' WHERE organization_id=$1 AND workspace_id=$2`, `DELETE FROM zasp_authorized_scopes WHERE organization_id=$1 AND workspace_id=$2`},
			{"zasp_core_payloads", `INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,'pid_78000008-0000-4000-8000-000000000008','session_bootstrap:raw','{}')`, `UPDATE zasp_core_payloads SET payload='{"raw":true}' WHERE organization_id=$1 AND workspace_id=$2`, `DELETE FROM zasp_core_payloads WHERE organization_id=$1 AND workspace_id=$2`},
		} {
			for _, q := range []string{tc.insert, tc.update, tc.remove, `TRUNCATE public.` + tc.table} {
				before := state()
				tx, err := api.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var args []any
				if !strings.HasPrefix(q, "TRUNCATE") {
					args = []any{o, w}
					if q == tc.insert && tc.table == "zasp_workspaces" {
						args[1] = id()
					}
				}
				_, err = tx.Exec(ctx, q, args...)
				tx.Rollback(ctx)
				var pe *pgconn.PgError
				if !errors.As(err, &pe) || pe.Code != "42501" {
					t.Errorf("raw %s rejection=%v", q, err)
				}
				unchanged(before)
			}
			var retainedRead, noTruncate bool
			if err := api.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,'SELECT'),NOT has_table_privilege(current_user,$1,'TRUNCATE')`, "public."+tc.table).Scan(&retainedRead, &noTruncate); err != nil || !retainedRead || !noTruncate {
				t.Fatalf("%s SELECT/TRUNCATE privileges=%v/%v %v", tc.table, retainedRead, noTruncate, err)
			}
		}
	})
	if !t.Run("mounted fresh browser creates both hierarchies and leaves projection pending", func(t *testing.T) {
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			name := "Mounted " + op
			r := call(op, name, w, nil)
			if r.Code != 201 || r.Header().Get("ETag") != `"1"` {
				t.Fatalf("%s status=%d etag=%q body=%s", op, r.Code, r.Header().Get("ETag"), r.Body.String())
			}
			var v struct {
				ID      string `json:"id"`
				Initial string `json:"initial_environment_id"`
				Audit   string `json:"audit_correlation_id"`
			}
			if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			m := administrationMutation{Operation: op, ID: v.ID, InitialEnvironmentID: v.Initial, AuditID: v.Audit, Name: name}
			effects(m, r.Body.Bytes())
			if _, err := a.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: op}); !errors.Is(err, authorization.ErrPending) {
				t.Fatalf("committed create did not block pending projection: %v", err)
			}
			reconcile()
			nw, ne := w, v.ID
			if op == "createWorkspace" {
				nw, ne = v.ID, v.Initial
			}
			check(nw, ne, "manage_identity", true)
			check(foreign, foreignEnvironment, "manage_identity", false)
		}
	}) {
		return
	}
	t.Run("ordinary member denial and scoped admin role derivation", func(t *testing.T) {
		exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=$1`, p)
		reconcile()
		before := state()
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			if r := call(op, "Denied", w, nil); r.Code != 403 {
				t.Fatalf("ordinary member %s=%d", op, r.Code)
			}
		}
		unchanged(before)
		exec(`UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1`, p)
		reconcile()
		m := mutation("createWorkspace")
		body, err := mutate(m)
		if err != nil {
			t.Fatal(err)
		}
		effects(m, body)
		reconcile()
		check(m.ID, m.InitialEnvironmentID, "manage_identity", true)
		exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=$1`, p)
		exec(`INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-hierarchy','security_admin',$2,$3)`, o, w, e)
		var resolved []byte
		if err := api.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-hierarchy80','member-hierarchy80','["scim-group-test-hierarchy"]'::jsonb)`).Scan(&resolved); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_product_sessions SET revoked_at=NULL,authenticated_at=clock_timestamp() WHERE session_id='session-hierarchy80'`)
		reconcile()
		check(w, e, "manage_identity", true)
		m = mutation("createEnvironment")
		body, err = mutate(m)
		if err != nil {
			t.Fatal(err)
		}
		effects(m, body)
		reconcile()
		check(w, m.ID, "view", true)
		check(w, m.ID, "manage_identity", false)
		exec(`DELETE FROM zasp_authorized_scopes WHERE principal_id=$1 AND organization_id=$2 AND workspace_id=$3 AND environment_id=$4`, p, o, w, e)
		reconcile()
		check(w, e, "manage_identity", true)
		before = state()
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			m = mutation(op)
			if _, err = mutate(m); err == nil {
				t.Fatalf("group-only %s admitted without direct row", op)
			}
		}
		unchanged(before)
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, p, o, w, e)
		exec(`UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$1`, p)
		reconcile()
	})
	t.Run("mounted PAT CSRF freshness selected scope and foreign workspace refusals", func(t *testing.T) {
		before := state()
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			for _, change := range []func(*RequestIdentity, map[string]string){func(i *RequestIdentity, h map[string]string) { i.CredentialKind = CredentialBearerToken }, func(i *RequestIdentity, h map[string]string) { i.FreshAuthenticated = false }, func(i *RequestIdentity, h map[string]string) { h["X-CSRF-Token"] = "wrong" }, func(i *RequestIdentity, h map[string]string) { h[expectedScopeHeader] = "wrong" }} {
				if r := call(op, "Denied boundary", w, change); r.Code < 400 || r.Code >= 500 {
					t.Fatalf("%s boundary status=%d", op, r.Code)
				}
			}
		}
		if r := call("createEnvironment", "Foreign", foreign, nil); r.Code != 404 {
			t.Fatalf("foreign workspace status=%d", r.Code)
		}
		unchanged(before)
	})
	t.Run("stale credential and revision refuse then fresh Check reuses prepared IDs", func(t *testing.T) {
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			m := mutation(op)
			g := grant(op)
			exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-hierarchy80'`)
			before := state()
			if _, err := repo.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, m); err == nil {
				t.Fatal("revoked credential admitted")
			}
			unchanged(before)
			exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-hierarchy80'`)
			g = grant(op)
			exec(`UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1`, p)
			reconcile()
			before = state()
			if _, err := repo.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, m); err == nil {
				t.Fatal("stale revision admitted")
			}
			unchanged(before)
			body, err := mutate(m)
			if err != nil {
				t.Fatal(err)
			}
			effects(m, body)
			reconcile()
			exec(`UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$1`, p)
			reconcile()
		}
	})
	t.Run("native proof purpose actor target and inert array are mandatory", func(t *testing.T) {
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			for _, bad := range []string{"proofless", "operation", "actor", "organization", "environment", "permissions", "null", "requested_workspace"} {
				if bad == "requested_workspace" && op == "createWorkspace" {
					continue
				}
				m := mutation(op)
				q := postgresCreateEnvironmentCurrentSQL
				args := []any{m.ID, o, w, m.Name, m.AuditID, p, w, e, []byte("[]")}
				if op == "createWorkspace" {
					q = postgresCreateWorkspaceCurrentSQL
					args = []any{m.ID, o, m.Name, w, e, m.AuditID, p, m.InitialEnvironmentID, []byte("[]")}
				}
				proofOp := op
				if bad == "operation" {
					proofOp = "getDataControls"
				}
				g := grant(proofOp)
				proof, err := authorizationProofJSON(g)
				if err != nil {
					t.Fatal(err)
				}
				switch bad {
				case "actor":
					if op == "createWorkspace" {
						args[6] = foreign
					} else {
						args[5] = foreign
					}
				case "organization":
					args[1] = foreign
				case "environment":
					if op == "createWorkspace" {
						args[4] = foreign
					} else {
						args[7] = foreign
					}
				case "permissions":
					args[8] = []byte(`["manage_identity"]`)
				case "null":
					args[8] = []byte(`null`)
				case "requested_workspace":
					args[2] = foreign
				}
				before := state()
				tx, err := api.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if bad != "proofless" {
					if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
						tx.Rollback(ctx)
						t.Fatal(err)
					}
				}
				_, err = tx.Exec(ctx, q, args...)
				tx.Rollback(ctx)
				var pe *pgconn.PgError
				if !errors.As(err, &pe) || (pe.Code != "42501" && pe.Code != "22023" && pe.Code != "P0002") {
					t.Fatalf("native %s/%s refused incorrectly: %v", op, bad, err)
				}
				unchanged(before)
			}
		}
	})
	t.Run("late audit failure and duplicate IDs or names roll back every effect", func(t *testing.T) {
		for _, op := range []string{"createWorkspace", "createEnvironment"} {
			m := mutation(op)
			aw, ae := w, m.ID
			if op == "createWorkspace" {
				ae = e
			}
			exec(`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,$4,$5,'fixture.collision',$6,'succeeded','{}')`, o, aw, ae, m.AuditID, p, m.ID)
			before := state()
			if _, err := mutate(m); err == nil {
				t.Fatal("audit collision accepted")
			}
			unchanged(before)
			exec(`DELETE FROM zasp_admin_audit WHERE id=$1`, m.AuditID)
			body, err := mutate(m)
			if err != nil {
				t.Fatal(err)
			}
			effects(m, body)
			reconcile()
			for _, duplicate := range []administrationMutation{m, func() administrationMutation { next := mutation(op); next.Name = m.Name; return next }()} {
				before = state()
				if _, err := mutate(duplicate); err == nil {
					t.Fatal("duplicate accepted")
				}
				unchanged(before)
			}
		}
	})
	t.Run("new scope stays unusable until reconciliation and current stored selection", func(t *testing.T) {
		m := mutation("createEnvironment")
		body, err := mutate(m)
		if err != nil {
			t.Fatal(err)
		}
		effects(m, body)
		scoped := i
		environmentID, err := domain.ParseProductID(m.ID)
		if err != nil {
			t.Fatal(err)
		}
		scoped.Scope, err = domain.NewScope(i.Scope.OrganizationID(), i.Scope.WorkspaceID(), environmentID)
		if err != nil {
			t.Fatal(err)
		}
		// Use an already admitted selected-scope reader. getEnvironment remains
		// an unrelated unsupported statement and cannot prove the native fence.
		route := RoutedOperation{OperationID: "getDataControls"}
		if _, err = a.Authorize(ctx, scoped, scoped.credentialBinding, route); !errors.Is(err, authorization.ErrPending) {
			t.Fatalf("new scope pending admission=%v", err)
		}
		reconcile()
		g, err := a.Authorize(ctx, scoped, scoped.credentialBinding, route)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = repo.ReadAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), scoped, "getDataControls", nil); err == nil {
			t.Fatal("new request scope bypassed old stored session selection")
		}
		// Controlled stored selection is explicit; this is not a scope-switch endpoint test.
		exec(`UPDATE zasp_product_sessions SET environment_id=$1 WHERE session_id='session-hierarchy80'`, m.ID)
		reconcile()
		selected, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "hierarchy80-session"})
		if err != nil {
			t.Fatal(err)
		}
		g, err = a.Authorize(ctx, selected, selected.credentialBinding, route)
		if err != nil {
			t.Fatal(err)
		}
		controls, err := repo.ReadAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), selected, "getDataControls", nil)
		if err != nil {
			t.Fatal(err)
		}
		var selectedControls struct {
			EnvironmentID string `json:"environment_id"`
		}
		if json.Unmarshal(controls, &selectedControls) != nil || selectedControls.EnvironmentID != m.ID {
			t.Fatalf("selected controls=%s", controls)
		}
		exec(`UPDATE zasp_product_sessions SET environment_id=$1 WHERE session_id='session-hierarchy80'`, e)
		reconcile()
	})
	t.Run("registered API raw controls and owner assumption remain closed", func(t *testing.T) {
		for _, role := range []string{"zasp_e2e", "zasp_discovery_authority"} {
			if _, err := api.Exec(ctx, `SET ROLE `+role); err == nil {
				api.Exec(ctx, `RESET ROLE`)
				t.Fatalf("API assumed %s", role)
			}
		}
		before := state()
		if _, err := api.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) VALUES($1,$2,$3,'development','metadata_only',30,true)`, o, w, id()); err == nil {
			t.Fatal("raw API controls INSERT accepted")
		}
		unchanged(before)
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_compliance_configuration($1,$2,$3)`, o, w, e).Scan(&count); err != nil || count != 1 {
			t.Fatalf("retained owner source56 helper=%d %v", count, err)
		}
	})
	t.Run("retained source19 deprovision and source14 owner cutover", func(t *testing.T) {
		member, audit := id(), id()
		exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-hierarchy80','member-hierarchy80-deprovision','read_only_viewer',true)`, member, o)
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Deprovision','[]',false)`, member, o, w, e)
		var response []byte
		if err := api.QueryRow(ctx, `SELECT zasp_identity_admin_reconcile_deprovision('project-hierarchy80','webhook-event-test-hierarchy80','organization-hierarchy80','member-hierarchy80-deprovision',digest('hierarchy80-deprovision','sha256'),$1)`, audit).Scan(&response); err != nil {
			t.Fatal(err)
		}
		var removed bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_authorized_scopes WHERE principal_id=$1) AND EXISTS(SELECT 1 FROM zasp_identity_memberships WHERE principal_id=$1 AND NOT active) AND EXISTS(SELECT 1 FROM zasp_admin_audit WHERE id=$2 AND action='identity.member.deprovision')`, member, audit).Scan(&removed); err != nil || !removed {
			t.Fatalf("source19 deprovision=%v %v", removed, err)
		}
		exec(`INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES($1,$2,$3,'agents','{}')`, o, w, e)
		var deleted int
		if err := owner.QueryRow(ctx, `SELECT public.zasp_core_inventory_cutover($1,$2,$3,digest(convert_to('{"agents": {}}','UTF8'),'sha256'))`, o, w, e).Scan(&deleted); err != nil || deleted != 1 {
			t.Fatalf("source14 owner cutover=%d %v", deleted, err)
		}
		reconcile()
	})
	t.Run("source pin wrapper ownership ACL and RLS drift close creation", func(t *testing.T) {
		changes := [][2]string{{`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=7`, `UPDATE zasp_schema_versions SET checksum='aaeb8cc70a5a6dec76496e4c0f49aa4311dea32b6a1d416eae00d1f07431d0d6' WHERE version=7`}, {`ALTER FUNCTION zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority`, `ALTER FUNCTION zasp_authorization80.create_workspace(text,text,text,text,text,text,text,text,jsonb) OWNER TO zasp_e2e`}, {`GRANT EXECUTE ON FUNCTION zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION zasp_authorization80.create_environment(text,text,text,text,text,text,text,text,jsonb) FROM PUBLIC`}, {`ALTER TABLE zasp_data_controls NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE zasp_data_controls FORCE ROW LEVEL SECURITY`}}
		changes = append(changes, [2]string{`ALTER TABLE zasp_workspaces DISABLE TRIGGER zasp_authorization80_hierarchy_write_guard`, `ALTER TABLE zasp_workspaces ENABLE TRIGGER zasp_authorization80_hierarchy_write_guard`}, [2]string{`ALTER FUNCTION zasp_authorization80.hierarchy_write_guard() SECURITY DEFINER`, `ALTER FUNCTION zasp_authorization80.hierarchy_write_guard() SECURITY INVOKER`})
		for _, change := range changes {
			g := grant("createWorkspace")
			m := mutation("createWorkspace")
			if _, err := bootstrap.Exec(ctx, change[0]); err != nil {
				t.Fatal(err)
			}
			before := state()
			_, callErr := repo.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, m)
			_, restoreErr := bootstrap.Exec(ctx, change[1])
			if restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if callErr == nil {
				t.Fatalf("source drift accepted: %s", change[0])
			}
			unchanged(before)
		}
	})
}
