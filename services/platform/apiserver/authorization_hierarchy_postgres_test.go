package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7HierarchyAuthorizationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	admin, err := pgx.Connect(ctx, dsn)
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
	i := fixtureRequestIdentity(t)
	i.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	other := "pid_89700001-0000-4000-8000-000000000001"
	envs := []string{"pid_89700002-0000-4000-8000-000000000002", "pid_89700003-0000-4000-8000-000000000003", "pid_89700004-0000-4000-8000-000000000004"}
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Hierarchy','hierarchy80.invalid')`, o)
	for _, id := range []string{w, other} {
		exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,$2)`, o, id)
	}
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-hierarchy80','member-hierarchy80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','["view"]',true)`, p, o, w, e)
	for _, id := range envs {
		exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,$3,'production')`, o, other, id)
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Other','["view"]')`, p, o, other, id)
	}
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('hierarchy80-credential','sha256'),'session-hierarchy80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	db.currentAuthorization = true
	repo := &PostgresRepository{database: db, currentAuthorization: true}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	allow := map[string]bool{other: true, envs[1]: true, envs[2]: true}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: authorizationDecisionFixture{allow: allow, model: model}, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-hierarchy80", Digest: sha256.Sum256([]byte("hierarchy80-credential"))}
	i.credentialBinding = credential
	getGrant := func(t *testing.T, workspace string) RequestAuthorization {
		t.Helper()
		c := context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{"workspace_id": {workspace}})
		g, err := authorizer.Authorize(c, i, credential, RoutedOperation{OperationID: "listEnvironments"})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	t.Run("mounted other workspace filtered before pagination", func(t *testing.T) {
		policy, _ := authorization.LookupOperation("listEnvironments")
		handler := &identityHTTPHandler{administration: repo, signingKey: []byte(strings.Repeat("h", 32)), now: time.Now}
		router, err := NewRouter([]Operation{{Method: policy.Method, Pattern: policy.Path, OperationID: policy.ID, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, Handler: handler}})
		if err != nil {
			t.Fatal(err)
		}
		router.(*operationRouter).authorizer = authorizer
		request := httptest.NewRequest(http.MethodGet, "/api/v1/environments?workspace_id="+other+"&limit=1", nil)
		request.Header.Set(expectedScopeHeader, expectedScopeValue(i.Scope))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(context.WithValue(ctx, identityContextKey{}, i)))
		var body struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Items) != 1 || body.Items[0].ID != envs[1] {
			t.Fatalf("mounted hierarchy status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("empty permitted request and sibling statement denial", func(t *testing.T) {
		g := getGrant(t, w)
		c := context.WithValue(ctx, requestAuthorizationContextKey{}, g)
		body, err := repo.ReadAdministration(c, i, "listEnvironments", map[string]string{"workspace_id": w, "limit": "1"})
		if err != nil || string(body) != `{"items": []}` && string(body) != `{"items":[]}` {
			t.Fatalf("empty current page=%s error=%v", body, err)
		}
		if _, err := repo.ReadAdministration(c, i, "listEnvironments", map[string]string{"workspace_id": other, "limit": "1"}); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("sibling adapter request=%v", err)
		}
		proof, err := authorizationProofJSON(g)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,'',2)`, o, other, p)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("native sibling selector=%v", err)
		}
	})
	t.Run("changed hierarchy revision denies old request", func(t *testing.T) {
		g := getGrant(t, other)
		exec(`UPDATE zasp_authorized_scopes SET permissions='["view","view_audit"]' WHERE principal_id=$1 AND environment_id=$2`, p, envs[1])
		_, err := repo.ReadAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, "listEnvironments", map[string]string{"workspace_id": other, "limit": "1"})
		if !errors.Is(err, ErrRepositoryConflict) {
			t.Fatalf("old hierarchy revision used: %v", err)
		}
	})
}
