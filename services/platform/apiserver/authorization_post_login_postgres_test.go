package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type postLoginUnusedHandler struct{ domain byte }

func (*postLoginUnusedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }

type postLoginRoundTripper func(*http.Request) (*http.Response, error)

func (f postLoginRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type postLoginRaceAuthorizer struct {
	*OpenFGAAuthorizer
	after func()
}

func (a *postLoginRaceAuthorizer) preparePostLogin(c context.Context, i RequestIdentity, r RoutedOperation) (postLoginAuthorization, error) {
	g, e := a.OpenFGAAuthorizer.preparePostLogin(c, i, r)
	if e == nil {
		a.after()
	}
	return g, e
}

// Catches a missing native self-read admission after a genuinely issued cookie.
// The provider is controlled local HTTP; PostgreSQL and OpenFGA are actual.
func TestP7PostLoginMountedPostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA")
	}
	runIdentityVerifiedProviderFixture(t, func(ctx context.Context, dsn string, owner, api *pgx.Conn, db *PostgresJSONDatabase, repo *PostgresRepository, provider *RepositoryIdentityProvider, start func() string) {
		var outage atomic.Bool
		var checks atomic.Int32
		modelPin := ""
		client, config := newAuthorizationProjectionFGA(t, func(next http.RoundTripper) http.RoundTripper {
			return postLoginRoundTripper(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/check") {
					checks.Add(1)
					if api.PgConn().TxStatus() != 'I' {
						t.Error("FGA Check ran inside API database transaction")
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					var check map[string]any
					if json.Unmarshal(body, &check) != nil || check["consistency"] != "HIGHER_CONSISTENCY" || check["authorization_model_id"] != modelPin {
						t.Error("Check lost current consistency/model binding")
					}
					if outage.Load() {
						return nil, errors.New("controlled local post-login transport outage")
					}
				}
				return next.RoundTrip(r)
			})
		})
		modelPin = config.ModelID
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := client.DeleteStore(c).Execute(); err != nil {
				t.Error("owned post-login store cleanup failed")
			}
		})
		writer, err := authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
		checker, err := authorization.NewOpenFGA(client, config)
		if err != nil {
			t.Fatal(err)
		}
		pc, _ := pgxpool.ParseConfig(dsn)
		pc.ConnConfig.User = "auth80_outbox"
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		projection, _ := authorization.NewPostgresProjectionRepository(pool)
		resolver, _ := NewPostgresAuthorizationResolver(db)
		a := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: config.StoreID, ModelID: config.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
		cookie := fixtureCookiePolicy()
		cookie.Clock = func() time.Time { return time.Now().UTC() }
		router, err := NewComposition(Dependencies{Authorizer: a, Session: &sessionHTTPHandler{repository: repo, provider: provider, cookie: cookie, deploymentMode: "saas"}, Identity: &identityHTTPHandler{repository: repo, administration: repo}, Inventory: &postLoginUnusedHandler{1}, Risk: &riskHTTPHandler{repository: repo, signingKey: cookie.WorkflowSigningKey, now: cookie.Clock}, Workflow: &postLoginUnusedHandler{3}, Connector: &postLoginUnusedHandler{4}})
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: repo.Authenticate}, router)
		if err != nil {
			t.Fatal(err)
		}
		callback := httptest.NewRequest("POST", "/api/v1/session/callback", strings.NewReader(`{"provider_token":"one","state":"`+start()+`"}`))
		callback.Header.Set("Content-Type", "application/json")
		callback.Header.Set("Origin", "https://console.example")
		issued := httptest.NewRecorder()
		mounted.ServeHTTP(issued, callback)
		if issued.Code != 200 || len(issued.Result().Cookies()) != 1 {
			t.Fatalf("native mounted callback: %d %s", issued.Code, issued.Body.String())
		}
		credential := issued.Result().Cookies()[0]
		identity, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: credential.Value})
		if err != nil {
			t.Fatal(err)
		}
		org := identity.Scope.OrganizationID().String()
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, org, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		if r, err := authorization.Reconcile(ctx, projection, writer, org, config.StoreID, config.ModelID); err != nil || !r.Applied {
			t.Fatalf("projection: %v", err)
		}
		call := func(path string, c *http.Cookie, scope string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", path, nil)
			r.AddCookie(c)
			r.Header.Set(expectedScopeHeader, scope)
			w := httptest.NewRecorder()
			mounted.ServeHTTP(w, r)
			return w
		}
		exec := func(q string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
		reconcile := func() {
			t.Helper()
			if r, err := authorization.Reconcile(ctx, projection, writer, org, config.StoreID, config.ModelID); err != nil || !r.Applied {
				t.Fatalf("projection: %v", err)
			}
		}
		bootstrap := func(t *testing.T) struct {
			Permissions, Capabilities []string
			Environment               string `json:"environment_id"`
		} {
			t.Helper()
			response := call("/api/v1/session/bootstrap", credential, expectedScopeValue(identity.Scope))
			var body struct {
				Permissions, Capabilities []string
				Environment               string `json:"environment_id"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatalf("bootstrap HTTP %d %s", response.Code, response.Body.String())
			}
			return body
		}
		for _, path := range []string{"/api/v1/session/bootstrap", "/api/v1/me", "/api/v1/session/scopes"} {
			t.Run(path, func(t *testing.T) {
				w := call(path, credential, expectedScopeValue(identity.Scope))
				if w.Code != 200 {
					t.Errorf("post-login admission: HTTP %d body=%s", w.Code, w.Body.String())
					return
				}
				var value map[string]json.RawMessage
				if json.Unmarshal(w.Body.Bytes(), &value) != nil {
					t.Fatal("invalid response")
				}
				if path == "/api/v1/session/bootstrap" {
					var caps []string
					_ = json.Unmarshal(value["capabilities"], &caps)
					if len(caps) == 0 {
						t.Error("current allowed policy produced no capabilities")
					}
				}
			})
		}
		t.Run("bounded current checks and exact capability targets", func(t *testing.T) {
			checks.Store(0)
			body := bootstrap(t)
			if n := checks.Load(); n != 12 {
				t.Errorf("environment-allowed bootstrap made %d Checks; want 11 scoped permissions + organization identity", n)
			}
			for _, cap := range []string{"inventory.read", "identity.manage", "identity.groups.manage", "identity.scopes.manage", "security-agents.controls.manage", "security-agents.catalog.read", "scope.switch"} {
				if !slices.Contains(body.Capabilities, cap) {
					t.Errorf("missing %s", cap)
				}
			}
		})
		t.Run("projection pending and recovery", func(t *testing.T) {
			exec(`SELECT zasp_authorization79.touch($1)`, org)
			before := checks.Load()
			for _, path := range []string{"/api/v1/session/bootstrap", "/api/v1/me", "/api/v1/session/scopes"} {
				r := call(path, credential, expectedScopeValue(identity.Scope))
				if r.Code != 409 || !strings.Contains(r.Body.String(), `"authorization_pending"`) {
					t.Errorf("pending %s: %d %s", path, r.Code, r.Body.String())
				}
			}
			if checks.Load() != before {
				t.Error("pending projection reached FGA")
			}
			reconcile()
			_ = bootstrap(t)
		})
		t.Run("official adapter outage has no cached positive", func(t *testing.T) {
			outage.Store(true)
			for _, path := range []string{"/api/v1/session/bootstrap", "/api/v1/me", "/api/v1/session/scopes"} {
				r := call(path, credential, expectedScopeValue(identity.Scope))
				if r.Code != 503 || !strings.Contains(r.Body.String(), `"authorization_unavailable"`) {
					t.Errorf("outage %s: %d %s", path, r.Code, r.Body.String())
				}
			}
			outage.Store(false)
			_ = bootstrap(t)
		})
		t.Run("revision changes after preparation before result", func(t *testing.T) {
			router.(*operationRouter).authorizer = &postLoginRaceAuthorizer{a, func() { exec(`SELECT zasp_authorization79.touch($1)`, org) }}
			r := call("/api/v1/session/bootstrap", credential, expectedScopeValue(identity.Scope))
			router.(*operationRouter).authorizer = a
			if r.Code != 409 || !strings.Contains(r.Body.String(), `"authorization_changed"`) {
				t.Errorf("stale result: %d %s", r.Code, r.Body.String())
			}
			reconcile()
		})
		t.Run("native self facts reject foreign or forged binding", func(t *testing.T) {
			binding, _ := postLoginBinding(identity)
			for _, change := range []struct {
				field string
				value any
			}{{"organization_id", "pid_98000002-0000-4000-8000-000000000001"}, {"principal_id", "pid_98000002-0000-4000-8000-000000000004"}, {"credential_digest", strings.Repeat("0", 64)}, {"csrf_digest", strings.Repeat("0", 64)}, {"pat_ceiling", []string{"view"}}, {"extra", "caller"}} {
				var b map[string]any
				_ = json.Unmarshal(binding, &b)
				b[change.field] = change.value
				bad, _ := json.Marshal(b)
				var raw []byte
				if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.post_login_snapshot($1::jsonb)`, string(bad)).Scan(&raw); err == nil {
					t.Errorf("native accepted %s", change.field)
				}
			}
			var raw []byte
			if err := api.QueryRow(ctx, `SELECT zasp_authorization80_identity.post_login_binding($1::jsonb)`, string(binding)).Scan(&raw); err == nil {
				t.Error("API executed private credential helper")
			}
			if _, err := db.QueryJSON(ctx, postgresBootstrapV19SQL, identity.PrincipalID.String(), org, identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), testCorrelationID); err == nil {
				t.Error("generic identity SQL admitted")
			}
		})
		t.Run("policy denial and resource-only access preserve scope switch", func(t *testing.T) {
			p, w, e := identity.PrincipalID.String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
			const finding = "pid_98000001-0000-4000-8000-000000000071"
			const agent = "pid_98000001-0000-4000-8000-000000000074"
			exec(`INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'supervised',1,'{}','post-login-catalog-boundary')`, org, w, e, agent)
			exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','post-login','Resource-only finding','high','open')`, org, w, e, finding)
			exec(`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,'pid_98000001-0000-4000-8000-000000000072')`, org, w, e, finding)
			reconcile()
			orgRole := fga.ClientTupleKey{User: "user:" + p, Relation: "security_admin", Object: "organization:" + org}
			scopeRole := fga.ClientTupleKey{User: "user:" + p, Relation: "security_admin", Object: "environment:" + org + "/" + w + "/" + e}
			remove := func(tuple fga.ClientTupleKey) {
				t.Helper()
				if _, err := client.Write(ctx).Body(fga.ClientWriteRequest{Deletes: []fga.ClientTupleKeyWithoutCondition{{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}}}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute(); err != nil {
					t.Fatal("owned policy removal failed")
				}
			}
			add := func(tuple fga.ClientTupleKey) {
				t.Helper()
				if _, err := client.Write(ctx).Body(fga.ClientWriteRequest{Writes: []fga.ClientTupleKey{tuple}}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute(); err != nil {
					t.Fatal("owned policy addition failed")
				}
			}
			remove(scopeRole)
			body := bootstrap(t)
			if !slices.Equal(body.Capabilities, []string{"identity.manage", "scope.switch"}) {
				t.Errorf("org-only capabilities=%v", body.Capabilities)
			}
			remove(orgRole)
			body = bootstrap(t)
			if !slices.Equal(body.Capabilities, []string{"scope.switch"}) || len(body.Permissions) != 0 {
				t.Errorf("denied policy fell back to role: %v %v", body.Capabilities, body.Permissions)
			}
			direct := fga.ClientTupleKey{User: "user:" + p, Relation: "direct_view", Object: "resource:" + org + "/" + w + "/" + e + "/finding/" + finding}
			add(direct)
			body = bootstrap(t)
			if !slices.Equal(body.Capabilities, []string{"findings.read", "scope.switch"}) || !slices.Equal(body.Permissions, []string{"view"}) {
				t.Errorf("resource-only capabilities=%v permissions=%v", body.Capabilities, body.Permissions)
			}
			r := call("/api/v1/findings", credential, expectedScopeValue(identity.Scope))
			if r.Code != 200 || !strings.Contains(r.Body.String(), finding) {
				t.Errorf("resource-only product collection: %d %s", r.Code, r.Body.String())
			}
			remove(direct)
			agentGrant := fga.ClientTupleKey{User: "user:" + p, Relation: "direct_view", Object: "resource:" + org + "/" + w + "/" + e + "/security_agent/" + agent}
			add(agentGrant)
			body = bootstrap(t)
			if !slices.Equal(body.Capabilities, []string{"scope.switch", "security-agents.read"}) {
				t.Errorf("resource-only agent became catalog authority: %v", body.Capabilities)
			}
			grant, err := a.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "listSecurityAgents"})
			if err != nil || len(grant.Allowed) != 1 || grant.Allowed[0].ID != agent {
				t.Errorf("resource-only definition collection denied: %v %v", grant.Allowed, err)
			}
			for _, op := range []string{"listSecurityAgentTemplates", "listSecurityActions"} {
				if _, err := a.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: op}); !errors.Is(err, ErrAuthorizationDenied) {
					t.Errorf("resource grant became environment catalog allow: %s %v", op, err)
				}
			}
			remove(agentGrant)
			add(scopeRole)
			body = bootstrap(t)
			if slices.Contains(body.Capabilities, "identity.manage") || !slices.Contains(body.Capabilities, "security-agents.controls.manage") {
				t.Errorf("scoped authority became organization authority: %v", body.Capabilities)
			}
			add(orgRole)
		})
		t.Run("foreign expected scope refused", func(t *testing.T) {
			w := call("/api/v1/me", credential, "pid_98000002-0000-4000-8000-000000000001/pid_98000002-0000-4000-8000-000000000002/pid_98000002-0000-4000-8000-000000000003")
			if w.Code != 409 {
				t.Errorf("foreign scope HTTP %d", w.Code)
			}
		})
		t.Run("membership scope switch reboots current policy and refuses foreign target", func(t *testing.T) {
			const second = "pid_98000001-0000-4000-8000-000000000073"
			w, old := identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
			exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Second','production')`, org, w, second)
			exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Second','[]',false)`, identity.PrincipalID.String(), org, w, second)
			reconcile()
			listed := call("/api/v1/session/scopes", credential, expectedScopeValue(identity.Scope))
			if listed.Code != 200 || !strings.Contains(listed.Body.String(), second) || strings.Contains(listed.Body.String(), "pid_98000002") {
				t.Fatalf("membership choices: %d %s", listed.Code, listed.Body.String())
			}
			switchTo := func(workspace, environment, csrf string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("PUT", "/api/v1/session/scope", strings.NewReader(`{"workspace_id":"`+workspace+`","environment_id":"`+environment+`"}`))
				r.AddCookie(credential)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://console.example")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
				response := httptest.NewRecorder()
				mounted.ServeHTTP(response, r)
				return response
			}
			if r := switchTo(w, second, ""); r.Code != 403 {
				t.Errorf("missing CSRF admitted: %d", r.Code)
			}
			if r := switchTo("pid_98000002-0000-4000-8000-000000000002", "pid_98000002-0000-4000-8000-000000000003", identity.CSRFToken); r.Code == 204 {
				t.Fatal("foreign target admitted")
			}
			if r := switchTo(w, second, identity.CSRFToken); r.Code != 204 {
				t.Fatalf("valid switch: %d %s", r.Code, r.Body.String())
			}
			identity, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: credential.Value})
			if err != nil {
				t.Fatal(err)
			}
			if pending := call("/api/v1/session/bootstrap", credential, expectedScopeValue(identity.Scope)); pending.Code != 409 || !strings.Contains(pending.Body.String(), `"authorization_pending"`) {
				t.Errorf("scope mutation must await projection: %d %s", pending.Code, pending.Body.String())
			}
			reconcile()
			if body := bootstrap(t); body.Environment != second || !slices.Contains(body.Capabilities, "findings.read") {
				t.Errorf("new scope bootstrap: %#v", body)
			}
			if r := switchTo(w, old, identity.CSRFToken); r.Code != 204 {
				t.Fatalf("return switch: %d %s", r.Code, r.Body.String())
			}
			identity, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: credential.Value})
			if err != nil {
				t.Fatal(err)
			}
			reconcile()
		})
		t.Run("PAT self read preserves ceiling and browser-only boundary", func(t *testing.T) {
			const token = "post-login-local-pat-fixture-01234567890123456789"
			exec(`INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest($1,'sha256'),'pid_98000001-0000-4000-8000-000000000099','Post login PAT',$2,$3,$4,$5,'["view"]',clock_timestamp()+interval '1 hour')`, token, identity.PrincipalID.String(), org, identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
			reconcile()
			request := func(path string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", path, nil)
				r.Header.Set("Authorization", "Bearer "+token)
				r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
				w := httptest.NewRecorder()
				mounted.ServeHTTP(w, r)
				return w
			}
			for _, path := range []string{"/api/v1/me", "/api/v1/findings"} {
				if r := request(path); r.Code != 200 {
					t.Errorf("PAT allowed %s: %d %s", path, r.Code, r.Body.String())
				}
			}
			for _, path := range []string{"/api/v1/session/bootstrap", "/api/v1/session/scopes"} {
				if r := request(path); r.Code == 200 {
					t.Errorf("PAT admitted browser route %s", path)
				}
			}
			exec(`UPDATE zasp_product_api_tokens SET permissions='["manage_findings"]' WHERE token_digest=digest($1,'sha256')`, token)
			reconcile()
			if r := request("/api/v1/me"); r.Code != 200 {
				t.Errorf("self read imposed product ceiling: %d %s", r.Code, r.Body.String())
			}
			if r := request("/api/v1/findings"); r.Code != 403 {
				t.Errorf("PAT exceeded ceiling: %d %s", r.Code, r.Body.String())
			}
		})
		t.Run("credential expires or revokes after Check before final read", func(t *testing.T) {
			for _, field := range []string{"expires_at", "revoked_at"} {
				var expires time.Time
				if err := owner.QueryRow(ctx, `SELECT expires_at FROM zasp_product_sessions WHERE token_digest=digest($1,'sha256')`, credential.Value).Scan(&expires); err != nil {
					t.Fatal(err)
				}
				router.(*operationRouter).authorizer = &postLoginRaceAuthorizer{a, func() {
					exec(`UPDATE zasp_product_sessions SET `+field+`=clock_timestamp()-interval '1 second' WHERE token_digest=digest($1,'sha256')`, credential.Value)
				}}
				r := call("/api/v1/me", credential, expectedScopeValue(identity.Scope))
				router.(*operationRouter).authorizer = a
				if r.Code != 409 || !strings.Contains(r.Body.String(), `"authorization_changed"`) {
					t.Errorf("final %s fence: %d %s", field, r.Code, r.Body.String())
				}
				exec(`UPDATE zasp_product_sessions SET expires_at=$2,revoked_at=NULL WHERE token_digest=digest($1,'sha256')`, credential.Value, expires)
				reconcile()
			}
		})
		t.Run("revoked cookie refused", func(t *testing.T) {
			if err := repo.Revoke(ctx, identity, credential.Value); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/v1/session/bootstrap", "/api/v1/me", "/api/v1/session/scopes"} {
				if w := call(path, credential, expectedScopeValue(identity.Scope)); w.Code != 401 {
					t.Errorf("revoked %s HTTP %d", path, w.Code)
				}
			}
		})
	})
}
