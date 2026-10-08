package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/integration"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This fixture keeps the actual registered API, native canonical predecessor,
// projection and official local Check in the mounted client path.
type integrationClientFixture struct {
	t                   *testing.T
	ctx                 context.Context
	owner, api          *pgx.Conn
	dsn                 string
	browser, pat        RequestIdentity
	repo                *PostgresRepository
	authorizer          *OpenFGAAuthorizer
	driver              *integrationClientDriver
	provider            *connectorProviderStub
	references          *ReferenceConnectorRegistry
	referenceAuthorizer RequestAuthorizer
	providerCalls       atomic.Int32
	capabilityAvailable bool
	router              http.Handler
	reconcile           func()
}

const integrationClientExisting = "pid_78200001-0000-4000-8000-000000000001"
const integrationClientBody = `{"name":"Client GitHub","connector_key":"github","configuration":{"authorization_mode":"github_app"}}`

// Diagnostics expose only fixed categories and a validated PostgreSQL SQLSTATE.
// Original fixture errors and admission/cleanup remain unchanged.
func connectorFixtureErrorDiagnostic(t *testing.T, err error) {
	t.Helper()
	var native *pgconn.PgError
	if errors.As(err, &native) && native != nil && len(native.Code) == 5 {
		valid := true
		for _, value := range native.Code {
			if (value < '0' || value > '9') && (value < 'A' || value > 'Z') {
				valid = false
			}
		}
		if valid {
			t.Logf("connector fixture SQLSTATE=%s", native.Code)
			return
		}
	}
	t.Log("connector fixture errorCategory=non-postgres-or-unclassified")
}

func newIntegrationClientFixture(t *testing.T, composed ...bool) *integrationClientFixture {
	t.Helper()
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned local OpenFGA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	t.Log("connector fixture stage=postgres-start")
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	t.Log("connector fixture stage=postgres-connect")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	t.Log("connector fixture stage=canonical-install")
	if len(composed) > 0 && composed[0] {
		migrateIntegrationClientComposed(t, ctx, owner)
	} else {
		migrateP7Authorization(t, ctx, owner)
	}
	t.Log("connector fixture stage=fixture-data")
	f := &integrationClientFixture{t: t, ctx: ctx, owner: owner, dsn: dsn}
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	f.exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Client','client.invalid')`, o)
	f.exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Selected')`, o, w)
	f.exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production')`, o, w, e)
	f.exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-client80','member-client80','security_engineer',true)`, p, o)
	f.exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','[]',true)`, p, o, w, e)
	f.exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('client80-session','sha256'),'session-client80',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp()-interval '10 minutes',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	f.exec(`INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('client80-pat','sha256'),'pid_78200004-0000-4000-8000-000000000004','Client PAT',$1,$2,$3,$4,'["manage_workflows","view"]',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	f.exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration) VALUES($1,$2,$3,$4,'github','1.0.0','Existing','{"authorization_mode":"github_app"}')`, o, w, e, integrationClientExisting)
	f.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Existing','connector_key','github','configuration','{"authorization_mode":"github_app"}'::jsonb,'status','pending_authorization','created_at','2026-01-01T00:00:00Z','updated_at','2026-01-01T00:00:00Z'))`, o, w, e, integrationClientExisting)
	t.Log("connector fixture stage=projection-pool")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	t.Log("connector fixture stage=owned-fga-model")
	client, pins := newAuthorizationProjectionFGA(t)
	t.Log("connector fixture stage=tuple-writer")
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Log("connector fixture stage=fga-checker")
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Log("connector fixture stage=projection-configure")
	f.exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID)
	f.reconcile = func() {
		t.Helper()
		if result, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID); err != nil || !result.Applied {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatalf("projection=%+v %v", result, err)
		}
	}
	t.Log("connector fixture stage=projection-reconcile")
	f.reconcile()
	t.Log("connector fixture stage=registered-api-connect")
	f.api = connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	t.Cleanup(func() { _ = f.api.Close(context.Background()) })
	t.Log("connector fixture stage=registered-api-role")
	var exact bool
	if err := f.api.QueryRow(ctx, `SELECT session_user='auth80_api' AND current_user=session_user AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=session_user`).Scan(&exact); err != nil || !exact {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatalf("registered API=%t %v", exact, err)
	}
	t.Log("connector fixture stage=database-current-authority")
	f.driver = &integrationClientDriver{rejectionAuthorizationDriver: rejectionAuthorizationDriver{authorizationConnectionDriver: authorizationConnectionDriver{conn: f.api}}, t: t}
	db, _ := NewPostgresJSONDatabase(f.driver)
	if err := db.RequireCurrentAuthorization(); err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	f.repo, _ = NewPostgresRepository(db)
	t.Log("connector fixture stage=browser-authentication")
	f.browser, err = f.repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "client80-session"})
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Log("connector fixture stage=token-authentication")
	f.pat, err = f.repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: "client80-pat"})
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	if len(f.browser.Permissions) != 0 || len(f.pat.Permissions) != 0 {
		t.Fatal("legacy allow permissions exposed")
	}
	t.Log("connector fixture stage=authorization-resolver")
	resolver, _ := NewPostgresAuthorizationResolver(db)
	f.authorizer = &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	f.capabilityAvailable = true
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.providerCalls.Add(1); w.WriteHeader(204) }))
	t.Cleanup(endpoint.Close)
	f.provider = &connectorProviderStub{beforeComplete: func() {
		r, err := http.Get(endpoint.URL)
		if err != nil {
			t.Error(err)
			return
		}
		_ = r.Body.Close()
	}}
	check := func(context.Context) error {
		if !f.capabilityAvailable {
			return ErrRepositoryUnavailable
		}
		return nil
	}
	t.Log("connector fixture stage=connector-registry")
	oauth, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: f.provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}, "okta": {Provider: f.provider, RequestedScopes: []string{"okta.users.read"}, CredentialClass: "okta_refresh_reference"}, "slack": {Provider: f.provider, RequestedScopes: []string{"nango:auth"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack"}}, map[string]ConnectorCapabilityCheck{"github": check, "okta": check, "slack": check})
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	probe := &integrationClientReferenceProbe{url: endpoint.URL}
	t.Log("connector fixture stage=reference-registry")
	f.references, err = NewReferenceConnectorRegistry(map[string]ReferenceAuthorizationProbe{"aws": probe, "kubernetes": probe}, map[string]ConnectorCapabilityCheck{"aws": check, "kubernetes": check})
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	t.Log("connector fixture stage=workflow-handler")
	handler, err := newWorkflowHTTPHandler(f.repo, []byte(strings.Repeat("k", 32)), time.Now, CombinedConnectorCapabilities{OAuth: oauth, Reference: f.references})
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	var ops []Operation
	for _, id := range []string{"createIntegration", "updateIntegration", "getIntegration"} {
		policy, _ := authorization.LookupOperation(id)
		ops = append(ops, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: id, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, RequireCSRF: id != "getIntegration", Handler: handler})
	}
	t.Log("connector fixture stage=router")
	f.router, err = NewRouter(ops)
	if err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal(err)
	}
	f.router.(*operationRouter).authorizer = f.authorizer
	return f
}

type integrationClientReferenceProbe struct{ url string }

func (p *integrationClientReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return ReferenceAuthorizationSubject{}, err
	}
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return ReferenceAuthorizationSubject{}, err
	}
	_ = response.Body.Close()
	if target.Provider == "aws" {
		return ReferenceAuthorizationSubject{Kind: "aws_account", ID: "123456789012"}, nil
	}
	return ReferenceAuthorizationSubject{Kind: "kubernetes_cluster", ID: "cluster.example.test/cluster-01"}, nil
}

type integrationClientDriver struct {
	rejectionAuthorizationDriver
	t    *testing.T
	mode string
}

func (d *integrationClientDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &integrationClientTx{Tx: tx, t: d.t, mode: d.mode}, nil
}

type integrationClientTx struct {
	pgx.Tx
	t       *testing.T
	mode    string
	mutated bool
}

func (tx *integrationClientTx) QueryRow(ctx context.Context, q string, a ...any) pgx.Row {
	if q == postgresCurrentIntegrationMutateSQL || q == postgresCurrentReferenceCompleteSQL {
		tx.mutated = true
	}
	return integrationClientRow{Row: tx.Tx.QueryRow(ctx, q, a...), t: tx.t, query: q, mode: tx.mode}
}
func (tx *integrationClientTx) Commit(ctx context.Context) error {
	if tx.mutated && tx.mode == "before-commit" {
		return errors.New("owned precommit fault")
	}
	err := tx.Tx.Commit(ctx)
	if err == nil && tx.mutated && tx.mode == "lost-response" {
		return errors.New("owned lost commit acknowledgement")
	}
	return err
}

type integrationClientRow struct {
	pgx.Row
	t           *testing.T
	query, mode string
}

func (r integrationClientRow) Scan(out ...any) error {
	err := r.Row.Scan(out...)
	if err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) {
			r.t.Logf("client native query=%s code=%s message=%s where=%s", r.query, p.Code, p.Message, p.Where)
		}
	}
	if err == nil && (r.query == postgresCurrentIntegrationMutateSQL || r.query == postgresCurrentReferenceCompleteSQL) {
		if r.mode == "panic-after-mutation" {
			panic("owned post-mutation panic")
		}
		if r.mode == "error-after-mutation" {
			return errors.New("owned post-mutation fault")
		}
	}
	return err
}
func (f *integrationClientFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.owner.Exec(f.ctx, q, args...); err != nil {
		connectorFixtureErrorDiagnostic(f.t, err)
		f.t.Fatal(err)
	}
}
func (f *integrationClientFixture) invoke(identity RequestIdentity, operation, id, key, body string, version int64) *httptest.ResponseRecorder {
	return f.invokeContext(f.ctx, identity, operation, id, key, body, version)
}
func (f *integrationClientFixture) invokeContext(call context.Context, identity RequestIdentity, operation, id, key, body string, version int64) *httptest.ResponseRecorder {
	method, path := "POST", "/api/v1/integrations"
	if operation == "updateIntegration" {
		method, path = "PATCH", path+"/"+id
	}
	if operation == "getIntegration" {
		method, path = "GET", path+"/"+id
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, version))
	r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
	r.Header.Set("Origin", "https://console.example")
	r.Header.Set("X-CSRF-Token", identity.CSRFToken)
	if identity.CredentialKind == CredentialBearerToken {
		r.Header.Set("Authorization", "Bearer client80-pat")
	} else {
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "client80-session"})
	}
	ctx := context.WithValue(call, identityContextKey{}, identity)
	ctx = context.WithValue(ctx, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
	ctx = context.WithValue(ctx, correlationContextKey{}, integrationClientCorrelation(key))
	result := httptest.NewRecorder()
	f.router.ServeHTTP(result, r.WithContext(ctx))
	return result
}

func migrateIntegrationClientComposed(t *testing.T, ctx context.Context, conn *pgx.Conn) *migrations.Runner {
	t.Helper()
	t.Log("connector fixture stage=canonical-cutover")
	runner := migrateToTypedInventoryCutover(t, ctx, conn)
	runner, _ = migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: conn, t: t})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, q, args...); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal(err)
		}
	}
	t.Log("connector fixture stage=data-plane-roles")
	for _, name := range []string{"auth80_api", "auth80_discovery", "auth80_ingest", "auth80_runtime", "auth80_outbox", "auth80_gateway"} {
		exec(fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, name))
	}
	t.Log("connector fixture stage=data-plane-principals")
	exec(`SELECT zasp_discovery_register_principals(session_user,'auth80_api','auth80_discovery','auth80_ingest','auth80_runtime','auth80_outbox','auth80_gateway')`)
	t.Log("connector fixture stage=current-authorization-modules")
	for _, up := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution,
		runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety, runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance, runner.UpProductionRuntimeCorrelationRouting, runner.UpProductionRuntimeSandboxBinding, runner.UpProductionRuntimePrecision, runner.UpProductionAuditExports, runner.UpProductionSecurityAgentBudgets, runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
		if err := up(ctx); err != nil {
			version, _ := runner.Version(ctx)
			t.Logf("failed after canonical version %d", version)
			tx, _ := conn.Begin(ctx)
			_, detail := tx.Exec(ctx, migrations.ProductionAuthorizationEnforcement().UpSQL())
			_ = tx.Rollback(ctx)
			t.Logf("installation diagnostic: %v", detail)
			var pgerr *pgconn.PgError
			if errors.As(detail, &pgerr) {
				t.Logf("SQL position=%d internal=%d query=%s context=%s", pgerr.Position, pgerr.InternalPosition, pgerr.InternalQuery, pgerr.Where)
			}
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatalf("authorization install: %v", err)
		}
	}
	t.Log("connector fixture stage=execution-roles")
	for _, name := range []string{"client_scheduler", "client_risk", "client_graph", "client_search"} {
		exec(fmt.Sprintf("CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOBYPASSRLS", name))
	}
	t.Log("connector fixture stage=execution-principals")
	exec("SELECT zasp_execution_register_principals(session_user,'client_scheduler','auth80_discovery','client_risk','client_graph','client_search')")
	t.Log("connector fixture stage=temporal-authorization-modules")
	for _, up := range []func(context.Context) error{runner.UpProductionTemporalDomain, runner.UpProductionTemporalExecutor, runner.UpProductionTemporalWorkflow, runner.UpProductionTemporalCompatibility, runner.UpProductionTemporalLegacyTests, runner.UpProductionTemporalDiscovery, runner.UpProductionTemporalAdmission, runner.UpProductionTemporalTestExecutor, runner.UpProductionTemporalTestSelector, runner.UpProductionTemporalHumanAdmission, runner.UpProductionTemporalAutomaticSources, runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalAuditProfile} {
		if err := up(ctx); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("composed client installation", err)
		}
	}
	t.Log("connector fixture stage=current-authorization-replay")
	if err := runner.UpProductionAuthorizationTemporalAuditProfile(ctx); err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal("composed current replay", err)
	}
	t.Log("connector fixture stage=verifier-registration")
	key := authorizationFixtureAttestor(t)
	exec("SELECT zasp_authorization80.register_verifier($1,$2)", key.Version(), key.Verifier())
	return runner
}

func TestP7IntegrationMutationsPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	t.Run("mounted_create_commits_real_five_effects", func(t *testing.T) {
		r := f.invoke(f.browser, "createIntegration", "", "client-create-browser", integrationClientBody, 0)
		if r.Code != 201 {
			t.Fatalf("valid mounted create=%d body=%s", r.Code, r.Body)
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil || body.ID == "" {
			t.Fatalf("created body=%s", r.Body)
		}
		f.assertEffects(t, f.browser, "createIntegration", "client-create-browser", body.ID, 1, r)
		f.reconcile()
		g := f.invoke(f.browser, "getIntegration", body.ID, "", "", 0)
		if g.Code != 200 || g.Header().Get("ETag") != `"1"` {
			t.Fatalf("created GET=%d ETag=%s body=%s", g.Code, g.Header().Get("ETag"), g.Body)
		}
	})
	t.Run("mounted_get_uses_original_view_and_workflow_etag", func(t *testing.T) {
		r := f.invoke(f.browser, "getIntegration", integrationClientExisting, "", "", 0)
		if r.Code != 200 || r.Header().Get("ETag") != `"1"` {
			t.Fatalf("valid mounted GET=%d ETag=%s body=%s", r.Code, r.Header().Get("ETag"), r.Body)
		}
	})
	t.Run("mounted_update_commits_workflow_plus_one", func(t *testing.T) {
		r := f.invoke(f.browser, "updateIntegration", integrationClientExisting, "client-update-browser", integrationClientBody, 1)
		if r.Code != 200 || r.Header().Get("ETag") != `"2"` {
			t.Fatalf("valid mounted update=%d ETag=%s body=%s", r.Code, r.Header().Get("ETag"), r.Body)
		}
		f.assertEffects(t, f.browser, "updateIntegration", "client-update-browser", integrationClientExisting, 2, r)
	})
	t.Run("public_predecessor_retains_historical_readiness_refusal", func(t *testing.T) {
		i := f.browser
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var raw []byte
		err = tx.QueryRow(f.ctx, postgresConnectorWorkflowMutateSQL, "create", "integration", "pid_78200005-0000-4000-8000-000000000005", i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), "createIntegration", "client-native-predecessor", int64(0), json.RawMessage(`{"resource_id":"","expected_version":0,"body":`+integrationClientBody+`}`), json.RawMessage(`{"id":"pid_78200005-0000-4000-8000-000000000005","name":"Client GitHub","connector_key":"github","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization"}`), "pid_78200006-0000-4000-8000-000000000006", testCorrelationID, "pid_78200007-0000-4000-8000-000000000007").Scan(&raw)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55000" || pgerr.Message != "audit exports authority unavailable" {
			t.Fatalf("historical predecessor result: %v", err)
		}
		t.Logf("unchanged public predecessor: %s %s", pgerr.Code, pgerr.Message)
	})
	t.Run("PAT_real_create_get_update_replay_and_conflict", func(t *testing.T) {
		r := f.invoke(f.pat, "createIntegration", "", "client-pat-create-key", integrationClientBody, 0)
		if r.Code != 201 || r.Header().Get("X-Mutation-Receipt-ID") != "" {
			t.Fatalf("PAT create=%d %s", r.Code, r.Body)
		}
		var body struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &body)
		f.assertEffects(t, f.pat, "createIntegration", "client-pat-create-key", body.ID, 1, r)
		f.reconcile()
		get := f.invoke(f.pat, "getIntegration", body.ID, "", "", 0)
		if get.Code != 200 || get.Header().Get("ETag") != `"1"` {
			t.Fatalf("PAT GET=%d %s", get.Code, get.Body)
		}
		before := f.effects(t)
		for n := 0; n < 2; n++ {
			again := f.invoke(f.pat, "createIntegration", "", "client-pat-create-key", integrationClientBody, 0)
			if again.Code != 201 || again.Body.String() != r.Body.String() || again.Header().Get("X-Audit-ID") != r.Header().Get("X-Audit-ID") {
				t.Fatalf("PAT replay=%d %s", again.Code, again.Body)
			}
		}
		conflict := f.invoke(f.pat, "createIntegration", "", "client-pat-create-key", strings.Replace(integrationClientBody, "Client GitHub", "Changed", 1), 0)
		if conflict.Code != 409 || f.effects(t) != before {
			t.Fatalf("conflict=%d or replay churn", conflict.Code)
		}
		u := f.invoke(f.pat, "updateIntegration", body.ID, "client-pat-update-key", integrationClientBody, 1)
		if u.Code != 200 || u.Header().Get("ETag") != `"2"` {
			t.Fatalf("PAT update=%d %s", u.Code, u.Body)
		}
		f.assertEffects(t, f.pat, "updateIntegration", "client-pat-update-key", body.ID, 2, u)
	})
	t.Run("rejected_key_corrected_into_actual_success", func(t *testing.T) {
		bad := strings.Replace(integrationClientBody, `"authorization_mode":"github_app"`, `"authorization_mode":"github_app","provider_url":"https://never.invalid"`, 1)
		r := f.invoke(f.browser, "createIntegration", "", "client-corrected-key", bad, 0)
		if r.Code != 400 {
			t.Fatalf("rejection=%d %s", r.Code, r.Body)
		}
		r = f.invoke(f.browser, "createIntegration", "", "client-corrected-key", integrationClientBody, 0)
		if r.Code != 201 {
			t.Fatalf("correction=%d %s", r.Code, r.Body)
		}
		var body struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &body)
		f.assertEffects(t, f.browser, "createIntegration", "client-corrected-key", body.ID, 1, r)
		f.reconcile()
	})
	t.Run("legitimate_typed_transition_preserves_public_receipt_plus_one", func(t *testing.T) {
		r := f.invoke(f.browser, "updateIntegration", integrationClientExisting, "client-version-three", integrationClientBody, 2)
		if r.Code != 200 {
			t.Fatalf("workflow3=%d %s", r.Code, r.Body)
		}
		i := f.browser
		for n, state := range []string{"authorizing", "active", "degraded", "active", "degraded"} {
			var raw []byte
			if err := f.api.QueryRow(f.ctx, `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,$5,$6)`, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), integrationClientExisting, 3+n, state).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		f.reconcile()
		get := f.invoke(i, "getIntegration", integrationClientExisting, "", "", 0)
		if get.Code != 200 || get.Header().Get("ETag") != `"3"` {
			t.Fatalf("workflow ETag=%d/%s", get.Code, get.Header().Get("ETag"))
		}
		r = f.invoke(i, "updateIntegration", integrationClientExisting, "client-divergent-update", integrationClientBody, 3)
		if r.Code != 200 || r.Header().Get("ETag") != `"4"` {
			t.Fatalf("divergent update=%d %s", r.Code, r.Body)
		}
		f.assertEffects(t, i, "updateIntegration", "client-divergent-update", integrationClientExisting, 4, r)
		var version int64
		if err := f.owner.QueryRow(f.ctx, `SELECT version FROM zasp_integrations WHERE id=$1`, integrationClientExisting).Scan(&version); err != nil || version != 9 {
			t.Fatalf("typed8 -> %d: %v", version, err)
		}
		before := f.effects(t)
		again := f.invoke(i, "updateIntegration", integrationClientExisting, "client-divergent-update", integrationClientBody, 3)
		if again.Code != 200 || again.Header().Get("ETag") != `"4"` || f.effects(t) != before {
			t.Fatalf("divergent replay=%d or changed counters", again.Code)
		}
		stale := f.invoke(i, "updateIntegration", integrationClientExisting, "client-stale-workflow", integrationClientBody, 3)
		if stale.Code != 409 || f.effects(t) != before {
			t.Fatalf("stale workflow=%d", stale.Code)
		}
	})
	t.Run("native_full_input_and_isolation_refusals_are_atomic", func(t *testing.T) {
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
		if err != nil {
			t.Fatal(err)
		}
		before := f.effects(t)
		for _, tc := range []struct {
			name      string
			change    func([]any)
			isolation pgx.TxIsoLevel
		}{
			{"actor", func(a []any) { a[6] = "pid_78200099-0000-4000-8000-000000000099" }, pgx.ReadCommitted},
			{"scope", func(a []any) { a[5] = "pid_78200099-0000-4000-8000-000000000099" }, pgx.ReadCommitted},
			{"operation", func(a []any) { a[7] = "updateIntegration" }, pgx.ReadCommitted},
			{"action", func(a []any) { a[0] = "delete" }, pgx.ReadCommitted},
			{"kind", func(a []any) { a[1] = "policy" }, pgx.ReadCommitted},
			{"receipt", func(a []any) { a[14] = "" }, pgx.ReadCommitted},
			{"intent_name", func(a []any) {
				a[11] = json.RawMessage(strings.Replace(string(a[11].(json.RawMessage)), "Client GitHub", "Forged", 1))
			}, pgx.ReadCommitted},
			{"active_state", func(a []any) {
				a[11] = json.RawMessage(strings.Replace(string(a[11].(json.RawMessage)), "pending_authorization", "active", 1))
			}, pgx.ReadCommitted},
			{"server_credential", func(a []any) {
				a[11] = json.RawMessage(strings.TrimSuffix(string(a[11].(json.RawMessage)), "}") + `,"credential_reference":"ref:attacker/credential"}`)
			}, pgx.ReadCommitted},
			{"unsafe_matching_configuration", func(a []any) {
				for _, n := range []int{10, 11} {
					a[n] = json.RawMessage(strings.Replace(string(a[n].(json.RawMessage)), `"authorization_mode":"github_app"`, `"authorization_mode":"github_app","provider_url":"https://attacker.invalid"`, 1))
				}
			}, pgx.ReadCommitted},
			{"repeatable_read", nil, pgx.RepeatableRead}, {"serializable", nil, pgx.Serializable},
		} {
			t.Run(tc.name, func(t *testing.T) {
				a := f.nativeArgs("client-native-negative", integrationClientExisting, "create", 0)
				a[2] = "pid_78200015-0000-4000-8000-000000000015"
				a[11] = json.RawMessage(strings.ReplaceAll(string(a[11].(json.RawMessage)), integrationClientExisting, a[2].(string)))
				if tc.change != nil {
					tc.change(a)
				}
				tx, err := f.api.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: tc.isolation})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				proof, _ := authorizationProofJSON(g)
				if _, err := tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof)); err != nil {
					t.Fatal(err)
				}
				var raw []byte
				err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, a...).Scan(&raw)
				var pe *pgconn.PgError
				if !errors.As(err, &pe) || !stringIn(pe.Code, "22023", "42501", "55000") {
					t.Fatalf("native refusal=%v", err)
				}
				_ = tx.Rollback(f.ctx)
				if f.effects(t) != before {
					t.Fatal("native refusal left partial effects")
				}
			})
		}
	})
}

func (f *integrationClientFixture) effects(t *testing.T) string {
	t.Helper()
	var result string
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM zasp_workflow_records r),(SELECT jsonb_agg(to_jsonb(i) ORDER BY i.id) FROM zasp_integrations i),(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.audit_id) FROM zasp_workflow_audit a),(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.operation,k.idempotency_key) FROM zasp_workflow_idempotency k),(SELECT jsonb_agg(to_jsonb(q) ORDER BY q.receipt_id) FROM zasp_workflow_receipts q),(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.organization_id) FROM zasp_authorization79.organizations o))::text`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func (f *integrationClientFixture) nativeArgs(key, id, action string, version int64) []any {
	i := f.browser
	operation := "createIntegration"
	target := ""
	if action == "update" {
		operation = "updateIntegration"
		target = id
	}
	intent := json.RawMessage(fmt.Sprintf(`{"resource_id":%q,"expected_version":%d,"body":%s}`, target, version, integrationClientBody))
	body := json.RawMessage(`{"id":"` + id + `","name":"Client GitHub","connector_key":"github","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`)
	return []any{action, "integration", id, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), operation, key, version, intent, body, "pid_78200016-0000-4000-8000-000000000016", testCorrelationID, "pid_78200017-0000-4000-8000-000000000017"}
}

// Completion runs the original native admitted-attempt/reference code. These
// owned provider fixtures are not a claim of mounted provider authorization.
func TestP7IntegrationClientConnectedPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	t.Run("all_supported_setup_saves_without_provider_or_discovery_effects", func(t *testing.T) {
		for _, tc := range []struct{ provider, configuration string }{
			{"github", `{"authorization_mode":"github_app"}`}, {"okta", `{"issuer":"https://customer.okta.com"}`},
			{"aws", `{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`},
			{"kubernetes", `{"connection_reference":"ref:kubernetes/connection/customer-0001"}`}, {"slack", `{"workspace_label":"Customer"}`},
			{"generic-webhook", `{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer"}`},
		} {
			t.Run(tc.provider, func(t *testing.T) {
				body := fmt.Sprintf(`{"name":"Configured %s","connector_key":%q,"configuration":%s}`, tc.provider, tc.provider, tc.configuration)
				key := "client-provider-" + tc.provider
				r := f.invoke(f.browser, "createIntegration", "", key, body, 0)
				if r.Code != 201 {
					t.Fatalf("setup=%d %s", r.Code, r.Body)
				}
				var b struct {
					ID string `json:"id"`
				}
				_ = json.Unmarshal(r.Body.Bytes(), &b)
				f.assertEffects(t, f.browser, "createIntegration", key, b.ID, 1, r)
				f.reconcile()
			})
		}
		var residue int
		if err := f.owner.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM zasp_integration_connections)+(SELECT count(*) FROM zasp_connector_oauth_attempts)+(SELECT count(*) FROM zasp_connector_effects)+(SELECT count(*) FROM zasp_discovery_syncs)+(SELECT count(*) FROM zasp_discovery_jobs)+(SELECT count(*) FROM zasp_inventory_entities)`).Scan(&residue); err != nil || residue != 0 || f.providerCalls.Load() != 0 || f.provider.state != "" {
			t.Fatalf("save provider calls=%d residue=%d error=%v", f.providerCalls.Load(), residue, err)
		}
		f.capabilityAvailable = false
		defer func() { f.capabilityAvailable = true }()
		before := f.effects(t)
		r := f.invoke(f.browser, "createIntegration", "", "client-capability-decline", integrationClientBody, 0)
		if r.Code != 400 || f.effects(t) != before {
			t.Fatalf("capability decline=%d %s", r.Code, r.Body)
		}
	})
	t.Run("actual_oauth_completion_then_public_get_update", func(t *testing.T) {
		r := f.invoke(f.browser, "createIntegration", "", "client-connected-oauth", integrationClientBody, 0)
		if r.Code != 201 {
			t.Fatalf("create=%d %s", r.Code, r.Body)
		}
		var b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &b)
		f.reconcile()
		i := f.browser
		o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
		digest := sha256.Sum256([]byte("owned connected provider proof"))
		attempt := "pid_78200031-0000-4000-8000-000000000031"
		cleanup := "pid_78200032-0000-4000-8000-000000000032"
		effect := "pid_78200033-0000-4000-8000-000000000033"
		var raw []byte
		if err := f.api.QueryRow(f.ctx, postgresConnectorStartOAuthSQL, o, w, e, attempt, b.ID, "github", p, digest[:], digest[:], "ref:oauth/pkce/client", digest[:], `["read:org","repo"]`, time.Now().Add(5*time.Minute), int64(1), json.RawMessage(`{"authorization_mode":"github_app"}`), cleanup, effect).Scan(&raw); err != nil {
			t.Fatal("native start", err)
		}
		if err := f.api.QueryRow(f.ctx, postgresConnectorConsumeOAuthSQL, o, w, e, digest[:], p, digest[:]).Scan(&raw); err != nil {
			t.Fatal("native consume", err)
		}
		grant, err := f.provider.Complete(f.ctx, "client-owned", "fixture-code", []byte("fixture-verifier"))
		if err != nil {
			t.Fatal(err)
		}
		completion := OAuthCompletion{AttemptID: attempt, EffectID: effect, ConnectionID: "pid_78200034-0000-4000-8000-000000000034", ConnectionReference: grant.ConnectionReference, ProviderSubject: grant.ProviderSubject, CredentialID: "pid_78200035-0000-4000-8000-000000000035", CredentialClass: grant.CredentialClass, Metadata: grant.Metadata}
		metadata, completed := connectorOAuthCompletionDigest(completion)
		if err := f.api.QueryRow(f.ctx, postgresConnectorCompleteOAuthSQL, o, w, e, completion.AttemptID, completion.EffectID, completion.ConnectionID, completion.ConnectionReference, completion.ProviderSubject, completion.CredentialID, completion.CredentialClass, metadata, completed[:]).Scan(&raw); err != nil {
			t.Fatal("native completion", err)
		}
		f.reconcile()
		get := f.invoke(i, "getIntegration", b.ID, "", "", 0)
		var connected struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(get.Body.Bytes(), &connected)
		if get.Code != 200 || get.Header().Get("ETag") != `"2"` || connected.Status != "active" {
			t.Fatalf("connected GET=%d %s", get.Code, get.Body)
		}
		r = f.invoke(i, "updateIntegration", b.ID, "client-connected-update", integrationClientBody, 2)
		if r.Code != 200 || r.Header().Get("ETag") != `"3"` {
			t.Fatalf("connected update=%d %s", r.Code, r.Body)
		}
		f.assertEffects(t, i, "updateIntegration", "client-connected-update", b.ID, 3, r)
		var preserved bool
		if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_integrations i JOIN zasp_integration_connections c ON(c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=(i.organization_id,i.workspace_id,i.environment_id,i.id) WHERE i.id=$1 AND i.state='active' AND i.version=3 AND c.state='verified' AND c.revoked_at IS NULL)`, b.ID).Scan(&preserved); err != nil || !preserved {
			t.Fatalf("connected authority retained=%t %v", preserved, err)
		}
	})
	t.Run("actual_reference_completion_then_public_get_update", func(t *testing.T) {
		f.freshReferenceSession(t)
		configuration := json.RawMessage(`{"external_id_reference":"ref:aws/external-id/customer-0001","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}`)
		body := `{"name":"Connected AWS","connector_key":"aws","configuration":` + string(configuration) + `}`
		r := f.invoke(f.browser, "createIntegration", "", "client-connected-reference", body, 0)
		if r.Code != 201 {
			t.Fatalf("reference create=%d %s", r.Code, r.Body)
		}
		var b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &b)
		f.reconcile()
		i := f.browser
		key := "client-reference-completion"
		completed := f.invokeReference(t, i, b.ID, key, 1)
		if completed.Code != 200 {
			t.Fatalf("actual mounted registered-API reference completion=%d %s", completed.Code, completed.Body)
		}
		f.reconcile()
		get := f.invoke(i, "getIntegration", b.ID, "", "", 0)
		if get.Code != 200 || get.Header().Get("ETag") != `"2"` {
			t.Fatalf("reference GET=%d %s", get.Code, get.Body)
		}
		r = f.invoke(i, "updateIntegration", b.ID, "client-reference-update", body, 2)
		if r.Code != 200 || r.Header().Get("ETag") != `"3"` {
			t.Fatalf("reference update=%d %s", r.Code, r.Body)
		}
	})
}

func (f *integrationClientFixture) assertEffects(t *testing.T, i RequestIdentity, operation, key, id string, version int64, r *httptest.ResponseRecorder) {
	t.Helper()
	var good bool
	err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_workflow_records w JOIN zasp_integrations i ON(i.organization_id,i.workspace_id,i.environment_id,i.id)=(w.organization_id,w.workspace_id,w.environment_id,w.id)
 JOIN zasp_workflow_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.resource_kind,a.resource_id,a.resource_version)=(w.organization_id,w.workspace_id,w.environment_id,w.kind,w.id,w.version)
 JOIN zasp_workflow_idempotency k ON(k.organization_id,k.workspace_id,k.environment_id,k.principal_id,k.operation,k.idempotency_key)=(w.organization_id,w.workspace_id,w.environment_id,$4,$5,$6)
 WHERE(w.organization_id,w.workspace_id,w.environment_id,w.kind,w.id,w.version)=($1,$2,$3,'integration',$7,$8)
 AND a.audit_id=$9 AND a.principal_id=$4 AND a.operation=$5 AND a.correlation_id=$10
 AND k.response->>'audit_id'=$9 AND k.response->'body'=w.body AND (k.response->>'version')::bigint=$8
 AND i.display_name=w.body->>'name' AND i.configuration=w.body->'configuration' AND i.kind=w.body->>'connector_key'
 AND CASE WHEN $11='' THEN k.receipt_semantics='receiptless_incompatible' AND NOT EXISTS(SELECT 1 FROM zasp_workflow_receipts q WHERE q.idempotency_key=$6)
	 ELSE k.receipt_semantics='receipt_backed' AND EXISTS(SELECT 1 FROM zasp_workflow_receipts q WHERE(q.organization_id,q.workspace_id,q.environment_id,q.principal_id,q.operation,q.idempotency_key,q.resource_id,q.resource_version,q.audit_id,q.receipt_id)=($1,$2,$3,$4,$5,$6,$7,$8,$9,$11) AND q.result=w.body AND q.intent->>'resource_id'=CASE $5 WHEN 'createIntegration' THEN '' ELSE $7 END AND q.expires_at>q.created_at AND q.expires_at<=q.created_at+interval '7 days') END)`, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), operation, key, id, version, r.Header().Get("X-Audit-ID"), integrationClientCorrelation(key), r.Header().Get("X-Mutation-Receipt-ID")).Scan(&good)
	if err != nil || !good {
		t.Fatalf("five exact effects=%t error=%v audit=%s receipt=%s", good, err, r.Header().Get("X-Audit-ID"), r.Header().Get("X-Mutation-Receipt-ID"))
	}
}

func integrationClientCorrelation(key string) string {
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("pid_%x-0000-4000-8000-%x", digest[:4], digest[4:10])
}

func TestP7IntegrationClientSetupBoundaryPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	t.Run("optional_public_signing_version_remains_valid", func(t *testing.T) {
		body := `{"name":"Versioned webhook","connector_key":"generic-webhook","configuration":{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":"0123456789abcdef0123456789abcdef"}}`
		r := f.invoke(f.browser, "createIntegration", "", "client-versioned-webhook", body, 0)
		if r.Code != 201 {
			t.Fatalf("existing optional metadata contract=%d %s", r.Code, r.Body)
		}
		f.reconcile()
	})
	t.Run("native_rejects_urls_rejected_by_public_setup", func(t *testing.T) {
		catalog, err := integration.NewCatalog(integration.BuiltinManifests())
		if err != nil {
			t.Fatal(err)
		}
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := authorizationProofJSON(g)
		for _, sample := range []struct {
			destination string
			valid       bool
		}{{"https://hooks.example.test:invalid/", false}, {"https://hooks.example.test/%zz", false}, {"https://hooks%2eexample.test/", false}, {"https://hooks<.example.test/receive", true}, {"https://hooks>.example.test/receive", true}, {"https://hooks|.example.test/receive", false}, {"https://hooks\".example.test/receive", true}, {"https://hooks{.example.test/receive", false}, {"https://hooks}.example.test/receive", false}, {"https://hooks^.example.test/receive", false}, {"https://hooks`.example.test/receive", false}, {"https://hooks\x01.example.test/receive", false}, {"https://caf%C3%A9.example.test:9443/a%20b", true}, {"https://hooks%25.example.test/", true}, {"https://hooks.example.test:/", true}, {"https://hooks_foo.example.test/", true}} {
			destination := sample.destination
			args := f.nativeArgs("client-native-url-boundary", "pid_78200074-0000-4000-8000-000000000074", "create", 0)
			configuration := map[string]string{"destination_url": destination, "signing_secret_reference": "secret_ref_customer"}
			if publicValid := catalog.ValidateSetup("generic-webhook", configuration) == nil; publicValid != sample.valid {
				t.Fatalf("public parser parity %q=%t want%t", destination, publicValid, sample.valid)
			}
			before := f.effects(t)
			input := map[string]any{"name": "Webhook", "connector_key": "generic-webhook", "configuration": configuration}
			intent, _ := json.Marshal(map[string]any{"resource_id": "", "expected_version": 0, "body": input})
			args[10] = json.RawMessage(intent)
			body, _ := json.Marshal(map[string]any{"id": args[2], "name": "Webhook", "connector_key": "generic-webhook", "configuration": configuration, "status": "configured", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"})
			args[11] = json.RawMessage(body)
			tx, err := f.api.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
			var raw []byte
			if err == nil {
				err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, args...).Scan(&raw)
			}
			_ = tx.Rollback(f.ctx)
			if f.effects(t) != before {
				t.Fatalf("URL refusal/rolled-back positive left durable effects: %q", destination)
			}
			var native *pgconn.PgError
			if sample.valid && err != nil || !sample.valid && (!errors.As(err, &native) || native.Code != "22023") {
				t.Errorf("native URL parity %q valid=%t: %v", destination, sample.valid, err)
			}
		}
	})
}

func TestP7IntegrationClientAtomicityPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	t.Run("postwrite_error_panic_and_precommit_fault_rollback_all_effects", func(t *testing.T) {
		for _, mode := range []string{"error-after-mutation", "panic-after-mutation", "before-commit"} {
			t.Run(mode, func(t *testing.T) {
				before := f.effects(t)
				f.driver.mode = mode
				defer func() { f.driver.mode = "" }()
				panicked := false
				var r *httptest.ResponseRecorder
				func() {
					defer func() {
						if recover() != nil {
							panicked = true
						}
					}()
					r = f.invoke(f.browser, "createIntegration", "", "client-fault-"+mode, integrationClientBody, 0)
				}()
				if mode == "panic-after-mutation" && !panicked || mode != "panic-after-mutation" && (r == nil || r.Code != 503) {
					t.Fatalf("fault mode=%s panic=%t response=%v", mode, panicked, r)
				}
				if f.effects(t) != before {
					t.Fatal("fault left a partial effect or revision")
				}
			})
		}
	})
	t.Run("genuine_lost_commit_acknowledgement_retries_one_durable_result", func(t *testing.T) {
		f.driver.mode = "lost-response"
		t.Cleanup(func() { f.driver.mode = "" })
		r := f.invoke(f.browser, "createIntegration", "", "client-lost-response", integrationClientBody, 0)
		f.driver.mode = ""
		if r.Code != 503 {
			t.Fatalf("lost response=%d %s", r.Code, r.Body)
		}
		f.reconcile()
		before := f.effects(t)
		r = f.invoke(f.browser, "createIntegration", "", "client-lost-response", integrationClientBody, 0)
		if r.Code != 201 {
			t.Fatalf("lost-response retry=%d %s", r.Code, r.Body)
		}
		var b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &b)
		f.assertEffects(t, f.browser, "createIntegration", "client-lost-response", b.ID, 1, r)
		if f.effects(t) != before {
			t.Fatal("retry wrote a second result")
		}
	})
	for _, mode := range []string{"cancel", "credential-expiry"} {
		t.Run("audit_insert_wait_"+mode, func(t *testing.T) {
			// pgx can discard a cancelled connection. Production pools replace
			// it; this single-connection fixture must do the same explicitly.
			if f.api.IsClosed() {
				f.api = connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, "auth80_api")
				f.driver.conn = f.api
			}
			before := f.effects(t)
			if mode == "credential-expiry" {
				t.Cleanup(func() {
					f.exec(`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE session_id='session-client80'`)
				})
				f.exec(`UPDATE zasp_product_sessions SET expires_at=clock_timestamp()+interval '6 seconds' WHERE session_id='session-client80'`)
			}
			blocker, err := f.owner.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			if _, err := blocker.Exec(f.ctx, `LOCK TABLE zasp_workflow_audit IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			call, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- f.invokeContext(call, f.browser, "createIntegration", "", "client-audit-wait-"+mode, integrationClientBody, 0)
			}()
			waitIntegrationClientLock(t, f, blocker, int(f.api.PgConn().PID()))
			if mode == "cancel" {
				cancel()
			} else {
				for {
					var expired bool
					if err := blocker.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM zasp_product_sessions WHERE session_id='session-client80'`).Scan(&expired); err != nil {
						t.Fatal(err)
					}
					if expired {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			if err := blocker.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-done:
				want := 503
				if mode == "credential-expiry" {
					want = 401
				}
				if r.Code != want {
					t.Fatalf("wait status=%d want=%d body=%s", r.Code, want, r.Body)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("owned request did not join")
			}
			if f.effects(t) != before {
				t.Fatal("wait refusal left partial five-table or revision effects")
			}
		})
	}
}

func waitIntegrationClientLock(t *testing.T, f *integrationClientFixture, tx pgx.Tx, pid int) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		var waiting bool
		if err := tx.QueryRow(f.ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected native INSERT lock wait not observed")
}

func TestP7IntegrationClientConcurrencyPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	t.Run("two_registered_connections_race_one_key_then_replay", func(t *testing.T) {
		second := connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, "auth80_api")
		defer second.Close(context.Background())
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "createIntegration"})
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := authorizationProofJSON(g)
		const key = "client-native-racing-key"
		const id = "pid_78200061-0000-4000-8000-000000000061"
		args := f.nativeArgs(key, id, "create", 0)
		args[13] = integrationClientCorrelation(key)
		type outcome struct {
			raw []byte
			err error
		}
		done := make(chan outcome, 2)
		start := make(chan struct{})
		for _, conn := range []*pgx.Conn{f.api, second} {
			go func(c *pgx.Conn) {
				<-start
				tx, err := c.Begin(f.ctx)
				if err != nil {
					done <- outcome{err: err}
					return
				}
				defer tx.Rollback(context.Background())
				if _, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof)); err != nil {
					done <- outcome{err: err}
					return
				}
				var raw []byte
				if err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, args...).Scan(&raw); err == nil {
					err = tx.Commit(f.ctx)
				}
				done <- outcome{raw: raw, err: err}
			}(conn)
		}
		close(start)
		wins, conflicts := 0, 0
		for n := 0; n < 2; n++ {
			select {
			case result := <-done:
				if result.err == nil {
					wins++
				} else {
					var pe *pgconn.PgError
					if !errors.As(result.err, &pe) || pe.Code != "40001" {
						t.Fatal(result.err)
					}
					conflicts++
				}
			case <-time.After(15 * time.Second):
				t.Fatal("race did not join")
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("wins=%d current-revision conflicts=%d", wins, conflicts)
		}
		f.reconcile()
		before := f.effects(t)
		r := f.invoke(f.browser, "createIntegration", "", key, integrationClientBody, 0)
		if r.Code != 201 {
			t.Fatalf("fresh Check retry=%d %s", r.Code, r.Body)
		}
		f.assertEffects(t, f.browser, "createIntegration", key, id, 1, r)
		if f.effects(t) != before {
			t.Fatal("race retry duplicated mutation")
		}
	})
	t.Run("typed_target_changes_after_official_Check_refuse", func(t *testing.T) {
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "updateIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := authorizationProofJSON(g)
		// A version-only change isolates the typed target guard from revision
		// capture. The legitimate transition writer is covered in the version case.
		f.exec(`UPDATE zasp_integrations SET version=version+1 WHERE id=$1`, integrationClientExisting)
		before := f.effects(t)
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "40001" {
			t.Fatalf("stale typed target=%v", err)
		}
		_ = tx.Rollback(f.ctx)
		if f.effects(t) != before {
			t.Fatal("stale target wrote effects")
		}
	})
	t.Run("overflow_and_foreign_deleted_targets_refuse_without_writes", func(t *testing.T) {
		t.Cleanup(func() {
			f.exec(`UPDATE zasp_integrations SET version=2,deleted_at=NULL,state='pending' WHERE id=$1`, integrationClientExisting)
			f.reconcile()
		})
		f.exec(`UPDATE zasp_integrations SET version=9223372036854775807 WHERE id=$1`, integrationClientExisting)
		before := f.effects(t)
		r := f.invoke(f.browser, "updateIntegration", integrationClientExisting, "client-overflow-key", integrationClientBody, 1)
		if r.Code != 409 || f.effects(t) != before {
			t.Fatalf("overflow=%d %s", r.Code, r.Body)
		}
		f.exec(`UPDATE zasp_integrations SET version=2,state='deleted',deleted_at=clock_timestamp() WHERE id=$1`, integrationClientExisting)
		f.reconcile()
		before = f.effects(t)
		for _, op := range []string{"getIntegration", "updateIntegration"} {
			r = f.invoke(f.browser, op, integrationClientExisting, "client-deleted-target", integrationClientBody, 1)
			if r.Code != 403 || f.effects(t) != before {
				t.Fatalf("deleted %s=%d", op, r.Code)
			}
		}
		const foreign = "pid_78200071-0000-4000-8000-000000000071"
		const workspace = "pid_78200072-0000-4000-8000-000000000072"
		const environment = "pid_78200073-0000-4000-8000-000000000073"
		const integration = "pid_78200074-0000-4000-8000-000000000074"
		f.exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Other','other.invalid')`, foreign)
		f.exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Other')`, foreign, workspace)
		f.exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Other','production')`, foreign, workspace, environment)
		f.exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name) VALUES($1,$2,$3,$4,'github','1','Other')`, foreign, workspace, environment, integration)
		before = f.effects(t)
		for _, op := range []string{"getIntegration", "updateIntegration"} {
			r = f.invoke(f.browser, op, integration, "client-foreign-target", integrationClientBody, 1)
			if r.Code != 403 || f.effects(t) != before {
				t.Fatalf("foreign %s=%d", op, r.Code)
			}
		}
	})
	t.Run("proofless_and_read_as_write_refuse_private_helpers_unavailable", func(t *testing.T) {
		before := f.effects(t)
		var callable bool
		if err := f.api.QueryRow(f.ctx, `SELECT has_function_privilege(current_user,'zasp_authorization80.integration_receipt_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','EXECUTE') OR has_function_privilege(current_user,'zasp_authorization80.integration_connector_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','EXECUTE')`).Scan(&callable); err != nil || callable {
			t.Fatalf("private writer callable=%t %v", callable, err)
		}
		var raw []byte
		err := f.api.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, f.nativeArgs("client-proofless-key", integrationClientExisting, "create", 0)...).Scan(&raw)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("proofless=%v", err)
		}
		g, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "getIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := authorizationProofJSON(g)
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof)); err != nil {
			t.Fatal(err)
		}
		err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, f.nativeArgs("client-view-as-write", integrationClientExisting, "update", 1)...).Scan(&raw)
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("view proof mutation=%v", err)
		}
		_ = tx.Rollback(f.ctx)
		if f.effects(t) != before {
			t.Fatal("wrong-purpose write changed product")
		}
	})
}

func TestP7IntegrationClientGuardedComposedPostgres(t *testing.T) {
	f := newIntegrationClientFixture(t, true)
	db := f.repo.database.(*PostgresJSONDatabase)
	if err := db.CurrentAuthorizationRuntimeReady(f.ctx, "zasp_discovery_api", authorizationFixtureAttestor(t).Version()); err != nil {
		t.Fatal("current compiled guarded composed readiness", err)
	}
	t.Logf("current compiled80=%s audit=%s; actual registered API readiness passed", migrations.ProductionAuthorizationEnforcement().Checksum(), migrations.AuthorizationAuditProfileChecksum())
	r := f.invoke(f.browser, "createIntegration", "", "client-composed-create", integrationClientBody, 0)
	if r.Code != 201 {
		t.Fatalf("composed create=%d %s", r.Code, r.Body)
	}
	var b struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &b)
	f.assertEffects(t, f.browser, "createIntegration", "client-composed-create", b.ID, 1, r)
	f.reconcile()
	g := f.invoke(f.browser, "getIntegration", b.ID, "", "", 0)
	if g.Code != 200 || g.Header().Get("ETag") != `"1"` {
		t.Fatalf("composed get=%d %s", g.Code, g.Body)
	}
	r = f.invoke(f.browser, "updateIntegration", b.ID, "client-composed-update", integrationClientBody, 1)
	if r.Code != 200 || r.Header().Get("ETag") != `"2"` {
		t.Fatalf("composed update=%d %s", r.Code, r.Body)
	}
	f.assertEffects(t, f.browser, "updateIntegration", "client-composed-update", b.ID, 2, r)
	f.freshReferenceSession(t)
	referenceID, referenceBody := f.createReference(t, "aws", "client-composed-reference-create")
	r = f.invokeReference(t, f.browser, referenceID, "client-composed-reference-complete", 1)
	if r.Code != 200 {
		t.Fatalf("composed actual reference=%d %s", r.Code, r.Body)
	}
	f.reconcile()
	r = f.invoke(f.browser, "getIntegration", referenceID, "", "", 0)
	if r.Code != 200 || r.Header().Get("ETag") != `"2"` {
		t.Fatalf("composed reference GET=%d %s", r.Code, r.Body)
	}
	r = f.invoke(f.browser, "updateIntegration", referenceID, "client-composed-reference-update", referenceBody, 2)
	if r.Code != 200 {
		t.Fatalf("composed reference update=%d %s", r.Code, r.Body)
	}
	versionedBody := `{"name":"Composed metadata","connector_key":"generic-webhook","configuration":{"destination_url":"https://hooks.example.test/receive","signing_secret_reference":"secret_ref_customer","signing_secret_version":"0123456789abcdef0123456789abcdef"}}`
	r = f.invoke(f.browser, "createIntegration", "", "client-composed-metadata-create", versionedBody, 0)
	if r.Code != 201 {
		t.Fatalf("composed versioned create=%d %s", r.Code, r.Body)
	}
	_ = json.Unmarshal(r.Body.Bytes(), &b)
	f.reconcile()
	g = f.invoke(f.browser, "getIntegration", b.ID, "", "", 0)
	if g.Code != 200 || !strings.Contains(g.Body.String(), "0123456789abcdef0123456789abcdef") {
		t.Fatalf("composed version metadata GET=%d %s", g.Code, g.Body)
	}
	var projected bool
	if err := f.owner.QueryRow(f.ctx, `SELECT i.configuration=(r.body->'configuration')-'signing_secret_version' AND (r.body->'configuration') ? 'signing_secret_version' FROM zasp_integrations i JOIN zasp_workflow_records r ON(r.organization_id,r.workspace_id,r.environment_id,r.id,r.kind)=(i.organization_id,i.workspace_id,i.environment_id,i.id,'integration') WHERE i.id=$1`, b.ID).Scan(&projected); err != nil || !projected {
		t.Fatalf("composed exact projection=%t %v", projected, err)
	}
	if err := db.CurrentAuthorizationRuntimeReady(f.ctx, "zasp_discovery_api", authorizationFixtureAttestor(t).Version()); err != nil {
		t.Fatal("final current composed readiness", err)
	}
}

// This exercises the retained native callback writer, not mounted callback
// admission. Both contenders use actual registered API connections.
func TestP7IntegrationClientCallbackRacePostgres(t *testing.T) {
	f := newIntegrationClientFixture(t)
	i := f.browser
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	digest := sha256.Sum256([]byte("owned callback update race"))
	attempt, cleanup, effect := "pid_78200131-0000-4000-8000-000000000031", "pid_78200132-0000-4000-8000-000000000032", "pid_78200133-0000-4000-8000-000000000033"
	var raw []byte
	if err := f.api.QueryRow(f.ctx, postgresConnectorStartOAuthSQL, o, w, e, attempt, integrationClientExisting, "github", p, digest[:], digest[:], "ref:oauth/pkce/race", digest[:], `["read:org","repo"]`, time.Now().Add(5*time.Minute), int64(1), json.RawMessage(`{"authorization_mode":"github_app"}`), cleanup, effect).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := f.api.QueryRow(f.ctx, postgresConnectorConsumeOAuthSQL, o, w, e, digest[:], p, digest[:]).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	provider, err := f.provider.Complete(f.ctx, "client-owned", "fixture-code", []byte("fixture-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	completion := OAuthCompletion{AttemptID: attempt, EffectID: effect, ConnectionID: "pid_78200134-0000-4000-8000-000000000034", ConnectionReference: provider.ConnectionReference, ProviderSubject: provider.ProviderSubject, CredentialID: "pid_78200135-0000-4000-8000-000000000035", CredentialClass: provider.CredentialClass, Metadata: provider.Metadata}
	metadata, completed := connectorOAuthCompletionDigest(completion)
	f.reconcile()
	g, err := f.authorizer.Authorize(f.ctx, i, i.credentialBinding, RoutedOperation{OperationID: "updateIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := authorizationProofJSON(g)
	args := f.nativeArgs("client-callback-racing-update", integrationClientExisting, "update", 1)
	args[13] = integrationClientCorrelation("client-callback-racing-update")
	second := connectRuntimeDataPlanePrincipal(t, f.ctx, f.dsn, "auth80_api")
	defer second.Close(context.Background())
	type outcome struct {
		callback bool
		err      error
	}
	done := make(chan outcome, 2)
	start := make(chan struct{})
	for n, conn := range []*pgx.Conn{f.api, second} {
		go func(callback bool, c *pgx.Conn) {
			<-start
			tx, err := c.Begin(f.ctx)
			if err != nil {
				done <- outcome{callback, err}
				return
			}
			defer tx.Rollback(context.Background())
			var body []byte
			if callback {
				err = tx.QueryRow(f.ctx, postgresConnectorCompleteOAuthSQL, o, w, e, completion.AttemptID, completion.EffectID, completion.ConnectionID, completion.ConnectionReference, completion.ProviderSubject, completion.CredentialID, completion.CredentialClass, metadata, completed[:]).Scan(&body)
			} else {
				_, err = tx.Exec(f.ctx, `SELECT zasp_authorization80.fence($1)`, string(proof))
				if err == nil {
					err = tx.QueryRow(f.ctx, postgresCurrentIntegrationMutateSQL, args...).Scan(&body)
				}
			}
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			done <- outcome{callback, err}
		}(n == 1, conn)
	}
	close(start)
	wins, conflicts, callbackWon := 0, 0, false
	for n := 0; n < 2; n++ {
		select {
		case result := <-done:
			if result.err == nil {
				wins++
				callbackWon = result.callback
			} else {
				var native *pgconn.PgError
				if !errors.As(result.err, &native) || !stringIn(native.Code, "40001", "23505", "40P01") {
					t.Fatal(result.err)
				}
				conflicts++
				t.Logf("native callback=%t loser=%s %s", result.callback, native.Code, native.Message)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("callback/update race did not join")
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
	operation, status := "updateIntegration", "pending_authorization"
	connectionCount := 0
	if callbackWon {
		operation, status, connectionCount = "completeIntegrationOAuth", "active", 1
	}
	var good bool
	err = f.owner.QueryRow(f.ctx, `SELECT
	 EXISTS(SELECT 1 FROM zasp_workflow_records r JOIN zasp_integrations i ON (r.organization_id,r.workspace_id,r.environment_id,r.id)=(i.organization_id,i.workspace_id,i.environment_id,i.id) WHERE r.id=$1 AND r.version=2 AND i.version=2 AND r.body->>'status'=$3)
	 AND (SELECT count(*) FROM zasp_workflow_audit WHERE resource_id=$1)=1
	 AND EXISTS(SELECT 1 FROM zasp_workflow_receipts q JOIN zasp_workflow_records r ON r.id=q.resource_id JOIN zasp_workflow_audit a ON a.audit_id=q.audit_id JOIN zasp_workflow_idempotency k ON k.operation=q.operation AND k.idempotency_key=q.idempotency_key WHERE q.resource_id=$1 AND q.operation=$2 AND q.resource_version=2 AND q.result=r.body AND a.operation=q.operation AND a.resource_version=2 AND k.response->'body'=q.result)
	 AND (SELECT count(*) FROM zasp_workflow_idempotency)=1 AND (SELECT count(*) FROM zasp_workflow_receipts)=1
	 AND (SELECT count(*) FROM zasp_integration_connections WHERE integration_id=$1)=$4
	 AND (SELECT count(*) FROM zasp_connector_credentials WHERE integration_id=$1)=$4
	 AND (SELECT count(*) FROM zasp_discovery_connection_subjects WHERE integration_id=$1)=$4`, integrationClientExisting, operation, status, connectionCount).Scan(&good)
	if err != nil || !good {
		t.Fatalf("callbackWon=%t exact winner effects=%t %v", callbackWon, good, err)
	}
	f.reconcile()
	get := f.invoke(i, "getIntegration", integrationClientExisting, "", "", 0)
	if get.Code != 200 || get.Header().Get("ETag") != `"2"` {
		t.Fatalf("winner read=%d %s", get.Code, get.Body)
	}
}
