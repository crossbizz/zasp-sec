package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// This joins installed canonical61+79+80, registered API/outbox roles, real
// credential authentication, official FGA Check and the actual sensor reader.
// It does not construct the full API/Temporal/provider runtime.
func TestP7AuthorizationLiveModelPostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE auth80_live_agent_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE auth80_live_agent_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; SELECT zasp_security_agent_register_principals(session_user,'auth80_live_agent_api','auth80_live_agent_worker')`)
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const sibling = "pid_89000001-0000-4000-8000-000000000001"
	const sensor = "pid_89000002-0000-4000-8000-000000000002"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Live authorization','live-authorization.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Live authorization')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Selected','production'),($1,$2,$4,'Sibling','production')`, o, w, e, sibling)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-live80','member-live80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Selected','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('live80-session','sha256'),'session-live80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Live sensor','otlp','active')`, o, w, e, sensor)
	// An active sensor's public contract includes a live issued token expiry.
	exec(`SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,'pid_89000003-0000-4000-8000-000000000003',1,1,digest('live80-locator','sha256'),digest('live80-salt','sha256'),digest('live80-hash','sha256'),clock_timestamp()+interval '1 day')`, o, w, e, sensor)
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	client, config := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, config.StoreID, config.ModelID)
	reconcile := func() {
		t.Helper()
		receipt, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID)
		if err != nil || !receipt.Applied {
			t.Fatalf("reconcile=%+v error=%v", receipt, err)
		}
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err = db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	i, err = sessions.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "live80-session"})
	if err != nil {
		t.Fatal(err)
	}
	if len(i.Permissions) != 0 || i.credentialBinding.ID != "session-live80" {
		t.Fatal("authentication granted role permissions or lost credential binding")
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	a := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: config.StoreID, ModelID: config.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	route := RoutedOperation{OperationID: "getSensor", PathParameters: map[string]string{"id": sensor}}
	if _, err = a.Authorize(ctx, i, i.credentialBinding, route); !errors.Is(err, authorization.ErrPending) {
		t.Fatalf("pending generation usable: %v", err)
	}
	reconcile()
	grant, err := a.Authorize(ctx, i, i.credentialBinding, route)
	if err != nil {
		t.Fatal(err)
	}
	sensors, err := NewSensorPublicRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	agentAPI := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_live_agent_api")
	defer agentAPI.Close(context.Background())
	agentDB, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: agentAPI})
	if err = agentDB.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	agentRepository, err := NewSecurityAgentPostgresRepository(agentDB)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewRepositoryIdentityProvider(fixedExternalAuthenticator{}, &fixedGrantResolver{})
	if err != nil {
		t.Fatal(err)
	}
	cookie := fixtureCookiePolicy()
	cookie.Clock = func() time.Time { return time.Now().UTC() }
	dependencies, authenticate, err := NewProductionHandlersWithSecurityAgent(sessions, agentRepository, provider, http.NotFoundHandler(), cookie)
	if err != nil {
		t.Fatalf("actual production handlers: %v", err)
	}
	dependencies.Authorizer = a
	router, err := NewComposition(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: authenticate}, router)
	if err != nil {
		t.Fatal(err)
	}
	call := func() int {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/sensors/"+sensor, nil)
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "live80-session"})
		r.Header.Set(expectedScopeHeader, expectedScopeValue(i.Scope))
		w := httptest.NewRecorder()
		mounted.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Logf("sensor HTTP %d %s", w.Code, w.Body.String())
		}
		return w.Code
	}
	if status := call(); status != 200 {
		t.Fatalf("actual checked sensor reader=%d", status)
	}
	orgRequest := authorization.CheckRequest{PrincipalKind: "user", PrincipalID: p, OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ResourceType: "organization_identity", ResourceID: o, Permission: "manage_identity"}
	check := func(request authorization.CheckRequest, want bool) {
		t.Helper()
		decision, err := authorization.CheckRevision(ctx, projection, checker, request, config.StoreID, config.ModelID)
		if err != nil || decision.Decision.Allowed != want {
			t.Fatalf("live decision allowed=%v want=%v error=%v", decision.Decision.Allowed, want, err)
		}
	}
	check(orgRequest, true)
	siblingRequest := orgRequest
	siblingRequest.ResourceType = "environment"
	siblingRequest.ResourceID = sibling
	siblingRequest.EnvironmentID = sibling
	siblingRequest.Permission = "view"
	check(siblingRequest, false)
	exec(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE(principal_id,organization_id)=($1,$2)`, p, o)
	checkedCtx := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	if _, err = sensors.GetSensor(checkedCtx, i.Scope, sensor); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("old role revision reached read: %v", err)
	}
	reconcile()
	check(orgRequest, false)
	// Publish an identical model as a new generation in the owned store only.
	raw, err := os.ReadFile("../authorization/model.json")
	if err != nil {
		t.Fatal(err)
	}
	var model fga.ClientWriteAuthorizationModelRequest
	if json.Unmarshal(raw, &model) != nil {
		t.Fatal("invalid model")
	}
	written, err := client.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		t.Fatal("owned new-generation model rejected")
	}
	oldModel := config.ModelID
	config.ModelID = written.AuthorizationModelId
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, config.StoreID, config.ModelID)
	if _, err = a.Authorize(ctx, i, i.credentialBinding, route); err == nil {
		t.Fatal("old model generation stayed usable")
	}
	writer, err = authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal(err)
	}
	checker, err = authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	a.Checker = checker
	a.ModelID = config.ModelID
	if _, err = a.Authorize(ctx, i, i.credentialBinding, route); !errors.Is(err, authorization.ErrPending) {
		t.Fatalf("new generation before projection=%v", err)
	}
	reconcile()
	check(orgRequest, false)
	if status := call(); status != 200 {
		t.Fatalf("fresh generation reader=%d", status)
	}
	exec(`UPDATE zasp_identity_memberships SET role='security_admin' WHERE(principal_id,organization_id)=($1,$2)`, p, o)
	reconcile()
	check(orgRequest, true)
	check(siblingRequest, false)
	exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-live80'`)
	if status := call(); status != 401 {
		t.Fatalf("revoked credential read=%d", status)
	}
	t.Logf("installed80 real FGA generation transition old=%s new=%s; org-role revoke/regrant and sibling denial verified", oldModel, config.ModelID)
}
