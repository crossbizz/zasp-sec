package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

func TestP7SessionSearchAuthorizationPostgres(t *testing.T) {
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
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Search authorization','search-auth.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Search authorization')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-search80','member-search80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('search80-credential','sha256'),'session-search80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	const denied = "pid_87000001-0000-4000-8000-000000000001"
	const allowed = "pid_87000002-0000-4000-8000-000000000002"
	for _, id := range []string{denied, allowed} {
		exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time,sandbox_id,sandbox_source_sensor_id) VALUES($1,$2,$3,$4,$4,$5,'exact','otlp','tool','invoke','Search event',$4,'2026-09-20T12:00:00Z','sandbox-recorded',$5)`, o, w, e, id, p)
	}
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
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	resolver, _ := NewPostgresAuthorizationResolver(database)
	checker := authorizationDecisionFixture{allow: map[string]bool{allowed: true}, model: model}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-search80", Digest: sha256.Sum256([]byte("search80-credential"))}
	grantFor := func(t *testing.T) context.Context {
		t.Helper()
		c := context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{"kind": {"runtime"}})
		grant, err := authorizer.Authorize(c, identity, credential, RoutedOperation{OperationID: "listSessions"})
		if err != nil {
			t.Fatal(err)
		}
		return context.WithValue(c, requestAuthorizationContextKey{}, grant)
	}
	parameters := map[string]string{"kind": "runtime", "limit": "1"}
	for _, sandbox := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "sandbox50"}[sandbox], func(t *testing.T) {
			index := &sessionQueryIndex{page: searchdriver.SessionSearchPage{InvestigationIDs: []string{allowed}, After: allowed}}
			repository := &PostgresRepository{database: database, runtimeSessionSearch: index, currentAuthorization: true, sandboxSessionSearch: sandbox}
			c := grantFor(t)
			body, err := repository.ReadAdministration(c, identity, "listSessions", parameters)
			if err != nil {
				t.Fatalf("checked installed search: %v", err)
			}
			var page struct {
				Items []struct {
					ID    string `json:"id"`
					Count int    `json:"event_count"`
				}
				Search json.RawMessage
			}
			if json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Items[0].ID != allowed || page.Items[0].Count != 1 || page.Search != nil {
				t.Fatalf("restricted hydrated page=%s", body)
			}
			if !index.filters.AuthorizationRestricted || len(index.filters.AllowedInvestigationIDs) != 1 || index.filters.AllowedInvestigationIDs[0] != allowed {
				t.Fatalf("pre-aggregation restriction absent: %+v", index.filters)
			}
			// Call SQL directly to prove provider validation is not the hydration fence.
			statement := "SELECT zasp_authorization80.runtime_session_query_hydrate($1,$2,$3,$4,$5)"
			if sandbox {
				statement = "SELECT zasp_authorization80.runtime_sandbox_query_hydrate($1,$2,$3,$4,$5)"
			}
			if leaked, err := database.QueryJSON(c, statement, o, w, e, p, []string{denied}); err == nil || leaked != nil {
				t.Fatalf("SQL hydrated denied candidate: %s %v", leaked, err)
			}
			checker.allow[e] = true
			environmentCtx := grantFor(t)
			environmentGrant, _ := requestAuthorizationFromContext(environmentCtx)
			if !environmentGrant.EnvironmentView {
				t.Fatal("separate environment Check did not grant status capability")
			}
			if body, err := repository.ReadAdministration(environmentCtx, identity, "listSessions", parameters); err != nil || json.Unmarshal(body, &page) != nil || len(page.Search) == 0 {
				t.Fatalf("environment-view status absent: %s %v", body, err)
			}
			delete(checker.allow, e)
			// Changing authorization after the index response must abort; no stale retry.
			index.onSearch = func() {
				exec(`UPDATE zasp_identity_memberships SET role=CASE role WHEN 'read_only_viewer' THEN 'security_admin' ELSE 'read_only_viewer' END WHERE principal_id=$1 AND organization_id=$2`, p, o)
				reconcile()
			}
			before := index.calls
			if leaked, err := repository.ReadAdministration(c, identity, "listSessions", parameters); !errors.Is(err, ErrRepositoryConflict) || leaked != nil || index.calls != before+1 {
				t.Fatalf("stale revision admitted or retried: %s %v calls=%d", leaked, err, index.calls-before)
			}
			index.onSearch = nil
			if leaked, err := repository.ReadAdministration(c, identity, "listSessions", parameters); !errors.Is(err, ErrRepositoryConflict) || leaked != nil {
				t.Fatalf("old Check reused: %s %v", leaked, err)
			}
			if body, err := repository.ReadAdministration(grantFor(t), identity, "listSessions", parameters); err != nil || len(body) == 0 {
				t.Fatalf("fresh Check failed: %s %v", body, err)
			}
			delete(checker.allow, allowed)
			deniedCtx := grantFor(t)
			if leaked, err := database.QueryJSON(deniedCtx, statement, o, w, e, p, []string{allowed}); err == nil || leaked != nil {
				t.Fatalf("empty current allow set hydrated row: %s %v", leaked, err)
			}
			index.page = searchdriver.SessionSearchPage{InvestigationIDs: []string{}}
			page.Search = nil
			if body, err := repository.ReadAdministration(deniedCtx, identity, "listSessions", parameters); err != nil || json.Unmarshal(body, &page) != nil || len(page.Items) != 0 || page.Search != nil {
				t.Fatalf("empty checked search leaked rows/status: %s %v", body, err)
			}
			checker.allow[allowed] = true
		})
	}
	t.Log("installed full61+79+80, controlled index and Check responses, real API SQL fence; no live OpenSearch/FGA claim")
}
