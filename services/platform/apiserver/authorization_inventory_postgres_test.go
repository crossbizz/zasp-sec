package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Real PostgreSQL, separate registered login, compiled source guard and signed
// fence; only permission-specific OpenFGA Check is controlled in this fixture.
func TestP7InventoryAuthorizationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	runner := migrateP7Authorization(t, ctx, owner)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE inventory80_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE inventory80_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; SELECT public.zasp_security_agent_register_principals(session_user,'inventory80_api','inventory80_worker')`)
	if err := runner.UpProductionAuthorizationInventoryProfile(ctx); err != nil {
		t.Fatalf("native profile installation: %v", err)
	}
	if err := runner.UpProductionAuthorizationInventoryProfile(ctx); err != nil {
		t.Fatalf("native profile repeat: %v", err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "inventory80_api")
	defer api.Close(context.Background())
	core := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer core.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	db.currentAuthorization = true
	coreDB, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: core})
	coreDB.currentAuthorization = true
	if err := db.CurrentAuthorizationInventoryReady(ctx); err != nil {
		t.Fatalf("native API guard: %v", err)
	}
	if _, err := NewPostgresInventoryRepository(coreDB); err == nil {
		t.Fatal("discovery login admitted current inventory")
	}
	repo, err := NewPostgresInventoryRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.Permissions = []string{"view", "manage_workflows"}
	identity.CSRFToken = strings.Repeat("x", 32)
	identity.FreshAuthenticated = false
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Inventory authorization','inventory-auth.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Inventory authorization')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'inventory-org','inventory-member','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view","manage_workflows"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('inventory-credential','sha256'),'session-inventory-current',$1,$2,$3,$4,'["view","manage_workflows"]',repeat('x',32),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_inventory_cutover_state(organization_id,workspace_id,environment_id,phase,rule_catalog_digest,legacy_digest,typed_digest,backfilled_at,equivalent_at,cutover_at) VALUES($1,$2,$3,'cutover','44820a38e96d80318165fc2333fd851cd932d2704d380a1199d569d1d0778f30',decode(repeat('11',32),'hex'),decode(repeat('11',32),'hex'),now(),now(),now())`, o, w, e)
	id := func(n int) string { return fmt.Sprintf("pid_97000000-0000-4000-8000-%012d", n) }
	agent, integration, syncID, snapshot := id(1), id(2), id(3), id(4)
	exec(`INSERT INTO zasp_product_api_tokens(token_digest,id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('inventory-pat','sha256'),$1,$2,$3,$4,$5,'["view","manage_workflows"]',clock_timestamp()+interval '1 hour')`, id(90), p, o, w, e)
	exec(`INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,state) VALUES($1,$2,$3,$4,'kubernetes','1.0.0','Inventory provenance','active')`, o, w, e, integration)
	exec(`INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version) VALUES($1,$2,$3,$4,$5,'inventory-provenance',decode(repeat('ab',32),'hex'),'manual',$6,'parser_v1','tool_v1')`, o, w, e, syncID, integration, p)
	exec(`INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at) VALUES($1,$2,$3,$4,$5,$6,1,'kubernetes','s3://zasp-evidence/inventory/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,now(),now())`, o, w, e, snapshot, integration, syncID)
	kinds := map[string]InventoryKind{agent: InventoryKindAgent, id(10): InventoryKindIdentity, id(11): InventoryKindIdentity, id(12): InventoryKindIdentity, id(13): InventoryKindTool, id(14): InventoryKindRuntime, id(15): InventoryKindAsset, id(16): InventoryKindAgent}
	for entity, kind := range kinds {
		evidence := id(100 + mustInventoryFixtureNumber(entity))
		native := "inventory-" + entity
		exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes,confidence_basis_points,winning_evidence_id,winning_snapshot_id,winning_generation,projection_version,winning_integration_id,winning_provider,winning_source,winning_source_native_id,winning_identity_rule,winning_source_projection) VALUES($1,$2,$3,$4,'agent_endpoint','Inventory fixture','active',now(),now(),$5,'2026-09-20T12:00:00Z','2026-10-03T12:00:00Z','{}',9500,$6,$7,1,1,$8,'kubernetes','kubernetes',$9,1,1)`, o, w, e, entity, string(kind), evidence, snapshot, integration, native)
		exec(`INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',now(),'kubernetes',1,$4,$9,'version-1',128,'tool_v1')`, o, w, e, evidence, integration, snapshot, entity, "s3://zasp-evidence/inventory/"+entity+".json", entity+".json")
		exec(`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version) VALUES($1,$2,$3,$4,'kubernetes',$5,$6,$7,'present','{}',now(),now(),'kubernetes','kubernetes_agent','Inventory fixture','{}','kubernetes_agent',$8,1,decode(repeat('ab',32),'hex'),$9,9500,'2026-09-20T12:00:00Z','2026-10-03T12:00:00Z',1,80,1)`, o, w, e, integration, entity, native, snapshot, string(kind), evidence)
	}
	for n := 0; n < 3; n++ {
		exec(`INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,'uses_identity',$4,now(),now())`, o, w, e, id(30+n), integration, snapshot, agent, id(10+n))
		exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,'exact','otlp','tool','invoke','Stored agent event',$4,'2026-09-20T12:00:00Z')`, o, w, e, id(60+n), id(50+n), agent)
	}
	exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,$4,$5,$6,'strong','otlp','tool','invoke','Other agent event',$4,'2026-09-20T10:00:00Z')`, o, w, e, id(69), id(50), id(16))
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
	resolver, _ := NewPostgresAuthorizationResolverWithSecurityAgent(coreDB, db)
	allowed := map[string]bool{}
	for entity, kind := range kinds {
		if entity != id(11) {
			var canonical string
			if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,$4,$5)`, o, w, e, string(kind), entity).Scan(&canonical); err != nil {
				t.Fatal(err)
			}
			allowed[canonical] = true
		}
	}
	for _, s := range []string{id(50), id(52)} {
		var canonical string
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,'session',$4)`, o, w, e, s).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		allowed[canonical] = true
	}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: authorizationDecisionFixture{allow: allowed, model: model}, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-inventory-current", Digest: sha256.Sum256([]byte("inventory-credential"))}
	grant := func(op, target string) context.Context {
		t.Helper()
		g, err := authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: op, PathParameters: map[string]string{"id": target}})
		if err != nil {
			t.Fatal(err)
		}
		return context.WithValue(ctx, requestAuthorizationContextKey{}, g)
	}
	parent, _ := domain.ParseProductID(agent)

	t.Run("required parent, separate login, scope and deadline", func(t *testing.T) {
		var parentKey string
		if err := owner.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,'agent',$4)`, o, w, e, agent).Scan(&parentKey); err != nil {
			t.Fatal(err)
		}
		allowed[parentKey] = false
		for _, op := range []string{"getAgentCapabilities", "getAgentRelationships", "listAgentSessions"} {
			if _, err := authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: op, PathParameters: map[string]string{"id": agent}}); !errors.Is(err, ErrAuthorizationDenied) {
				t.Errorf("denied parent %s: %v", op, err)
			}
		}
		allowed[parentKey] = true
		single, _ := NewPostgresAuthorizationResolver(coreDB)
		if _, err := single.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}}); !errors.Is(err, authorization.ErrUnavailable) {
			t.Fatalf("missing secondary fell back: %v", err)
		}
		same, _ := NewPostgresAuthorizationResolverWithSecurityAgent(coreDB, coreDB)
		if _, err := same.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}}); !errors.Is(err, authorization.ErrUnavailable) {
			t.Fatalf("same native principal fallback: %v", err)
		}
		otherWorkspace, _ := domain.ParseProductID(id(99))
		other := identity
		other.Scope, _ = domain.NewScope(identity.Scope.OrganizationID(), otherWorkspace, identity.Scope.EnvironmentID())
		if _, err := authorizer.Authorize(ctx, other, binding, RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}}); err == nil {
			t.Fatal("cross-workspace agent admitted")
		}
		expired, stop := context.WithCancel(ctx)
		stop()
		start := time.Now()
		if err := db.CurrentAuthorizationInventoryReady(expired); err == nil || time.Since(start) > time.Second {
			t.Fatalf("native guard cancellation refused too late: %v", err)
		}

	})
	t.Run("native shortcuts and profile tamper refuse", func(t *testing.T) {
		for _, q := range []string{postgresInventoryDetailSQL, postgresInventoryCapabilitiesSQL, postgresInventoryRelationshipsSQL, postgresInventorySessionsSQL, postgresInventoryUpdateAgentSQL} {
			args := []any{o, w, e, agent, InventoryKindAgent}
			if q != postgresInventoryDetailSQL {
				args = []any{o, w, e, agent, "", 1}
			}
			if q == postgresInventoryUpdateAgentSQL {
				args = []any{o, w, e, p, agent, "legacy-rejected", int64(1), "security", "platform", json.RawMessage(`[]`), id(82), id(83)}
			}
			_, err := api.Exec(ctx, q, args...)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "42501" {
				t.Errorf("legacy shortcut accepted: %v", err)
			}
		}
		_, err := api.Exec(ctx, postgresCurrentInventoryDetailSQL, o, w, e, agent, string(InventoryKindAgent), migrations.AuthorizationInventoryProfileChecksum())
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("unguarded native profile consumer: %v", err)
		}
		checkedList := grant("listIdentities", "")
		var original string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('zasp_authorization80_inventory.ready(text)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		exec(`CREATE OR REPLACE FUNCTION zasp_authorization80_inventory.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT true'`)
		defer exec(original)
		if err := db.CurrentAuthorizationInventoryReady(ctx); err == nil {
			t.Fatal("committed mutable ready accepted by API login")
		}
		if _, err := repo.ListInventoryPage(checkedList, identity.Scope, InventoryKindIdentity, "", 1); err == nil {
			t.Fatal("Check-before-tamper list grant reached native effect")
		}

	})
	t.Run("current inventory list filters before lookahead on separate login", func(t *testing.T) {
		checked := grant("listIdentities", "")
		statement := `SELECT zasp_authorization80.inventory_page($1,$2,$3,$4,NULLIF($5,''),$6)`
		if _, err := coreDB.QueryJSON(checked, statement, o, w, e, "identity", "", 1); err == nil {
			t.Fatal("current inventory list grant borrowed primary discovery adapter")
		}
		first, err := repo.ListInventoryPage(grant("listIdentities", ""), identity.Scope, InventoryKindIdentity, "", 1)
		if err != nil || len(first.Items) != 1 || first.Items[0].ID != id(10) || first.NextKey == "" {
			t.Fatalf("identity list first=%+v %v", first, err)
		}
		next, err := repo.ListInventoryPage(grant("listIdentities", ""), identity.Scope, InventoryKindIdentity, first.NextKey, 1)
		if err != nil || len(next.Items) != 1 || next.Items[0].ID != id(12) || next.NextKey != "" {
			t.Fatalf("identity list next=%+v %v", next, err)
		}
	})
	t.Run("all stored detail kinds", func(t *testing.T) {
		for _, tc := range []struct {
			target string
			kind   InventoryKind
			op     string
		}{{agent, InventoryKindAgent, "getAgent"}, {id(10), InventoryKindIdentity, "getIdentity"}, {id(13), InventoryKindTool, "getTool"}, {id(14), InventoryKindRuntime, "getRuntime"}, {id(15), InventoryKindAsset, "getAsset"}} {
			target, _ := domain.ParseProductID(tc.target)
			d, err := repo.GetInventory(grant(tc.op, tc.target), identity.Scope, target, tc.kind)
			if err != nil || d.Summary.ID != tc.target || len(d.Sources) != 1 || len(d.Evidence) != 1 {
				t.Errorf("%s native detail=%+v error=%v", tc.op, d, err)
			}
		}
	})
	t.Run("recorded sessions require completed scope cutover", func(t *testing.T) {
		exec(`UPDATE zasp_inventory_cutover_state SET phase='equivalent',cutover_at=NULL WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e)
		sessions, err := repo.ListAgentSessionsPage(grant("listAgentSessions", agent), identity.Scope, parent, "", 1)
		exec(`UPDATE zasp_inventory_cutover_state SET phase='cutover',cutover_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e)
		if err == nil {
			t.Fatalf("pre-cutover scope disclosed recorded sessions: %+v", sessions)
		}
	})
	t.Run("filtered lookahead and real mixed-agent sessions", func(t *testing.T) {
		c := grant("getAgentCapabilities", agent)
		first, err := repo.ListAgentCapabilitiesPage(c, identity.Scope, parent, "", 1)
		if err != nil || len(first.Items) != 1 || first.Items[0].TargetID != id(10) || first.NextKey == "" {
			t.Fatalf("cap first=%+v %v", first, err)
		}
		next, err := repo.ListAgentCapabilitiesPage(grant("getAgentCapabilities", agent), identity.Scope, parent, first.NextKey, 1)
		if err != nil || len(next.Items) != 1 || next.Items[0].TargetID != id(12) || next.NextKey != "" {
			t.Fatalf("cap next=%+v %v", next, err)
		}
		rel, err := repo.ListAgentRelationshipsPage(grant("getAgentRelationships", agent), identity.Scope, parent, "", 1)
		if err != nil || len(rel.Items) != 1 || rel.Items[0].ToID != id(10) || rel.NextKey == "" {
			t.Fatalf("relationship first=%+v %v", rel, err)
		}
		rel, err = repo.ListAgentRelationshipsPage(grant("getAgentRelationships", agent), identity.Scope, parent, rel.NextKey, 1)
		if err != nil || len(rel.Items) != 1 || rel.Items[0].ToID != id(12) || rel.NextKey != "" {
			t.Fatalf("relationship next=%+v %v", rel, err)
		}
		sessions, err := repo.ListAgentSessionsPage(grant("listAgentSessions", agent), identity.Scope, parent, "", 1)
		if err != nil || len(sessions.Items) != 1 || sessions.Items[0].ID != id(50) || sessions.Items[0].StartedAt != "2026-09-20T12:00:00Z" || sessions.NextKey == "" {
			t.Fatalf("session first=%+v %v", sessions, err)
		}
		sessions, err = repo.ListAgentSessionsPage(grant("listAgentSessions", agent), identity.Scope, parent, sessions.NextKey, 1)
		if err != nil || len(sessions.Items) != 1 || sessions.Items[0].ID != id(52) || sessions.NextKey != "" {
			t.Fatalf("session next=%+v %v", sessions, err)
		}
	})
	t.Run("mounted API cursor bound to operation", func(t *testing.T) {
		handler, _ := newInventoryHTTPHandler(repo, []byte(strings.Repeat("k", 32)))
		var ops []Operation
		for _, op := range []string{"getAgentCapabilities", "getAgentRelationships", "listAgentSessions"} {
			policy, _ := authorization.LookupOperation(op)
			ops = append(ops, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: op, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession, CredentialBearerToken}, Handler: handler})
		}
		router, err := NewRouter(ops)
		if err != nil {
			t.Fatal(err)
		}
		router.(*operationRouter).authorizer = authorizer
		current := identity
		current.credentialBinding = binding
		read := func(path string) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set(expectedScopeHeader, expectedScopeValue(current.Scope))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request.WithContext(context.WithValue(ctx, identityContextKey{}, current)))
			return response
		}
		absent := read("/api/v1/agents/" + id(99) + "/sessions?limit=1")
		if absent.Code != 403 || decodeErrorCode(t, absent) != "request_forbidden" {
			t.Fatalf("missing agent parent status=%d body=%s", absent.Code, absent.Body.String())
		}
		response := read("/api/v1/agents/" + agent + "/sessions?limit=1")
		if response.Code != 200 {
			t.Fatalf("mounted sessions=%d %s", response.Code, response.Body.String())
		}
		var page struct {
			PageInfo struct {
				NextCursor string `json:"next_cursor"`
			} `json:"page_info"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.PageInfo.NextCursor == "" {
			t.Fatalf("API cursor missing: %s", response.Body.String())
		}
		response = read("/api/v1/agents/" + agent + "/relationships?limit=1&cursor=" + page.PageInfo.NextCursor)
		if response.Code != 404 {
			t.Fatalf("cross-operation cursor=%d %s", response.Code, response.Body.String())
		}
		current.CredentialKind = CredentialBearerToken
		current.CSRFToken = ""
		current.credentialBinding = CredentialBinding{Kind: CredentialBearerToken, ID: id(90), Digest: sha256.Sum256([]byte("inventory-pat")), PATCeiling: []string{"view", "manage_workflows"}}
		response = read("/api/v1/agents/" + agent + "/sessions?limit=1&cursor=" + page.PageInfo.NextCursor)
		if response.Code != 404 {
			t.Fatalf("browser cursor reused by PAT=%d %s", response.Code, response.Body.String())
		}
		current = identity
		current.credentialBinding = binding
		exec(`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, p)
		exec(`UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, p)
		reconcile()
		response = read("/api/v1/agents/" + agent + "/sessions?limit=1&cursor=" + page.PageInfo.NextCursor)
		if response.Code != 404 {
			t.Fatalf("obsolete revision cursor=%d %s", response.Code, response.Body.String())
		}
	})
	t.Run("native PAT ceilings and revocation", func(t *testing.T) {
		pat := identity
		pat.CredentialKind = CredentialBearerToken
		pat.CSRFToken = ""
		patBinding := CredentialBinding{Kind: CredentialBearerToken, ID: id(90), Digest: sha256.Sum256([]byte("inventory-pat")), PATCeiling: []string{"view", "manage_workflows"}}
		patGrant, err := authorizer.Authorize(ctx, pat, patBinding, RoutedOperation{OperationID: "getAgent", PathParameters: map[string]string{"id": agent}})
		if err != nil {
			t.Fatal(err)
		}
		c := context.WithValue(ctx, requestAuthorizationContextKey{}, patGrant)
		detail, err := repo.GetInventory(c, pat.Scope, parent, InventoryKindAgent)
		if err != nil || detail.Summary.ID != agent {
			t.Fatalf("native PAT detail=%+v %v", detail, err)
		}
		ceiling := patBinding
		ceiling.PATCeiling = []string{"view"}
		if _, err := authorizer.Authorize(ctx, pat, ceiling, RoutedOperation{OperationID: "updateAgent", PathParameters: map[string]string{"id": agent}}); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("PAT mutation ceiling: %v", err)
		}
		mutation, err := authorizer.Authorize(ctx, pat, patBinding, RoutedOperation{OperationID: "updateAgent", PathParameters: map[string]string{"id": agent}})
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_product_api_tokens SET revoked_at=clock_timestamp() WHERE id=$1`, id(90))
		if _, err := repo.GetInventory(c, pat.Scope, parent, InventoryKindAgent); err == nil {
			t.Fatal("revoked PAT passed native read fence")
		}
		if _, err := repo.UpdateAgentOwnership(context.WithValue(ctx, requestAuthorizationContextKey{}, mutation), pat, parent, 1, "revoked-pat-owner", AgentOwnershipInput{Owner: "denied", Team: "denied", Tags: []string{}}, id(85), id(86)); err == nil {
			t.Fatal("revoked PAT passed native mutation fence")
		}
		exec(`UPDATE zasp_product_api_tokens SET revoked_at=NULL WHERE id=$1`, id(90))
		reconcile()
	})
	t.Run("ownership idempotency and credential revocation fence", func(t *testing.T) {
		c := grant("updateAgent", agent)
		result, err := repo.UpdateAgentOwnership(c, identity, parent, 1, "inventory-owner-key", AgentOwnershipInput{Owner: "security", Team: "platform", Tags: []string{"reviewed"}}, id(80), id(81))
		if err != nil || result.Agent.Version != 2 || result.Agent.Owner != "security" {
			t.Fatalf("ownership=%+v %v", result, err)
		}
		reconcile()
		result, err = repo.UpdateAgentOwnership(grant("updateAgent", agent), identity, parent, 1, "inventory-owner-key", AgentOwnershipInput{Owner: "security", Team: "platform", Tags: []string{"reviewed"}}, id(80), id(81))
		if err != nil || !result.Replayed {
			t.Fatalf("ownership replay=%+v %v", result, err)
		}
		pat := identity
		pat.CredentialKind = CredentialBearerToken
		pat.CSRFToken = ""
		patBinding := CredentialBinding{Kind: CredentialBearerToken, ID: id(90), Digest: sha256.Sum256([]byte("inventory-pat")), PATCeiling: []string{"view", "manage_workflows"}}
		patGrant, err := authorizer.Authorize(ctx, pat, patBinding, RoutedOperation{OperationID: "updateAgent", PathParameters: map[string]string{"id": agent}})
		if err != nil {
			t.Fatal(err)
		}
		result, err = repo.UpdateAgentOwnership(context.WithValue(ctx, requestAuthorizationContextKey{}, patGrant), pat, parent, 1, "inventory-owner-key", AgentOwnershipInput{Owner: "security", Team: "platform", Tags: []string{"reviewed"}}, id(80), id(81))
		if err != nil || !result.Replayed {
			t.Fatalf("native PAT permitted replay without fresh auth: %+v %v", result, err)
		}
		staleRevision := grant("getAgent", agent)
		exec(`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, p)
		if _, err := repo.GetInventory(staleRevision, identity.Scope, parent, InventoryKindAgent); err == nil {
			t.Fatal("membership revocation after Check passed fence")
		}
		exec(`UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, p)
		reconcile()
		stale := grant("getAgent", agent)
		exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-inventory-current'`)
		_, err = repo.GetInventory(stale, identity.Scope, parent, InventoryKindAgent)
		if err == nil {
			t.Fatal("revoked browser credential passed native fence")
		}
		var version int64
		var ownerValue string
		if err := owner.QueryRow(ctx, `SELECT entity.annotation_version,annotation.owner_value FROM zasp_inventory_entities entity JOIN zasp_inventory_annotations annotation ON(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id)=(annotation.organization_id,annotation.workspace_id,annotation.environment_id,annotation.entity_id) WHERE entity.id=$1`, agent).Scan(&version, &ownerValue); err != nil || version != 2 || ownerValue != "security" {
			t.Fatalf("persisted mutation version=%d owner=%s err=%v", version, ownerValue, err)
		}
	})
	t.Run("blocked native fence respects finite deadline", func(t *testing.T) {
		exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-inventory-current'`)
		reconcile()
		checked := grant("getAgent", agent)
		holder, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback(context.Background())
		if _, err := holder.Exec(ctx, `LOCK TABLE public.zasp_product_sessions IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(checked, 80*time.Millisecond)
		defer stop()
		start := time.Now()
		if _, err := repo.GetInventory(bounded, identity.Scope, parent, InventoryKindAgent); err == nil || time.Since(start) > time.Second {
			t.Fatalf("blocked native fence failed finite deadline: %v", err)
		}
	})

}
func mustInventoryFixtureNumber(id string) int { var n int; fmt.Sscanf(id[28:], "%d", &n); return n }
