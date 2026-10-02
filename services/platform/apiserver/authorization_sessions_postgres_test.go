package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Exercises installed SQL80 through the real transaction fence. A denied row
// sorting first must never consume the lookahead limit or expose its counts.
func TestP7SessionAuthorizationPostgres(t *testing.T) {
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
	identity.CSRFToken = strings.Repeat("x", 32)
	identity.CredentialKind = CredentialBrowserSession
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Session authorization','session-auth.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Session authorization')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-session80','member-session80','read_only_viewer',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('session80-credential','sha256'),'session-current',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	runtimeIDs := []string{"pid_84000001-0000-4000-8000-000000000001", "pid_84000002-0000-4000-8000-000000000002", "pid_84000003-0000-4000-8000-000000000003"}
	consoleIDs := []string{"session-authz-1", "session-authz-2", "session-authz-3"}
	events := map[string]string{}
	for i, id := range runtimeIDs {
		exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest($1,'sha256'),$1,$2,$3,$4,$5,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, consoleIDs[i], p, o, w, e)
		for j := 0; j < 3-i; j++ {
			event := fmt.Sprintf("pid_85000000-0000-4000-8000-%012d", i*10+j+1)
			events[id] = event
			exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,session_id,agent_id,confidence,source,event_class,action,title,evidence_id,event_time,sandbox_id,sandbox_source_sensor_id) VALUES($1,$2,$3,$4,$5,$6,'exact','otlp','tool','invoke','Recorded session event',$4,'2026-09-20T12:00:00Z','sandbox-recorded',$6)`, o, w, e, event, id, p)
		}
		exec(`INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES($1,$2,$3,'tool','Recorded console event',$3,'product','exact','2026-09-20T12:00:00Z')`, o, consoleIDs[i], events[id])
	}
	exec(`INSERT INTO zasp_runtime_session_events(organization_id,workspace_id,environment_id,event_id,confidence,source,event_class,action,title,evidence_id,event_time) VALUES($1,$2,$3,'pid_85000000-0000-4000-8000-000000000099','unattributed','otlp','tool','invoke','Unattributed event','pid_85000000-0000-4000-8000-000000000099','2026-09-20T12:00:00Z')`, o, w, e)
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
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	resolver, _ := NewPostgresAuthorizationResolver(database)
	checker := authorizationDecisionFixture{allow: map[string]bool{}, model: model}
	for _, id := range append(runtimeIDs[1:], consoleIDs[1:]...) {
		kind := "session"
		if !runtimeSessionTarget(id) {
			kind = "product_session"
		}
		var canonical string
		if err := admin.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,$4,$5)`, o, w, e, kind, id).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		checker.allow[canonical] = true
	}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-current", Digest: sha256.Sum256([]byte("session80-credential"))}
	repository := &PostgresRepository{database: database, currentAuthorization: true, sandboxSessionReads: true}
	grantFor := func(t *testing.T, kind, operation, id string) context.Context {
		t.Helper()
		queryCtx := context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{"kind": {kind}})
		parameters := map[string]string{"id": id}
		if operation == "getSessionEvent" {
			parameters["eventId"] = events[id]
		}
		grant, err := authorizer.Authorize(queryCtx, identity, credential, RoutedOperation{OperationID: operation, PathParameters: parameters})
		if err != nil {
			t.Fatal(err)
		}
		return context.WithValue(queryCtx, requestAuthorizationContextKey{}, grant)
	}
	read := func(t *testing.T, c context.Context, operation string, parameters map[string]string) json.RawMessage {
		t.Helper()
		body, err := repository.ReadAdministration(c, identity, operation, parameters)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	pageIDs := func(t *testing.T, body json.RawMessage) []string {
		t.Helper()
		var page struct {
			Items []struct {
				ID    string `json:"id"`
				Count int    `json:"event_count"`
			}
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, item := range page.Items {
			ids = append(ids, item.ID)
			if item.ID == runtimeIDs[1] && item.Count != 2 {
				t.Fatalf("allowed session count=%d want2", item.Count)
			}
		}
		return ids
	}
	t.Run("mounted session hidden and missing contract", func(t *testing.T) {
		handler := &identityHTTPHandler{administration: repository, signingKey: []byte(strings.Repeat("r", 32)), now: time.Now}
		var operations []Operation
		for _, id := range []string{"getSession", "listSessionEvents", "getSessionEvent"} {
			policy, err := authorization.LookupOperation(id)
			if err != nil {
				t.Fatal(err)
			}
			operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: id, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, Handler: handler})
		}
		router, err := NewRouter(operations)
		if err != nil {
			t.Fatal(err)
		}
		router.(*operationRouter).authorizer = authorizer
		current := identity
		current.credentialBinding = credential
		for _, tc := range []struct {
			path   string
			status int
		}{
			{"/api/v1/sessions/" + runtimeIDs[1], 200},
			{"/api/v1/sessions/" + runtimeIDs[0], 404},
			{"/api/v1/sessions/pid_84000009-0000-4000-8000-000000000009", 404},
			{"/api/v1/sessions/" + runtimeIDs[0] + "/events", 404},
			{"/api/v1/sessions/" + runtimeIDs[1] + "/events/pid_85000009-0000-4000-8000-000000000009", 404},
		} {
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			request.Header.Set(expectedScopeHeader, expectedScopeValue(current.Scope))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request.WithContext(context.WithValue(ctx, identityContextKey{}, current)))
			if response.Code != tc.status || tc.status == 404 && decodeErrorCode(t, response) != "not_found" {
				t.Errorf("public session response=%d body=%s expected=%d", response.Code, response.Body.String(), tc.status)
			}
		}
	})
	t.Run("native collection proof cannot become detail", func(t *testing.T) {
		for _, kind := range []string{"console", "runtime"} {
			t.Run(kind, func(t *testing.T) {
				g, _ := requestAuthorizationFromContext(grantFor(t, kind, "listSessions", ""))
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
				var body []byte
				if kind == "runtime" {
					err = tx.QueryRow(ctx, `SELECT zasp_authorization80.runtime_session_get($1,$2,$3,$4,$5)`, o, w, e, p, runtimeIDs[1]).Scan(&body)
				} else {
					err = tx.QueryRow(ctx, `SELECT zasp_authorization80.product_session_get($1,$2,$3,$4)`, o, w, e, consoleIDs[1]).Scan(&body)
				}
				if err != nil || len(body) != 0 && string(body) != "null" {
					t.Fatalf("native operation mismatch body=%s error=%v", body, err)
				}
			})
		}
	})
	for _, kind := range []string{"console", "runtime"} {
		t.Run(kind, func(t *testing.T) {
			ids := consoleIDs
			if kind == "runtime" {
				ids = runtimeIDs
			}
			c := grantFor(t, kind, "listSessions", "")
			got := pageIDs(t, read(t, c, "listSessions", map[string]string{"kind": kind, "limit": "1"}))
			if fmt.Sprint(got) != fmt.Sprint(ids[1:]) {
				t.Fatalf("denied-first lookahead page=%v want%v", got, ids[1:])
			}
			got = pageIDs(t, read(t, c, "listSessions", map[string]string{"kind": kind, "limit": "1", "after_id": ids[1]}))
			if len(got) != 1 || got[0] != ids[2] {
				t.Fatalf("authorized continuation=%v", got)
			}
			detailCtx := grantFor(t, kind, "getSession", ids[1])
			var detail map[string]any
			if json.Unmarshal(read(t, detailCtx, "getSession", map[string]string{"id": ids[1]}), &detail) != nil || detail["id"] != ids[1] {
				t.Fatalf("detail parity=%v", detail)
			}
			// The same checked context cannot be reused to fetch a denied sibling.
			if _, err := repository.ReadAdministration(detailCtx, identity, "getSession", map[string]string{"id": ids[0]}); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("denied detail error=%v", err)
			}
			eventCtx := grantFor(t, kind, "listSessionEvents", ids[1])
			if got := pageIDs(t, read(t, eventCtx, "listSessionEvents", map[string]string{"id": ids[1], "limit": "1"})); len(got) == 0 {
				t.Fatal("allowed events absent")
			}
			denied, err := repository.ReadAdministration(eventCtx, identity, "listSessionEvents", map[string]string{"id": ids[0], "limit": "1"})
			if err == nil && len(pageIDs(t, denied)) != 0 {
				t.Fatalf("denied events=%s", denied)
			}
			if err != nil && !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatal(err)
			}
			if kind == "runtime" {
				eventCtx = grantFor(t, kind, "getSessionEvent", ids[1])
				event := read(t, eventCtx, "getSessionEvent", map[string]string{"id": ids[1], "eventId": events[ids[1]]})
				var projected map[string]any
				if json.Unmarshal(event, &projected) != nil || projected["sandbox_id"] != "sandbox-recorded" || projected["sandbox_source_sensor_id"] != p {
					t.Fatalf("source50 event detail changed: %s", event)
				}
				if _, err := repository.ReadAdministration(eventCtx, identity, "getSessionEvent", map[string]string{"id": ids[0], "eventId": events[ids[0]]}); !errors.Is(err, ErrAuthorizationDenied) {
					t.Fatalf("denied event detail error=%v", err)
				}
			}
			// Independently retain the SQL guard proof: a checked detail cannot
			// disclose a denied sibling even when bypassing the application classifier.
			detailGrant, _ := requestAuthorizationFromContext(detailCtx)
			proof, err := authorizationProofJSON(detailGrant)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var native []byte
			if kind == "runtime" {
				err = tx.QueryRow(ctx, `SELECT zasp_authorization80.runtime_session_get($1,$2,$3,$4,$5)`, o, w, e, p, ids[0]).Scan(&native)
			} else {
				err = tx.QueryRow(ctx, `SELECT zasp_authorization80.product_session_get($1,$2,$3,$4)`, o, w, e, ids[0]).Scan(&native)
			}
			_ = tx.Rollback(ctx)
			if err != nil || len(native) != 0 && string(native) != "null" {
				t.Fatalf("native sibling disclosure=%s error=%v", native, err)
			}
			if _, err := repository.ReadAdministration(ctx, identity, "listSessions", map[string]string{"kind": kind, "limit": "1"}); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("missing proof error=%v", err)
			}
			grant, _ := requestAuthorizationFromContext(c)
			grant.Allowed = nil
			tamperedCtx := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
			if _, err := repository.ReadAdministration(tamperedCtx, identity, "listSessions", map[string]string{"kind": kind, "limit": "1"}); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("modified signed decision error=%v", err)
			}
			originalChecker := authorizer.Checker
			authorizer.Checker = authorizationDecisionFixture{allow: map[string]bool{}, model: model}
			emptyCtx := grantFor(t, kind, "listSessions", "")
			authorizer.Checker = originalChecker
			if got := pageIDs(t, read(t, emptyCtx, "listSessions", map[string]string{"kind": kind, "limit": "1"})); len(got) != 0 {
				t.Fatalf("empty allow set=%v", got)
			}
			for _, boundary := range []string{"kind", "scope", "source"} {
				grant, _ = requestAuthorizationFromContext(c)
				grant.Allowed = append([]AuthorizationTarget(nil), grant.Allowed...)
				for i := range grant.Allowed {
					switch boundary {
					case "kind":
						grant.Allowed[i].Kind = "foreign_kind"
					case "scope":
						foreignEnvironment, _ := domain.ParseProductID("pid_86000001-0000-4000-8000-000000000001")
						grant.Allowed[i].Scope, _ = domain.NewScope(identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), foreignEnvironment)
					case "source":
						grant.Allowed[i].SourceID = "foreign-native-key"
					}
				}
				foreignCtx := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
				if _, err := repository.ReadAdministration(foreignCtx, identity, "listSessions", map[string]string{"kind": kind, "limit": "1"}); !errors.Is(err, ErrAuthorizationDenied) {
					t.Fatalf("foreign %s modified decision error=%v", boundary, err)
				}
			}
		})
	}
	t.Run("unattributed requires explicit canonical grant", func(t *testing.T) {
		var canonical string
		if err := admin.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,'session','unattributed')`, o, w, e).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		checker.allow[canonical] = true
		c := grantFor(t, "runtime", "getSession", "unattributed")
		var detail map[string]any
		if body := read(t, c, "getSession", map[string]string{"id": "unattributed"}); json.Unmarshal(body, &detail) != nil || detail["id"] != "unattributed" || detail["event_count"] != float64(1) {
			t.Fatalf("unattributed detail=%s", body)
		}
	})
	t.Run("registered source drift denies readiness", func(t *testing.T) {
		checksum, fingerprint := migrations.ProductionRuntimeSessionReads().Checksum(), migrations.ProductionRuntimeSessionReadsSemanticFingerprint()
		var ready bool
		if err := api.QueryRow(ctx, `SELECT zasp_authorization80.session_source_readiness(41,$1,$2)`, checksum, fingerprint).Scan(&ready); err != nil || !ready {
			t.Fatalf("registered baseline readiness=%v err=%v", ready, err)
		}
		if err := api.QueryRow(ctx, `SELECT zasp_authorization80.session_source_readiness(41,$1,$2)`, "0000000000000000000000000000000000000000000000000000000000000000", fingerprint).Scan(&ready); err != nil || ready {
			t.Fatalf("wrong source pin accepted=%v err=%v", ready, err)
		}
		for _, tc := range []struct{ name, sql string }{
			{"table ACL", `GRANT SELECT ON public.zasp_runtime_session_events TO zasp_discovery_api`},
			{"source function ACL", `GRANT EXECUTE ON FUNCTION public.zasp_runtime_session_get(text,text,text,text,text) TO PUBLIC`},
			{"source RLS", `ALTER TABLE public.zasp_runtime_session_summaries DISABLE ROW LEVEL SECURITY`},
			{"registered61 identity", `UPDATE public.zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_fingerprint'`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, tc.sql); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(ctx, `SELECT zasp_authorization80.session_source_readiness(41,$1,$2)`, checksum, fingerprint).Scan(&ready); err != nil || ready {
					t.Fatalf("source drift admitted=%v err=%v", ready, err)
				}
			})
		}
		if err := api.QueryRow(ctx, `SELECT zasp_authorization80.session_source_readiness(41,$1,$2)`, checksum, fingerprint).Scan(&ready); err != nil || !ready {
			t.Fatalf("rollback did not restore source readiness=%v err=%v", ready, err)
		}
	})
	t.Log("installed canonical61+79+80; real API transaction fence and projection, controlled checker decisions (not live FGA)")
}
