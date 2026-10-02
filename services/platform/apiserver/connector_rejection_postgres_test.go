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

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This catches a missing durable side effect: an authenticated integration setup
// rejection must append one safe scoped audit without mutating connector state.
// The positive setup controls must pass before absence of an audit counts as RED.
func TestConnectorRejectedAuthorityOverridesPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const workspace = "pid_6a000002-0000-4000-8000-000000000002"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const actor = "pid_6a000009-0000-4000-8000-000000000009"
		const foreignID = "pid_9a000010-0000-4000-8000-000000000010"
		const cookie = "connector-rejection-session"
		const hostileURL = "https://attacker.invalid/override-private-marker"
		const hostileSecret = "private-credential-marker-never-persist"
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if version, err := runner.Version(ctx); err != nil || version != 56 {
			t.Fatalf("fixture release=%d err=%v", version, err)
		}
		t.Logf("compiled release56 checksum=%s fingerprint=%s", migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint())
		seed := func(sql string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
				t.Fatal(err)
			}
		}
		digest := sha256.Sum256([]byte(cookie))
		seed(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'organization-connector-rejection','member-connector-rejection','security_engineer');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'connector-rejection','["view","manage_workflows"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","manage_workflows"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp());`, org, workspace, environment, actor, digest[:])
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.User = "security_agent_v33_discovery_api_login"
		api, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		var user string
		var superuser, bypass, directAudit bool
		if err := api.QueryRow(ctx, `SELECT current_user,rolsuper,rolbypassrls,has_table_privilege(current_user,'zasp_admin_audit','INSERT') FROM pg_roles WHERE rolname=current_user`).Scan(&user, &superuser, &bypass, &directAudit); err != nil || user != cfg.User || superuser || bypass {
			t.Fatalf("registered API authority: user=%s super=%t bypass=%t audit-insert=%t err=%v", user, superuser, bypass, directAudit, err)
		}
		t.Logf("registered API ACL observation: current_user=%s audit-table INSERT privilege=%t; product writes use real repository operations only", user, directAudit)
		database, err := NewPostgresJSONDatabase(&connectorRejectionPGDriver{integrationPostgresDriver: &integrationPostgresDriver{connection: api}})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: cookie})
		if err != nil || !stringIn("manage_workflows", identity.Permissions...) {
			t.Fatalf("real workflow authentication: %+v %v", identity.Permissions, err)
		}
		workflow, err := newWorkflowHTTPHandler(repository, []byte(strings.Repeat("k", 32)), nil)
		if err != nil {
			t.Fatal(err)
		}
		// Setup create/update is a local route with no provider transport dependency.
		// Observe accidental default-client HTTP and dispatch to the connector route;
		// this does not claim coverage of custom Nango/GitHub transports or live egress.
		tripwire := &connectorRejectionHTTPTripwire{}
		priorTransport := http.DefaultTransport
		http.DefaultTransport = tripwire
		defer func() { http.DefaultTransport = priorTransport }()
		providerDispatch := 0
		unused := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerDispatch++; w.WriteHeader(http.StatusTeapot) })
		pages, err := NewAuditPublicPageRepository(ctx, database)
		if err != nil {
			t.Fatal(err)
		}
		identityHandler := &identityHTTPHandler{repository: repository, auditPublicPages: pages, signingKey: []byte(strings.Repeat("k", 32))}
		router, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: identityHandler, Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: workflow, Connector: unused})
		if err != nil {
			t.Fatal(err)
		}
		correlation := "pid_8b000000-0000-4000-8000-000000000000"
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: repository.Authenticate, GenerateCorrelationID: func() string { return correlation }}, router)
		if err != nil {
			t.Fatal(err)
		}
		invoke := func(method, path, body, key string, change func(*http.Request)) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: cookie})
			r.Header.Set(expectedScopeHeader, org+"/"+workspace+"/"+environment)
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", key)
			if method == http.MethodPatch {
				r.Header.Set("If-Match", `"1"`)
			}
			if change != nil {
				change(r)
			}
			w := httptest.NewRecorder()
			mounted.ServeHTTP(w, r)
			return w
		}
		positive := invoke("POST", "/api/v1/integrations", `{"connector_key":"github","name":"Safe GitHub","configuration":{"authorization_mode":"github_app"}}`, "connector-safe-create-0001", nil)
		var created struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if positive.Code != 201 || json.Unmarshal(positive.Body.Bytes(), &created) != nil || created.ID == "" || created.Status != "pending_authorization" {
			t.Fatalf("positive GitHub setup control: %d %s", positive.Code, positive.Body)
		}
		webhook := invoke("POST", "/api/v1/integrations", `{"connector_key":"generic-webhook","name":"Safe webhook","configuration":{"destination_url":"https://hooks.example.test/zasp","signing_secret_reference":"secret_ref_connector_fixture"}}`, "connector-safe-webhook-0001", nil)
		var configured struct {
			Status string `json:"status"`
		}
		if webhook.Code != 201 || json.Unmarshal(webhook.Body.Bytes(), &configured) != nil || configured.Status != "configured" {
			t.Fatalf("positive generic-webhook destination_url control: %d %s", webhook.Code, webhook.Body)
		}
		t.Logf("positive controls: registered role=%s real security_engineer manage_workflows session; GitHub=201, generic-webhook=201", user)
		seed(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) SELECT 'pid_9a000001-0000-4000-8000-000000000001','pid_9a000002-0000-4000-8000-000000000002','pid_9a000003-0000-4000-8000-000000000003','integration',$1,1,jsonb_set(body,'{id}',to_jsonb($1::text)) FROM zasp_workflow_records WHERE id=$2 AND kind='integration'`, foreignID, created.ID)
		// Snapshot exact table contents, not just counts, to catch hidden updates.
		snapshot := func(t *testing.T) string {
			t.Helper()
			var result strings.Builder
			for _, table := range []string{"zasp_workflow_records", "zasp_integrations", "zasp_integration_connections", "zasp_connector_credentials", "zasp_connector_effects", "zasp_connector_oauth_attempts", "zasp_workflow_idempotency", "zasp_workflow_receipts", "zasp_workflow_audit", "zasp_connector_audit"} {
				var raw string
				if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]')::text FROM `+table+` r`).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				result.WriteString(table + raw)
			}
			return result.String()
		}
		auditCount := func(t *testing.T) int {
			t.Helper()
			var n int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE (organization_id,workspace_id,environment_id,actor_id,outcome)=($1,$2,$3,$4,'rejected')`, org, workspace, environment, actor).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		badBody := `{"connector_key":"github","name":"Rejected setup","configuration":{"authorization_mode":"github_app","provider_url":"` + hostileURL + `"}}`
		for _, control := range []struct {
			name, method, path string
			status             int
			change             func(*http.Request)
		}{
			{"unauthenticated", "POST", "/api/v1/integrations", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
			{"csrf", "POST", "/api/v1/integrations", 403, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
			{"foreign_scope", "POST", "/api/v1/integrations", 409, func(r *http.Request) {
				r.Header.Set(expectedScopeHeader, "pid_9a000001-0000-4000-8000-000000000001/pid_9a000002-0000-4000-8000-000000000002/pid_9a000003-0000-4000-8000-000000000003")
			}},
			{"foreign_target", "PATCH", "/api/v1/integrations/" + foreignID, 404, nil},
		} {
			t.Run(control.name, func(t *testing.T) {
				before, audits := snapshot(t), auditCount(t)
				w := invoke(control.method, control.path, badBody, "connector-control-"+control.name, control.change)
				if w.Code != control.status {
					t.Fatalf("control: %d %s", w.Code, w.Body)
				}
				if snapshot(t) != before || auditCount(t) != audits {
					t.Fatal("unauthorized control changed state or borrowed selected-scope rejection audit authority")
				}
			})
		}
		caseNumber := 0
		for _, method := range []string{"POST", "PATCH"} {
			for _, key := range []string{"nango_url", "nango_base_url", "proxy_url", "provider_url", "provider_url_with_secret"} {
				caseNumber++
				t.Run(method+"_"+key, func(t *testing.T) {
					correlation = fmt.Sprintf("pid_8b000000-0000-4000-8000-%012d", caseNumber)
					field, extra := key, ""
					if key == "provider_url_with_secret" {
						field = "provider_url"
						extra = `,"client_secret":"` + hostileSecret + `"`
					}
					body := `{"connector_key":"github","name":"Rejected setup","configuration":{"authorization_mode":"github_app","` + field + `":"` + hostileURL + `"` + extra + `}}`
					path := "/api/v1/integrations"
					if method == "PATCH" {
						path += "/" + created.ID
					}
					before, audits := snapshot(t), auditCount(t)
					w := invoke(method, path, body, fmt.Sprintf("connector-rejected-%04d", caseNumber), nil)
					var rejection struct {
						Code        string `json:"code"`
						Correlation string `json:"correlation_id"`
					}
					if w.Code != 400 || json.Unmarshal(w.Body.Bytes(), &rejection) != nil || rejection.Code != "invalid_request" || rejection.Correlation != correlation {
						t.Fatalf("expected authorized setup rejection, not auth/config error: %d %s", w.Code, w.Body)
					}
					if strings.Contains(w.Body.String(), hostileURL) || strings.Contains(w.Body.String(), hostileSecret) {
						t.Fatal("rejection response disclosed hostile input")
					}
					if snapshot(t) != before {
						t.Fatal("rejected setup mutated integration, connection, effects, idempotency or receipt state")
					}
					if providerDispatch != 0 || tripwire.calls != 0 {
						t.Fatalf("provider dispatch=%d default HTTP calls=%d", providerDispatch, tripwire.calls)
					}
					var records string
					if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]')::text FROM zasp_admin_audit a WHERE (organization_id,workspace_id,environment_id,actor_id,outcome)=($1,$2,$3,$4,'rejected') AND metadata::text LIKE '%'||$5||'%'`, org, workspace, environment, actor, correlation).Scan(&records); err != nil {
						t.Fatal(err)
					}
					if strings.Contains(records, hostileURL) || strings.Contains(records, hostileSecret) || strings.Contains(records, "Rejected setup") {
						t.Fatal("durable rejection audit disclosed hostile input")
					}
					t.Logf("authorized rejection: HTTP=%d state unchanged; connector dispatch=%d default HTTP=%d; scoped rejected audit delta=%d records=%s", w.Code, providerDispatch, tripwire.calls, auditCount(t)-audits, records)
					var rows []json.RawMessage
					if json.Unmarshal([]byte(records), &rows) != nil || len(rows) != 1 || auditCount(t) != audits+1 {
						t.Fatalf("missing durable safe scoped rejection audit: want one authorized-attempt event with correlation %s; got delta=%d matching=%d", correlation, auditCount(t)-audits, len(rows))
					}
				})
			}
		}
		exerciseConnectorRejectionAuthority(t, ctx, owner, api, repository, identity, created.ID, invoke, auditCount)
		exerciseConnectorRejectionFailures(t, ctx, owner, api, identity)
	})
}

type connectorRejectionHTTPTripwire struct{ calls int }

type connectorRejectionPGDriver struct{ *integrationPostgresDriver }

func (driver *connectorRejectionPGDriver) BeginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	return driver.connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (tripwire *connectorRejectionHTTPTripwire) RoundTrip(*http.Request) (*http.Response, error) {
	tripwire.calls++
	return nil, errors.New("connector rejection test prohibits HTTP")
}
