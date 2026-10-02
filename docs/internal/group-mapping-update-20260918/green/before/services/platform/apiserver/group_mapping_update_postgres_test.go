package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catches suppressing the update branch for positive expected_version: a real
// registered-role mapping replacement must advance version and atomically audit
// and revoke credentials, rather than return a false optimistic-lock conflict.
func TestGroupMappingExpectedVersionUpdateMountedPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("compiled56 checksum=%s fingerprint=%s", migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint())
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const workspace = "pid_6a000002-0000-4000-8000-000000000002"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const actor = "pid_6a000091-0000-4000-8000-000000000091"
		const foreign = "pid_9a000001-0000-4000-8000-000000000001"
		exec := func(sql string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
				t.Fatal(err)
			}
		}
		exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'organization-mapping-regression','member-mapping-admin','security_admin');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Mapping admin','["view","manage_identity"]');
INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($5,'scim-group-test-foreign','security_engineer','pid_9a000002-0000-4000-8000-000000000002','pid_9a000003-0000-4000-8000-000000000003')`, org, workspace, environment, actor, foreign)
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
		var super, bypass bool
		if err = api.QueryRow(ctx, `SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&user, &super, &bypass); err != nil || user != cfg.User || super || bypass {
			t.Fatalf("registered role=%s super=%t bypass=%t err=%v", user, super, bypass, err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := domain.NewScope(integrationProductID(t, org), integrationProductID(t, workspace), integrationProductID(t, environment))
		if err != nil {
			t.Fatal(err)
		}
		var cookie, csrf string
		freshSession := func() {
			t.Helper()
			cookie, err = repository.CreateSession(ctx, SessionGrant{PrincipalID: integrationProductID(t, actor), Scope: scope, Permissions: []string{"view", "manage_identity"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: cookie})
			if err != nil || !stringIn("manage_identity", identity.Permissions...) || !identity.FreshAuthenticated {
				t.Fatalf("real admin auth: %+v %v", identity, err)
			}
			csrf = identity.CSRFToken
		}
		freshSession()
		handler := &identityHTTPHandler{repository: repository, administration: repository, signingKey: []byte(strings.Repeat("k", 32)), now: time.Now}
		router, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handler, Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: repository.Authenticate, GenerateCorrelationID: func() string { return "pid_8c000001-0000-4000-8000-000000000001" }}, router)
		if err != nil {
			t.Fatal(err)
		}
		invoke := func(group, role string, version int) *httptest.ResponseRecorder {
			body := fmt.Sprintf(`{"group_reference":%q,"role":%q,"workspace_id":%q,"environment_id":%q,"expected_version":%d}`, group, role, workspace, environment, version)
			r := httptest.NewRequest("PATCH", "/api/v1/admin/group-mappings", strings.NewReader(body)).WithContext(ctx)
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: cookie})
			r.Header.Set(expectedScopeHeader, org+"/"+workspace+"/"+environment)
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mounted.ServeHTTP(w, r)
			return w
		}
		const group = "scim-group-test-mapping-regression"
		countAudit := func() int {
			t.Helper()
			var n int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1 AND action='group_mapping.update'`, org).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		created := invoke(group, "security_engineer", 0)
		var value struct {
			Role    string `json:"role"`
			Version int    `json:"version"`
			AuditID string `json:"audit_correlation_id"`
		}
		if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &value) != nil || value.Role != "security_engineer" || value.Version != 1 || created.Header().Get("ETag") != `"1"` || !validProductID(value.AuditID) || countAudit() != 1 {
			t.Fatalf("initial create control: status=%d body=%s events=%d", created.Code, created.Body, countAudit())
		}
		if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: cookie}); !errors.Is(err, ErrRepositoryAuthentication) {
			t.Fatalf("create must revoke current admin session: %v", err)
		}
		t.Logf("positive create: registered=%s security_admin/manage_identity HTTP200 role=security_engineer version1 audit1 session revoked", user)
		freshSession()
		stale := invoke(group, "read_only_viewer", 0)
		if stale.Code != 409 || countAudit() != 1 {
			t.Fatalf("stale create version: %d %s", stale.Code, stale.Body)
		}
		denied := invoke("scim-group-test-foreign", "read_only_viewer", 1)
		if denied.Code != 404 || countAudit() != 1 {
			t.Fatalf("foreign tenant target: %d %s", denied.Code, denied.Body)
		}
		var foreignRole string
		var foreignVersion int
		if err := owner.QueryRow(ctx, `SELECT role,version FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference='scim-group-test-foreign'`, foreign).Scan(&foreignRole, &foreignVersion); err != nil || foreignRole != "security_engineer" || foreignVersion != 1 {
			t.Fatalf("foreign mapping changed: %s %d %v", foreignRole, foreignVersion, err)
		}
		t.Log("stale version0 conflict409 and foreign tenant target404 controls passed with no audit or foreign mapping change")
		updated := invoke(group, "read_only_viewer", 1)
		var storedRole string
		var storedVersion int
		var revoked bool
		if err := owner.QueryRow(ctx, `SELECT role,version FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference=$2`, org, group).Scan(&storedRole, &storedVersion); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM zasp_product_sessions WHERE token_digest=digest($1,'sha256')`, cookie).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if updated.Code != 200 || storedRole != "read_only_viewer" || storedVersion != 2 || countAudit() != 2 || !revoked {
			t.Fatalf("valid expected_version1 update missing: HTTP=%d want200 role=%s wantread_only_viewer version=%d want2 audit_count=%d want2 current_session_revoked=%t wanttrue body=%s", updated.Code, storedRole, storedVersion, countAudit(), revoked, updated.Body)
		}
		if json.Unmarshal(updated.Body.Bytes(), &value) != nil || value.Version != 2 || updated.Header().Get("ETag") != `"2"` {
			t.Fatalf("update version response=%s", updated.Body)
		}
	})
}
