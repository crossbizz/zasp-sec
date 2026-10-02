package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The actual extended composition uses fixture handlers for unrelated routes.
// Session authentication and export authority both use registered PostgreSQL.
func TestAuditExportProductionFactoryPostgresAuthenticatedHTTP(t *testing.T) {
	for _, release := range []struct {
		name    string
		version int64
	}{{"schema52", 52}, {"schema53", 53}, {"schema54", 54}} {
		t.Run(release.name, func(t *testing.T) {
			exerciseAuditExportAuthenticatedHTTP(t, release.version)
		})
	}
}

func exerciseAuditExportAuthenticatedHTTP(t *testing.T, version int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	if version >= 53 {
		if err := precisionMigrationRunner(t, f.admin).UpProductionSecurityAgentBudgets(ctx); err != nil {
			t.Fatal("upgrade authenticated export fixture to current schema53", err)
		}
	}
	if version == 54 {
		if err := precisionMigrationRunner(t, f.admin).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal("upgrade authenticated export fixture to schema54", err)
		}
	}
	var actual int64
	if err := f.admin.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&actual); err != nil || actual != version {
		t.Fatalf("authenticated export fixture schema=%d want=%d: %v", actual, version, err)
	}
	f.register(t, ctx)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	identityRepository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal("actual session repository", err)
	}
	config, transport := auditExportProductionConfigFixture(t)
	config.Storage[0].Policy = auditExportTestPolicy()
	handler, err := NewAuditExportProductionHandler(ctx, database, config)
	if err != nil {
		t.Fatal("actual export factory", err)
	}
	router, err := NewCompositionWithAuditExports(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")}, handler)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://audit-export.invalid", MaximumBodyBytes: 1024, Authenticate: identityRepository.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string) *http.Request {
		var body string
		if method == http.MethodPost {
			body = "{}"
		}
		req := httptest.NewRequest(method, "https://audit-export.invalid"+path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://audit-export.invalid")
		req.Header.Set("X-CSRF-Token", f.identity.CSRFToken)
		req.Header.Set(expectedScopeHeader, expectedScopeValue(f.identity.Scope))
		req.Header.Set("Idempotency-Key", "audit-factory-postgres-key")
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-export-browser-fixture"})
		return req
	}
	invoke := func(req *http.Request, want int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		secured.ServeHTTP(response, req)
		if response.Code != want || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("authenticated HTTP status=%d want=%d: %s", response.Code, want, response.Body.String())
		}
		return response
	}
	created := invoke(request(http.MethodPost, "/api/v1/audit-exports"), http.StatusCreated)
	var descriptor AuditExportDescriptor
	if json.Unmarshal(created.Body.Bytes(), &descriptor) != nil || descriptor.Status != "queued" || !validProductID(descriptor.ID) {
		t.Fatal("invalid durable creation response")
	}
	replayed := invoke(request(http.MethodPost, "/api/v1/audit-exports"), http.StatusCreated)
	if !bytes.Equal(created.Body.Bytes(), replayed.Body.Bytes()) {
		t.Fatal("HTTP replay changed persisted descriptor")
	}
	path := "/api/v1/audit-exports/" + descriptor.ID
	read := invoke(request(http.MethodGet, path), http.StatusOK)
	var page struct {
		Export   AuditExportDescriptor `json:"export"`
		Contents json.RawMessage       `json:"contents"`
	}
	if json.Unmarshal(read.Body.Bytes(), &page) != nil || page.Export.ID != descriptor.ID || string(page.Contents) != "null" {
		t.Fatal("queued read fabricated contents")
	}
	for _, item := range []struct {
		header, value string
		status        int
	}{{"Origin", "https://foreign.invalid", http.StatusForbidden}, {"X-CSRF-Token", "wrong-csrf", http.StatusForbidden}, {expectedScopeHeader, "wrong-scope", http.StatusConflict}} {
		req := request(http.MethodPost, "/api/v1/audit-exports")
		req.Header.Set(item.header, item.value)
		invoke(req, item.status)
	}
	missing := request(http.MethodGet, path)
	missing.Header.Del("Cookie")
	invoke(missing, http.StatusUnauthorized)
	var counts []int64
	if err := f.admin.QueryRow(ctx, `SELECT ARRAY[(SELECT count(*) FROM zasp_audit_export_jobs),(SELECT count(*) FROM zasp_audit_export_idempotency),(SELECT count(*) FROM zasp_audit_export_outbox),(SELECT count(*) FROM zasp_admin_audit WHERE action='audit_export.request')]`).Scan(&counts); err != nil {
		t.Fatal(err)
	}
	if len(counts) != 4 {
		t.Fatal("missing durable effect counts")
	}
	for _, count := range counts {
		if count != 1 {
			t.Fatal("HTTP replay/refusal created duplicate effects", counts)
		}
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 hour' WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	invoke(request(http.MethodGet, path), http.StatusOK)
	invoke(request(http.MethodPost, "/api/v1/audit-exports"), http.StatusForbidden)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	invoke(request(http.MethodGet, path), http.StatusForbidden)
	invoke(request(http.MethodPost, "/api/v1/audit-exports"), http.StatusForbidden)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	invoke(request(http.MethodGet, path), http.StatusOK)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	invoke(request(http.MethodGet, path), http.StatusUnauthorized)
	invoke(request(http.MethodPost, "/api/v1/audit-exports"), http.StatusUnauthorized)
	if transport.calls != 0 {
		t.Fatal("queued/refused operation accessed storage")
	}
}
