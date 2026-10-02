//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditExportPublicPageReadinessPostgresPageOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	api := sandboxSessionAPI(t, ctx, admin)
	runner := installAuditExports(t, ctx, admin)
	var configured int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_audit_export_api_bindings)+(SELECT count(*) FROM zasp_audit_export_current_policy WHERE policy_id IS NOT NULL)`).Scan(&configured); err != nil || configured != 0 {
		t.Fatal("not page-only fixture", configured, err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAuditPublicPageRepository(ctx, database)
	if err != nil {
		t.Fatal("page-only readiness requires export configuration", err)
	}
	pin := migrations.ProductionAuditExports()
	fp := migrations.ProductionAuditExportsSemanticFingerprint()
	for _, args := range [][]any{{pin.Checksum(), fp}, {strings.Repeat("0", 64), fp}, {pin.Checksum(), strings.Repeat("0", 64)}} {
		raw, err := database.QueryJSON(ctx, postgresAuditPublicPageReadySQL, args...)
		want := "false"
		if args[0] == pin.Checksum() && args[1] == fp {
			want = "true"
		}
		if err != nil || string(raw) != want {
			t.Fatal("wrong compiled readiness", string(raw), err)
		}
	}
	for _, query := range []string{`SELECT zasp_production_audit_exports_readiness('x','x')`, `SELECT * FROM zasp_audit_export_public_source_v1`, `SELECT * FROM zasp_red_team_audit`} {
		if _, err := api.Exec(ctx, query); auditExportSQLState(err) != "42501" {
			t.Fatal("page API gained private authority", query, err)
		}
	}
	worker, outbox := auditExportWorkerConnections(t, ctx, auditExportPG{admin: admin, api: api})
	for _, connection := range []*pgx.Conn{worker, outbox} {
		if _, err := connection.Exec(ctx, postgresAuditPublicPageReadySQL, pin.Checksum(), fp); auditExportSQLState(err) != "42501" {
			t.Fatal("worker reached page readiness", err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE audit_page_unregistered LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "audit_page_unregistered"
	foreign, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close(ctx)
	if _, err := foreign.Exec(ctx, postgresAuditPublicPageReadySQL, pin.Checksum(), fp); auditExportSQLState(err) != "42501" {
		t.Fatal("PUBLIC reached readiness", err)
	}
	if _, err := admin.Exec(ctx, `GRANT zasp_discovery_api TO audit_page_unregistered`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err := foreign.QueryRow(ctx, postgresAuditPublicPageReadySQL, pin.Checksum(), fp).Scan(new([]byte)); err != nil {
		t.Fatal("unregistered capability invocation", err)
	}
	if err := foreign.QueryRow(ctx, `SELECT zasp_audit_export_public_page_readiness($1,$2)`, pin.Checksum(), fp).Scan(&ready); err != nil || ready {
		t.Fatal("unregistered membership became trusted", err)
	}
	if _, err := admin.Exec(ctx, `REVOKE zasp_discovery_api FROM audit_page_unregistered`); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_audit_export_public_page_readiness(text,text) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	// Own transaction sees the drift; the warmed API checks committed drift below.
	if err := tx.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, pin.Checksum(), fp).Scan(&ready); err != nil || ready {
		t.Fatal("wrapper PUBLIC grant drift remained ready", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `ALTER FUNCTION zasp_audit_export_public_page_readiness(text,text) IMMUTABLE`); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(ctx); err == nil {
		t.Fatal("warmed page ignored wrapper catalog drift")
	}
	if _, err := admin.Exec(ctx, `ALTER FUNCTION zasp_audit_export_public_page_readiness(text,text) STABLE`); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(ctx); err != nil {
		t.Fatal("restored wrapper not ready", err)
	}
	if err := runner.DownProductionAuditExports(ctx); err != nil {
		t.Fatal("no-export Down", err)
	}
	if _, err := api.Exec(ctx, postgresAuditPublicPageReadySQL, pin.Checksum(), fp); auditExportSQLState(err) != "42883" {
		t.Fatal("Down retained page readiness", err)
	}
	installAuditExports(t, ctx, admin)
	if err := r.Ready(ctx); err != nil {
		t.Fatal("reinstall changed kept-open page readiness", err)
	}
}

// This gate2 fixture binds the actual registered SQL adapter to the real
// identity-handler branch. Runtime profile selection/middleware mount is gate3.
func TestAuditExportPublicPageHandlerPostgresBytesAndAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	f.identity.Permissions = append(f.identity.Permissions, "view_audit")
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewAuditPublicPageRepository(ctx, database)
	if err != nil {
		var raw []byte
		diagnosticErr := f.api.QueryRow(ctx, postgresAuditPublicPageReadySQL, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&raw)
		t.Fatalf("real boolean JSON readiness adapter: %v; direct=%q err=%v", err, raw, diagnosticErr)
	}
	handler := &identityHTTPHandler{auditPublicPages: repository, signingKey: []byte(strings.Repeat("k", 32))}
	invoke := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		req := workflowRequest(t, f.identity, testCorrelationID, "listAuditEvents", nil, http.MethodGet, "/api/v1/audit-events?"+query, "")
		bounded := context.WithValue(ctx, identityContextKey{}, f.identity)
		bounded = context.WithValue(bounded, correlationContextKey{}, testCorrelationID)
		routed, _ := RoutedOperationFromRequest(req)
		req = req.WithContext(context.WithValue(bounded, routedOperationContextKey{}, routed))
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-export-browser-fixture"})
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	auditExportPublicPolicyMutations(t, ctx, f)
	auditExportPublicTestMutations(t, ctx, f)
	response := invoke("")
	if response.Code != 200 {
		t.Fatal("registered producer read", response.Code, response.Body.String())
	}
	var all struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(response.Body.Bytes(), &all) != nil || len(all.Items) != 11 {
		t.Fatal("actual policy/test producer rows missing")
	}
	const id = "pid_79930001-0000-4000-8000-000000000001"
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auditPublicPageSeed(t, ctx, f, id, "page.httpedge", `{}`, at)
	for _, more := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "continuation"}[more], func(t *testing.T) {
			if more {
				auditPublicPageSeed(t, ctx, f, "pid_79930001-0000-4000-8000-000000000000", "page.httpedge", `{}`, at.Add(-time.Second))
			}
			fill := 900000
			setMetadata := func(n int) {
				t.Helper()
				metadata := map[string]string{strings.Repeat("k", n): ""}
				for i := 0; i < 31; i++ {
					metadata[fmt.Sprintf("small-%02d", i)] = ""
				}
				body, _ := json.Marshal(metadata)
				if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata=$1::jsonb WHERE id=$2`, string(body), id); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 3; attempt++ {
				setMetadata(fill)
				response = invoke("action=page.httpedge")
				if response.Code != 200 {
					t.Fatal("real SQL legal edge rejected", response.Code, response.Body.String())
				}
				if len(response.Body.Bytes()) == auditListHardBytes {
					break
				}
				fill += auditListHardBytes - len(response.Body.Bytes())
			}
			if len(response.Body.Bytes()) != auditListHardBytes {
				t.Fatal("failed actual HTTP hard edge", len(response.Body.Bytes()))
			}
			if !more {
				var private []byte
				if err := f.api.QueryRow(ctx, auditPublicPageSQL, auditPublicPageArgs(f, `{"action":"page.httpedge"}`, nil, nil, 50)...).Scan(&private); err != nil || len(private) != auditListHardBytes+49 {
					t.Fatal("terminal H+49 private transport rejected", len(private), err)
				}
				t.Logf("registered SQL private=%d actual handler public=%d", len(private), response.Body.Len())
			}
			if more {
				token := auditListResponseCursor(t, response)
				next := invoke("action=page.httpedge&cursor=" + token)
				if next.Code != 200 || !bytes.Contains(next.Body.Bytes(), []byte("pid_79930001-0000-4000-8000-000000000000")) || auditListResponseCursor(t, next) != "" {
					t.Fatal("soft-deferred row skipped", next.Code)
				}
			}
			for _, delta := range []int{-1, 0, 1} {
				setMetadata(fill + delta)
				response := invoke("action=page.httpedge")
				if delta > 0 {
					if response.Code != 503 || strings.Contains(response.Body.String(), `"items"`) {
						t.Fatal("oversize real SQL response leaked200", response.Code)
					}
					continue
				}
				if response.Code != 200 || response.Body.Len() != auditListHardBytes+delta {
					t.Fatal("exact real handler edge failed", more, delta, response.Code, response.Body.Len())
				}
			}
			setMetadata(10)
		})
	}
	// Source faults are unavailable, not invalid caller400, through the actual
	// PostgreSQL error classifier and the HTTP branch.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET occurred_at='0001-01-01T00:00:00Z'::timestamptz WHERE action='page.httpedge'`); err != nil {
		t.Fatal(err)
	}
	yearOne := invoke("action=page.httpedge&limit=1")
	if yearOne.Code != 200 {
		t.Fatal("actual finite year-one first page", yearOne.Code)
	}
	yearCursor := auditListResponseCursor(t, yearOne)
	yearNext := invoke("action=page.httpedge&limit=1&cursor=" + yearCursor)
	if yearCursor == "" || yearNext.Code != 200 || !strings.Contains(yearNext.Body.String(), "pid_79930001-0000-4000-8000-000000000000") || auditListResponseCursor(t, yearNext) != "" {
		t.Fatal("actual year-one continuation treated as missing time", yearNext.Code)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{"bad":null}'::jsonb WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if got := invoke("action=page.httpedge"); got.Code != 503 || strings.Contains(got.Body.String(), `"items"`) {
		t.Fatal("stored invalid source misclassified", got.Code, got.Body.String())
	}
	if got := invoke("outcome=rejected"); got.Code != 400 {
		t.Fatal("caller invalid not400", got.Code)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 day' WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	if got := invoke("outcome=failed"); got.Code != 200 {
		t.Fatal("GET incorrectly requires fresh auth", got.Code)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if got := invoke("outcome=failed"); got.Code != 403 {
		t.Fatal("current effective permission not reread", got.Code)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	if got := invoke("outcome=failed"); got.Code != 401 {
		t.Fatal("stored session revocation not401", got.Code)
	}
}
