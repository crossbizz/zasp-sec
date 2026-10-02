package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Only unrelated routes are fixtures. This path uses the actual registered
// session authenticator, ProductMiddleware, router and production identity
// handler. Requests contain cookies and expected-scope, never supplied identity.
func auditPublicPageSecuredFixture(t *testing.T, ctx context.Context, f auditExportPG) http.Handler {
	t.Helper()
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewAuditPublicPageRepository(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	identity := &identityHTTPHandler{repository: core, administration: core, auditPublicPages: page, signingKey: []byte(strings.Repeat("k", 32))}
	router, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: identity, Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	secured, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://audit-page.invalid", MaximumBodyBytes: 1024, Authenticate: core.Authenticate, GenerateCorrelationID: func() string { return testCorrelationID }}, router)
	if err != nil {
		t.Fatal(err)
	}
	return secured
}

func auditPublicPageAuthenticatedRequest(ctx context.Context, f auditExportPG, query string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://audit-page.invalid/api/v1/audit-events?"+query, nil).WithContext(ctx)
	req.Header.Set(expectedScopeHeader, expectedScopeValue(f.identity.Scope))
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-export-browser-fixture"})
	return req
}

func TestAuditExportPublicPageHTTPPostgresCurrentAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	secured := auditPublicPageSecuredFixture(t, ctx, f)
	invoke := func(req *http.Request, want int) *httptest.ResponseRecorder {
		t.Helper()
		res := httptest.NewRecorder()
		secured.ServeHTTP(res, req)
		if res.Code != want || res.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("actual middleware status=%d want=%d body=%s", res.Code, want, res.Body.String())
		}
		if want != 200 && strings.Contains(res.Body.String(), `"items"`) {
			t.Fatal("refusal leaked partial page")
		}
		return res
	}
	request := func(query string) *http.Request { return auditPublicPageAuthenticatedRequest(ctx, f, query) }
	policies := auditExportPublicPolicyMutations(t, ctx, f)
	tests := auditExportPublicTestMutations(t, ctx, f)
	res := invoke(request(""), 200)
	var all struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if json.Unmarshal(res.Body.Bytes(), &all) != nil || len(all.Items) != 11 {
		t.Fatal("real producers absent from authenticated page")
	}
	seen := map[string]bool{}
	for _, item := range all.Items {
		seen[item.ID] = true
	}
	for _, event := range append(policies, tests...) {
		if !seen[event.ID] {
			t.Fatal("original producer ID missing", event.ID)
		}
	}
	const id = "pid_79950001-0000-4000-8000-000000000002"
	const older = "pid_79950001-0000-4000-8000-000000000001"
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auditPublicPageSeed(t, ctx, f, id, "page.middleware", `{"empty":"","counter":7}`, at)
	auditPublicPageSeed(t, ctx, f, older, "page.middleware", `{}`, at.Add(-time.Second))
	for _, query := range []string{"actor_id=" + f.identity.PrincipalID.String(), "action=page.middleware", "outcome=succeeded", "from=2026-01-01T00:00:00Z", "to=2026-01-01T00:00:01Z", "actor_id=" + f.identity.PrincipalID.String() + "&action=page.middleware&outcome=succeeded&from=2026-01-01T00:00:00Z&to=2026-01-01T00:00:01Z"} {
		got := invoke(request(query), 200)
		if !bytes.Contains(got.Body.Bytes(), []byte(id)) {
			t.Fatal("authenticated filter omitted matching row", query)
		}
		var page struct {
			Items []json.RawMessage `json:"items"`
		}
		if json.Unmarshal(got.Body.Bytes(), &page) != nil {
			t.Fatal("invalid filtered page")
		}
		if query == "action=page.middleware" && len(page.Items) != 2 || strings.Contains(query, "&outcome=") && len(page.Items) != 1 {
			t.Fatal("filter leaked nonmatching rows", query, len(page.Items))
		}
	}
	for _, query := range []string{"actor_id=pid_79959999-0000-4000-8000-000000000001", "action=page.absent", "from=3000-01-01T00:00:00Z", "to=0001-01-01T00:00:00Z"} {
		got := invoke(request(query), 200)
		if !strings.Contains(got.Body.String(), `"items":[]`) {
			t.Fatal("filter ignored nonmatching boundary", query)
		}
	}
	if got := invoke(request("outcome=failed"), 200); !strings.Contains(got.Body.String(), `"items":[]`) {
		t.Fatal("failed filter fabricated source")
	}
	first := invoke(request("action=page.middleware&limit=1"), 200)
	cursor := auditListResponseCursor(t, first)
	if cursor == "" {
		t.Fatal("missing actual signed continuation")
	}
	next := invoke(request("limit=1&action=page.middleware&cursor="+url.QueryEscape(cursor)), 200)
	if !strings.Contains(next.Body.String(), older) || strings.Contains(next.Body.String(), id) || auditListResponseCursor(t, next) != "" {
		t.Fatal("continuation skipped/repeated source")
	}
	invoke(request("action=page.other&limit=1&cursor="+url.QueryEscape(cursor)), 404)
	for _, query := range []string{"outcome=rejected", "action=page.middleware&%61ction=page.middleware", "from=2026-02-30T00:00:00Z", "limit=0", "cursor=not-a-signed-cursor"} {
		want := 400
		if strings.HasPrefix(query, "cursor=") {
			want = 404
		}
		invoke(request(query), want)
	}
	missing := request("")
	missing.Header.Del("Cookie")
	invoke(missing, 401)
	wrong := request("")
	wrong.Header.Set("Cookie", browserSessionCookie+"=wrong-session")
	invoke(wrong, 401)
	duplicate := request("")
	duplicate.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-export-browser-fixture"})
	invoke(duplicate, 401)
	scope := request("")
	scope.Header.Set(expectedScopeHeader, "wrong-scope")
	invoke(scope, 409)
	// Measure complete bytes through the actual middleware. The prior gate2
	// terminal H+49 fixture remains separate; this also exercises a real cursor.
	fill := 900000
	setSize := func(n int) {
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
		setSize(fill)
		res = invoke(request("action=page.middleware&limit=1"), 200)
		if res.Body.Len() == auditListHardBytes {
			break
		}
		fill += auditListHardBytes - res.Body.Len()
	}
	if res.Body.Len() != auditListHardBytes || auditListResponseCursor(t, res) == "" {
		t.Fatal("actual middleware hard edge not reached")
	}
	for _, delta := range []int{-1, 0, 1} {
		setSize(fill + delta)
		want := 200
		if delta > 0 {
			want = 503
		}
		got := invoke(request("action=page.middleware&limit=1"), want)
		if want == 200 && got.Body.Len() != auditListHardBytes+delta {
			t.Fatal("public byte bound changed")
		}
	}
	setSize(10)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{"bad":null}' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	invoke(request("action=page.middleware"), 503)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET metadata='{}' WHERE id=$1;`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET authenticated_at=clock_timestamp()-interval '1 day' WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	invoke(request("action=page.middleware"), 200)
	f.groupScope(t, ctx)
	invoke(request("action=page.middleware&limit=1&cursor="+url.QueryEscape(cursor)), 200)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_group_mappings SET role='read_only_viewer' WHERE organization_id=$1 AND group_reference='scim-group-test-audit-export'`, f.identity.Scope.OrganizationID().String()); err != nil {
		t.Fatal(err)
	}
	invoke(request("action=page.middleware&limit=1&cursor="+url.QueryEscape(cursor)), 403)
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	// Removing the only selected scope means real authentication itself fails.
	invoke(request("action=page.middleware&limit=1&cursor="+url.QueryEscape(cursor)), 401)
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	invoke(request(""), 401)
}

func TestAuditExportPublicPageHTTPPostgresPostWait(t *testing.T) {
	for _, mode := range []string{"session", "group", "graph"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			f := auditExportPGFixture(t, ctx)
			if mode == "group" {
				f.groupScope(t, ctx)
			}
			secured := auditPublicPageSecuredFixture(t, ctx, f)
			observer, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			tx, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM zasp_product_sessions WHERE token_digest=$1 FOR UPDATE`, f.digest[:]); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			child, stop := context.WithCancel(ctx)
			done := make(chan *httptest.ResponseRecorder, 1)
			settled := false
			defer func() {
				stop()
				_ = tx.Rollback(context.Background())
				if !settled {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("middleware request failed to join")
					}
				}
			}()
			go func() {
				res := httptest.NewRecorder()
				secured.ServeHTTP(res, auditPublicPageAuthenticatedRequest(child, f, ""))
				done <- res
			}()
			for {
				var waiting bool
				if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT zasp_audit_export_public_page(%')`, f.api.PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case res := <-done:
					settled = true
					t.Fatal("HTTP did not reach registered page wait", res.Code)
				case <-ctx.Done():
					t.Fatal("page lock wait missing")
				case <-time.After(10 * time.Millisecond):
				}
			}
			want := 401
			switch mode {
			case "session":
				_, err = tx.Exec(ctx, `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:])
			case "group":
				want = 403
				_, err = tx.Exec(ctx, `DELETE FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, f.identity.Scope.OrganizationID().String(), f.identity.PrincipalID.String())
			case "graph":
				want = 503
				_, err = tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case res := <-done:
				settled = true
				if res.Code != want || strings.Contains(res.Body.String(), `"items"`) {
					t.Fatal("postwait HTTP authority escaped", res.Code, res.Body.String())
				}
			case <-ctx.Done():
				t.Fatal("postwait HTTP did not settle")
			}
		})
	}
}
