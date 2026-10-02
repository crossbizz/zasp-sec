package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type auditListLegacyFixture struct {
	administrationRecorder
	payload json.RawMessage
}

func auditListInvoke(t *testing.T, h *identityHTTPHandler, identity RequestIdentity, query string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	request := workflowRequest(t, identity, testCorrelationID, "listAuditEvents", nil, http.MethodGet, "/api/v1/audit-events?"+query, "")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-page-cookie"})
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}
func auditListResponseCursor(t *testing.T, r *httptest.ResponseRecorder) string {
	t.Helper()
	var page struct {
		Info struct {
			Cursor string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if json.Unmarshal(r.Body.Bytes(), &page) != nil {
		t.Fatal("invalid public page")
	}
	return page.Info.Cursor
}

func TestAuditExportPublicPageHTTPCursorsAndLegacy(t *testing.T) {
	item := string(auditListItemFixture(t))
	r, db, identity := auditListRepositoryFixture(t, json.RawMessage(`{"items":[`+item+`],"has_more":true}`))
	h := &identityHTTPHandler{auditPublicPages: r, signingKey: []byte(strings.Repeat("k", 32))}
	first := auditListInvoke(t, h, identity, "action=policy.update", nil)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	token := auditListResponseCursor(t, first)
	if len(token) > 512 || token == "" {
		t.Fatal("invalid emitted token")
	}
	nextItem := strings.Replace(item, "72000001-0000-4000-8000-000000000001", "71000001-0000-4000-8000-000000000001", 1)
	db.responses[postgresAuditPublicPageSQL] = json.RawMessage(`{"items":[` + nextItem + `],"has_more":false}`)
	next := auditListInvoke(t, h, identity, "limit=50&action=policy.update&cursor="+url.QueryEscape(token), nil)
	if next.Code != 200 || auditListResponseCursor(t, next) != "" || db.args[8] != "pid_72000001-0000-4000-8000-000000000001" || db.args[7] != (time.Date(2026, 9, 12, 0, 0, 0, 123456000, time.UTC)) {
		t.Fatal("cursor did not resume from returned row", next.Code, db.args)
	}
	for _, kind := range []string{"filter", "limit", "principal", "scope", "key", "operation", "old-version", "invalid-id", "submicrosecond"} {
		t.Run(kind, func(t *testing.T) {
			selected := identity
			query := "action=policy.update&cursor=" + token
			handler := *h
			switch kind {
			case "filter":
				query = "action=policy.delete&cursor=" + token
			case "limit":
				query = "limit=49&action=policy.update&cursor=" + token
			case "principal":
				selected.PrincipalID, _ = domain.ParseProductID("pid_10000004-0000-4000-8000-000000000009")
			case "scope":
				other, _ := domain.ParseProductID("pid_10000003-0000-4000-8000-000000000009")
				selected.Scope, _ = domain.NewScope(identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), other)
			case "key":
				handler.signingKey = []byte(strings.Repeat("j", 32))
			default:
				normalized, _ := parseAuditListQuery("action=policy.update", identity)
				position := administrationCursor{AfterID: "pid_72000001-0000-4000-8000-000000000001", AfterTime: "2026-09-12T00:00:00.123456Z"}
				op := "listAuditEvents"
				switch kind {
				case "operation":
					op = "listSessionEvents"
				case "old-version":
					normalized.digest = administrationCursorBinding(url.Values{"action": {"policy.update"}})
				case "invalid-id":
					position.AfterID = "not-a-product-id"
				case "submicrosecond":
					position.AfterTime = "2026-09-12T00:00:00.123456001Z"
				}
				query = "action=policy.update&cursor=" + handler.encodeAdministrationCursor(identity, op, normalized.digest, position)
			}
			before := len(db.queries)
			response := auditListInvoke(t, &handler, selected, query, nil)
			if response.Code != 404 || len(db.queries) != before {
				t.Fatal("foreign/invalid cursor reached authority", response.Code)
			}
		})
	}
	legacy := &identityHTTPHandler{administration: &auditListLegacyFixture{payload: json.RawMessage(`{"items":[` + item + `],"has_more":true}`)}, signingKey: h.signingKey}
	if response := auditListInvoke(t, legacy, identity, "action=policy.update", nil); response.Code != 400 {
		t.Fatal("nil legacy gained filters")
	}
	if response := auditListInvoke(t, legacy, identity, "", nil); response.Code != 200 || auditListResponseCursor(t, response) != "" {
		t.Fatal("nil legacy semantics changed")
	}
}

func TestAuditExportPublicPageHTTPAuthorizationAndErrors(t *testing.T) {
	for _, kind := range []string{"missing-cookie", "duplicate-cookie", "bearer", "permission", "csrf", "method", "body", "canceled", "sql-auth", "sql-forbidden", "sql-input", "sql-source"} {
		t.Run(kind, func(t *testing.T) {
			r, db, identity := auditListRepositoryFixture(t, json.RawMessage(`{"items":[],"has_more":false}`))
			h := &identityHTTPHandler{auditPublicPages: r, signingKey: []byte(strings.Repeat("k", 32))}
			want := 401
			switch kind {
			case "permission":
				identity.Permissions = []string{"view"}
				want = 403
			case "csrf":
				identity.CSRFToken = ""
			case "bearer":
				identity.CredentialKind = CredentialBearerToken
			case "method", "body":
				want = 400
			case "canceled", "sql-source":
				want = 503
			case "sql-input":
				want = 400
			case "sql-forbidden":
				want = 403
			}
			codes := map[string]string{"sql-auth": "28000", "sql-forbidden": "42501", "sql-input": "22023", "sql-source": "55000"}
			if code := codes[kind]; code != "" {
				db.errors[postgresAuditPublicPageSQL] = &pgconn.PgError{Code: code, Message: "private-sensitive-source"}
			}
			before := len(db.queries)
			response := auditListInvoke(t, h, identity, "", func(request *http.Request) {
				switch kind {
				case "missing-cookie":
					request.Header.Del("Cookie")
				case "duplicate-cookie":
					request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "other-cookie"})
				case "method":
					request.Method = http.MethodPost
				case "body":
					request.Body = http.NoBody
					request.ContentLength = 1
				case "canceled":
					ctx, cancel := context.WithCancel(request.Context())
					cancel()
					*request = *request.WithContext(ctx)
				}
			})
			if response.Code != want || strings.Contains(response.Body.String(), "private-sensitive-source") || strings.Contains(response.Body.String(), `"items"`) || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("wrong safe error", response.Code, response.Body.String())
			}
			if !strings.HasPrefix(kind, "sql-") && len(db.queries) != before {
				t.Fatal("invalid identity/query reached DB")
			}
		})
	}
}

func TestAuditExportPublicPageHTTPMarshalExactBounds(t *testing.T) {
	for _, more := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "continuation"}[more], func(t *testing.T) {
			item := auditListItemFixture(t)
			r, db, identity := auditListRepositoryFixture(t, nil)
			h := &identityHTTPHandler{auditPublicPages: r, signingKey: []byte(strings.Repeat("k", 32))}
			// Reach the real writer edge using its measured successful body, including
			// its actual HMAC cursor and sole newline, never an estimated cursor length.
			fill := 900000
			build := func(n int) json.RawMessage {
				metadata, _ := json.Marshal(map[string]string{strings.Repeat("k", n): "", "<>&\u2028\u2029\"\\": "<>&\u2028\u2029\"\\"})
				return json.RawMessage(strings.Replace(string(item), `"metadata":{}`, `"metadata":`+string(metadata), 1))
			}
			var exact []byte
			for attempt := 0; attempt < 3; attempt++ {
				selected := build(fill)
				db.responses[postgresAuditPublicPageSQL], _ = json.Marshal(map[string]any{"items": []json.RawMessage{selected}, "has_more": more})
				response := auditListInvoke(t, h, identity, "", nil)
				if response.Code != 200 {
					t.Fatal("admissible calibration refused", response.Code, response.Body.String())
				}
				if len(response.Body.Bytes()) == auditListHardBytes {
					exact = bytes.Clone(response.Body.Bytes())
					break
				}
				fill += auditListHardBytes - len(response.Body.Bytes())
			}
			if exact == nil {
				t.Fatal("actual writer never reached H")
			}
			for _, delta := range []int{-1, 0, 1} {
				selected := build(fill + delta)
				db.responses[postgresAuditPublicPageSQL], _ = json.Marshal(map[string]any{"items": []json.RawMessage{selected}, "has_more": more})
				response := auditListInvoke(t, h, identity, "", nil)
				if delta == 1 {
					if response.Code != 503 || bytes.Contains(response.Body.Bytes(), []byte(`"items"`)) {
						t.Fatal("over-hard output committed partial200", response.Code)
					}
					continue
				}
				if response.Code != 200 || len(response.Body.Bytes()) != auditListHardBytes+delta || response.Body.Bytes()[len(response.Body.Bytes())-1] != '\n' || bytes.HasSuffix(response.Body.Bytes(), []byte("\n\n")) {
					t.Fatal("wrong checked bytes", delta, response.Code, len(response.Body.Bytes()))
				}
			}
		})
	}
}

func (r *auditListLegacyFixture) ReadAdministration(context.Context, RequestIdentity, string, map[string]string) (json.RawMessage, error) {
	return r.payload, nil
}

func auditListItemFixture(t *testing.T) json.RawMessage {
	t.Helper()
	return json.RawMessage(`{"id":"pid_72000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","actor_id":"pid_10000004-0000-4000-8000-000000000004","action":"policy.update","target_id":"policy-fixture","outcome":"succeeded","metadata":{},"occurred_at":"2026-09-12T00:00:00.123456Z"}`)
}

func TestAuditExportPublicPageHTTPConstructorSelection(t *testing.T) {
	page, db, identity := auditListRepositoryFixture(t, json.RawMessage(`{"items":[],"has_more":false}`))
	core, err := NewPostgresRepository(newPersistentJSONDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie := fixtureCookiePolicy()
	cookie.AuditPublicPages = page
	handlers, _, err := NewProductionHandlers(core, CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) {
		return SessionGrant{}, ErrRepositoryUnavailable
	}), http.NotFoundHandler(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "listAuditEvents", nil, http.MethodGet, "/api/v1/audit-events?action=policy.update", "")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-page-cookie"})
	response := httptest.NewRecorder()
	handlers.Identity.ServeHTTP(response, request)
	if response.Code != 200 || db.query != postgresAuditPublicPageSQL {
		t.Fatal("optional repository was not carried into actual identity handler", response.Code)
	}
	db.responses[postgresAuditPublicPageReadySQL] = json.RawMessage(`false`)
	response = httptest.NewRecorder()
	handlers.Identity.ServeHTTP(response, request)
	if response.Code != 503 || strings.Contains(response.Body.String(), `"items"`) {
		t.Fatal("selected page fell back after drift", response.Code)
	}
}

func TestAuditExportPublicPageHTTPYearOneCursor(t *testing.T) {
	item := strings.Replace(string(auditListItemFixture(t)), "2026-09-12T00:00:00.123456Z", "0001-01-01T00:00:00.000000Z", 1)
	r, db, identity := auditListRepositoryFixture(t, json.RawMessage(`{"items":[`+item+`],"has_more":true}`))
	h := &identityHTTPHandler{auditPublicPages: r, signingKey: []byte(strings.Repeat("k", 32))}
	first := auditListInvoke(t, h, identity, "", nil)
	if first.Code != 200 {
		t.Fatal("legal finite year-one row refused", first.Code)
	}
	token := auditListResponseCursor(t, first)
	db.responses[postgresAuditPublicPageSQL] = json.RawMessage(`{"items":[` + strings.Replace(item, "72000001", "71000001", 1) + `],"has_more":false}`)
	next := auditListInvoke(t, h, identity, "cursor="+token, nil)
	if next.Code != 200 || db.args[7] != (time.Time{}) || db.args[8] != "pid_72000001-0000-4000-8000-000000000001" {
		t.Fatal("legal year-one cursor confused with absent timestamp", next.Code)
	}
	// Equal-time descending ID checks must still run at Go's zero-time instant.
	db.responses[postgresAuditPublicPageSQL] = json.RawMessage(`{"items":[` + item + `],"has_more":false}`)
	if got := auditListInvoke(t, h, identity, "cursor="+token, nil); got.Code != 503 {
		t.Fatal("year-one cursor repeated original row", got.Code)
	}
}

func TestAuditExportPublicPageHTTPValidFilterAndShortPage(t *testing.T) {
	for _, rawQuery := range []string{"action=policy.update", ""} {
		t.Run(rawQuery, func(t *testing.T) {
			identity := fixtureRequestIdentity(t)
			identity.Permissions = append(identity.Permissions, "view_audit")
			identity.FreshAuthenticated = false
			payload := json.RawMessage(`{"items":[` + string(auditListItemFixture(t)) + `],"has_more":true}`)
			repository, _, _ := auditListRepositoryFixture(t, payload)
			handler := &identityHTTPHandler{auditPublicPages: repository, administration: &auditListLegacyFixture{payload: payload}, signingKey: []byte(strings.Repeat("k", 32))}
			request := workflowRequest(t, identity, testCorrelationID, "listAuditEvents", nil, http.MethodGet, "/api/v1/audit-events?"+rawQuery, "")
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-audit-page-cookie"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var got struct {
				Items []json.RawMessage `json:"items"`
				Page  struct {
					More   bool    `json:"has_more"`
					Cursor *string `json:"next_cursor"`
				} `json:"page_info"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &got) != nil || len(got.Items) != 1 || !got.Page.More || got.Page.Cursor == nil || *got.Page.Cursor == "" {
				t.Fatalf("valid filtered/byte-shortened page lost continuation: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
