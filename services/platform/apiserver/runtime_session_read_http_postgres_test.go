package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func testRuntimeSessionReadHTTP(t *testing.T, ctx context.Context, api *pgx.Conn, identity RequestIdentity) {
	t.Helper()
	identity.Permissions = append(identity.Permissions, "investigate_sessions")
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handler := &identityHTTPHandler{administration: repository, signingKey: []byte(strings.Repeat("r", 32)), now: time.Now}
	request := func(who RequestIdentity, operation, id, query string) *httptest.ResponseRecorder {
		path := "/api/v1/sessions"
		parameters := map[string]string{}
		if id != "" {
			path += "/" + id
			parameters["id"] = id
		}
		if operation == "listSessionEvents" {
			path += "/events"
		}
		// Preserve the routed operation and correlation context established by the
		// shared HTTP fixture. The repository uses the actual least-privileged login.
		req := workflowRequest(t, who, testCorrelationID, operation, parameters, http.MethodGet, path+"?"+query, "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	const known = "pid_96000007-0000-4000-8000-000000000007"
	for _, target := range []string{known, "unattributed"} {
		response := request(identity, "getSession", target, "")
		var summary map[string]json.RawMessage
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &summary) != nil || summary["confidence_counts"] == nil || summary["expires_at"] != nil || response.Header().Get("ETag") != "" {
			t.Fatalf("runtime detail=%d %s", response.Code, response.Body.String())
		}
	}
	for _, scenario := range []struct {
		operation, id, query string
		count                int
	}{
		{"listSessions", "", "kind=runtime&limit=1", 2},
		{"listSessionEvents", known, "limit=1", 2},
		{"listSessionEvents", "unattributed", "limit=1", 1},
		{"listSessions", "", "kind=runtime&limit=1&from=2026-09-09T10:00:02Z&to=2026-09-09T10:00:02Z", 1},
	} {
		cursor := ""
		seen := map[string]bool{}
		priorAt, priorID := time.Time{}, ""
		for pageIndex := 0; pageIndex < 4; pageIndex++ {
			query := scenario.query
			if cursor != "" {
				query += "&cursor=" + url.QueryEscape(cursor)
			}
			response := request(identity, scenario.operation, scenario.id, query)
			var page struct {
				Items []struct {
					ID         string    `json:"id"`
					At         time.Time `json:"at"`
					Confidence string    `json:"confidence"`
					Session    *string   `json:"session_id"`
					Agent      *string   `json:"agent_id"`
				} `json:"items"`
				Info struct {
					Cursor *string `json:"next_cursor"`
					More   bool    `json:"has_more"`
				} `json:"page_info"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil {
				t.Fatalf("page=%d %s", response.Code, response.Body.String())
			}
			for _, item := range page.Items {
				if seen[item.ID] {
					t.Fatal("duplicate cursor event")
				}
				seen[item.ID] = true
				if scenario.operation == "listSessionEvents" {
					if item.At.Before(priorAt) || item.At.Equal(priorAt) && item.ID <= priorID {
						t.Fatal("event order is not canonical")
					}
					priorAt, priorID = item.At, item.ID
					if scenario.id == "unattributed" && (item.Confidence != "unattributed" || item.Session != nil || item.Agent != nil) {
						t.Fatal("unknown attribution was invented")
					}
				}
			}
			if !page.Info.More {
				if page.Info.Cursor != nil {
					t.Fatal("terminal cursor retained")
				}
				break
			}
			if page.Info.Cursor == nil || *page.Info.Cursor == "" {
				t.Fatal("continuation omitted")
			}
			cursor = *page.Info.Cursor
		}
		if len(seen) != scenario.count {
			t.Fatalf("%s %s count=%d want=%d", scenario.operation, scenario.query, len(seen), scenario.count)
		}
	}
	foreign := identity
	other := mustProductID(t, "pid_99000001-0000-4000-8000-000000000001")
	foreign.Scope, err = domain.NewScope(other, identity.Scope.WorkspaceID(), identity.Scope.EnvironmentID())
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		who                  RequestIdentity
		operation, id, query string
	}{
		{foreign, "listSessions", "", "kind=runtime"}, {foreign, "getSession", known, ""}, {foreign, "listSessionEvents", known, ""},
		{identity, "getSession", runtimeReadSessionID, ""}, {identity, "listSessionEvents", runtimeReadSessionID, ""},
	} {
		response := request(scenario.who, scenario.operation, scenario.id, scenario.query)
		if response.Code != 404 || decodeErrorCode(t, response) != "not_found" || strings.Contains(response.Body.String(), "zasp_") {
			t.Fatalf("stable denied/missing response=%d %s", response.Code, response.Body.String())
		}
	}
}
