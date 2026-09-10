package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

const runtimeReadSessionID = "pid_97000001-0000-4000-8000-000000000001"

func TestRuntimeSessionReadRepositorySeparatesRuntimeAndConsoleAuthority(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		operation, id, query string
		parameters           map[string]string
	}{
		{"listSessions", "", `SELECT zasp_runtime_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`, map[string]string{"kind": "runtime", "limit": "25"}},
		{"getSession", runtimeReadSessionID, `SELECT zasp_runtime_session_get($1,$2,$3,$4,$5)`, map[string]string{"id": runtimeReadSessionID}},
		{"getSession", "unattributed", `SELECT zasp_runtime_session_get($1,$2,$3,$4,$5)`, map[string]string{"id": "unattributed"}},
		{"listSessionEvents", runtimeReadSessionID, `SELECT zasp_runtime_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`, map[string]string{"id": runtimeReadSessionID, "limit": "25"}},
		{"getSessionEvent", runtimeReadSessionID, `SELECT zasp_runtime_session_event_get($1,$2,$3,$4,$5,$6)`, map[string]string{"id": runtimeReadSessionID, "eventId": runtimeReadSessionID}},
		{"getSessionEvent", "unattributed", `SELECT zasp_runtime_session_event_get($1,$2,$3,$4,$5,$6)`, map[string]string{"id": "unattributed", "eventId": runtimeReadSessionID}},
	} {
		t.Run(test.operation+test.id, func(t *testing.T) {
			database := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
			repository, err := NewPostgresRepository(database)
			if err != nil {
				t.Fatal(err)
			}
			_, err = repository.ReadAdministration(context.Background(), identity, test.operation, test.parameters)
			wantScope := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
			if err != nil || database.query != test.query || len(database.args) < 4 || !reflect.DeepEqual(database.args[:4], wantScope) {
				t.Fatalf("runtime read did not bind scope/principal: query=%s args=%v err=%v", database.query, database.args, err)
			}
		})
	}
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[]}`)}
	repository, _ := NewPostgresRepository(database)
	if _, err := repository.ReadAdministration(context.Background(), identity, "listSessions", map[string]string{"kind": "console", "limit": "25"}); err != nil || database.query != postgresListSessionsSQL {
		t.Fatal("console session compatibility changed")
	}
}

func TestRuntimeSessionEvidenceRouteAndHandlerRejectUnsupportedTargets(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		id, event, query string
		status, reads    int
	}{
		{runtimeReadSessionID, runtimeReadSessionID, "", 200, 1}, {"unattributed", runtimeReadSessionID, "", 200, 1},
		{"session-console-fixture", runtimeReadSessionID, "", 400, 0}, {"unattributed", "invalid", "", 400, 0},
		{"unattributed", runtimeReadSessionID, "?query=match_all", 400, 0}, {"unattributed", runtimeReadSessionID, "?cursor=ignored", 400, 0},
	} {
		parameters := map[string]string{"id": test.id, "eventId": test.event}
		if test.query == "" && validRouteParameters("getSessionEvent", parameters) != (test.status == 200) {
			t.Fatal("evidence route target validation drift", parameters)
		}
		r := &runtimeSessionReadRecorder{payload: json.RawMessage(`{"id":"event"}`)}
		h := &identityHTTPHandler{administration: r, now: time.Now}
		req := workflowRequest(t, identity, testCorrelationID, "getSessionEvent", parameters, http.MethodGet, "/api/v1/sessions/"+test.id+"/events/"+test.event+test.query, "")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != test.status || r.reads != test.reads {
			t.Fatalf("evidence request: status=%d reads=%d", res.Code, r.reads)
		}
		if test.status == 200 && res.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("evidence metadata response may be cached")
		}
	}
}

func TestRuntimeSessionReadRoutesNeverGrantConsoleRevocation(t *testing.T) {
	for _, id := range []string{runtimeReadSessionID, "unattributed"} {
		for _, operation := range []string{"getSession", "listSessionEvents"} {
			if !validRouteParameters(operation, map[string]string{"id": id}) {
				t.Fatalf("runtime read route rejected %s", id)
			}
		}
		if validRouteParameters("revokeSession", map[string]string{"id": id}) {
			t.Fatal("runtime investigation granted console login revocation")
		}
	}
	if !validRouteParameters("revokeSession", map[string]string{"id": "session-console-fixture"}) {
		t.Fatal("console revocation compatibility changed")
	}
}

type runtimeSessionReadRecorder struct {
	payload    json.RawMessage
	reads      int
	parameters map[string]string
}

func (r *runtimeSessionReadRecorder) ReadAdministration(_ context.Context, _ RequestIdentity, _ string, p map[string]string) (json.RawMessage, error) {
	r.reads++
	r.parameters = p
	return r.payload, nil
}
func (*runtimeSessionReadRecorder) MutateAdministration(context.Context, RequestIdentity, administrationMutation) (json.RawMessage, error) {
	return nil, ErrRepositoryOperation
}

func TestRuntimeSessionReadHandlerAcceptsExplicitKindAndRejectsUnsupportedFilters(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		query  string
		status int
		reads  int
	}{
		{"kind=runtime&limit=25", 200, 1},
		{"kind=console&limit=25", 200, 1},
		{"kind=invalid", 400, 0},
		{"kind=runtime&agent_id=product-console", 400, 0},
		{"kind=runtime&principal_id=" + identity.PrincipalID.String(), 200, 1},
		{"kind=runtime&query=%7B%22match_all%22%3A%7B%7D%7D", 400, 0},
	} {
		r := &runtimeSessionReadRecorder{payload: json.RawMessage(`{"items":[]}`)}
		h := &identityHTTPHandler{administration: r, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
		req := workflowRequest(t, identity, testCorrelationID, "listSessions", nil, http.MethodGet, "/api/v1/sessions?"+test.query, "")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != test.status || r.reads != test.reads {
			t.Fatalf("%s: status=%d reads=%d", test.query, res.Code, r.reads)
		}
	}
}

func TestRuntimeSessionReadEventCursorIsBoundToItsInvestigation(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	r := &runtimeSessionReadRecorder{payload: json.RawMessage(`{"items":[{"id":"event-first","at":"2026-09-09T00:00:00Z"},{"id":"event-second","at":"2026-09-09T00:00:01Z"}]}`)}
	h := &identityHTTPHandler{administration: r, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
	request := func(id, query string) *httptest.ResponseRecorder {
		req := workflowRequest(t, identity, testCorrelationID, "listSessionEvents", map[string]string{"id": id}, http.MethodGet, "/api/v1/sessions/"+id+"/events?"+query, "")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		return res
	}
	first := request(runtimeReadSessionID, "limit=1")
	var page struct {
		PageInfo struct {
			Cursor string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.PageInfo.Cursor == "" {
		t.Fatal("first event page unavailable")
	}
	foreign := request("unattributed", "limit=1&cursor="+url.QueryEscape(page.PageInfo.Cursor))
	if foreign.Code != 404 || r.reads != 1 {
		t.Fatalf("cross-investigation cursor reached store: status=%d reads=%d", foreign.Code, r.reads)
	}
	same := request(runtimeReadSessionID, "limit=1&cursor="+url.QueryEscape(page.PageInfo.Cursor))
	if same.Code != 200 || r.reads != 2 {
		t.Fatalf("same-principal event cursor rejected: status=%d reads=%d", same.Code, r.reads)
	}
	identity.PrincipalID = mustProductID(t, "pid_99000004-0000-4000-8000-000000000004")
	otherPrincipal := request(runtimeReadSessionID, "limit=1&cursor="+url.QueryEscape(page.PageInfo.Cursor))
	if otherPrincipal.Code != 404 || r.reads != 2 {
		t.Fatalf("cross-principal event cursor reached store: status=%d reads=%d", otherPrincipal.Code, r.reads)
	}
}
