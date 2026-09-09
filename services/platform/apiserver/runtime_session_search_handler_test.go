package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRuntimeSessionSearchHandlerKeepsFiltersFreshnessAndPrincipalBoundCursor(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	status := sessionQueryStatusFixture(t)
	recorder := &runtimeSessionReadRecorder{payload: sessionQueryPageFixture(t, status, sessionQuerySummaryFixture(t, identity, runtimeReadSessionID), sessionQuerySummaryFixture(t, identity, "pid_98000001-0000-4000-8000-000000000001"))}
	handler := &identityHTTPHandler{administration: recorder, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
	query := url.Values{"kind": {"runtime"}, "limit": {"1"}, "process": {"/bin/agent"}, "file": {"/data/report"}, "tool": {"read_file"}, "domain": {"api.example.com"}, "resource": {"https://api.example.com/report"}, "credential_id": {identity.PrincipalID.String()}, "principal_id": {identity.PrincipalID.String()}, "decision": {"allow"}}
	request := func(who RequestIdentity, query url.Values) *httptest.ResponseRecorder {
		req := workflowRequest(t, who, testCorrelationID, "listSessions", nil, http.MethodGet, "/api/v1/sessions?"+query.Encode(), "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	first := request(identity, query)
	var page struct {
		Items    []json.RawMessage          `json:"items"`
		Search   RuntimeSessionSearchStatus `json:"search"`
		PageInfo struct {
			Cursor string `json:"next_cursor"`
			More   bool   `json:"has_more"`
		} `json:"page_info"`
	}
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Search.State != "catching_up" || page.Search.Pending != 1 || !page.PageInfo.More || page.PageInfo.Cursor == "" || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("runtime search page: status=%d body=%s", first.Code, first.Body.String())
	}
	for key := range query {
		if recorder.parameters[key] != query.Get(key) {
			t.Fatalf("filter %s lost at handler", key)
		}
	}
	query.Set("cursor", page.PageInfo.Cursor)
	changed := identity
	changed.PrincipalID = mustProductID(t, "pid_99000004-0000-4000-8000-000000000004")
	if response := request(changed, query); response.Code != 404 || recorder.reads != 1 {
		t.Fatal("cursor replayed under another principal")
	}
	query.Set("process", "/bin/other")
	if response := request(identity, query); response.Code != 404 || recorder.reads != 1 {
		t.Fatal("cursor replayed under different filters")
	}
	query.Set("process", "/bin/agent")
	if response := request(identity, query); response.Code != 200 || recorder.reads != 2 || recorder.parameters["after_id"] != runtimeReadSessionID {
		t.Fatal("cursor did not resume after the last displayed canonical ID")
	}
}

func TestRuntimeSessionSearchHandlerRejectsDSLAndConsoleFilterMixing(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, query := range []string{"kind=runtime&query=*", "kind=runtime&dsl=%7B%7D", "kind=runtime&process=a&process=b", "kind=runtime&decision=permit", "kind=console&process=%2Fbin%2Fagent", "kind=runtime&principal_id=invalid", "kind=runtime&domain=bad_domain", "kind=runtime&tool=%0Aread"} {
		recorder := &runtimeSessionReadRecorder{payload: json.RawMessage(`{"items":[]}`)}
		handler := &identityHTTPHandler{administration: recorder, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
		req := workflowRequest(t, identity, testCorrelationID, "listSessions", nil, http.MethodGet, "/api/v1/sessions?"+query, "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != 400 || recorder.reads != 0 {
			t.Fatalf("unsafe query reached store: %s status=%d", query, response.Code)
		}
	}
}
