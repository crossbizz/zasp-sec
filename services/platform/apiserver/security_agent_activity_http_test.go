package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type activityHTTPAuthority struct {
	*securityAgentPublicAuthorityStub
	page   SecurityAgentActivityRunPage
	err    error
	input  SecurityAgentActivityRunRequest
	digest []byte
}

func TestSecurityAgentActivityHTTPPagination(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view"}
	run := runContextDetailFixture(t, "").Run
	stamp := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	stub := &activityHTTPAuthority{securityAgentPublicAuthorityStub: &securityAgentPublicAuthorityStub{}, page: SecurityAgentActivityRunPage{SecurityAgentRunPage: SecurityAgentRunPage{Items: []SecurityAgentRun{run}, NextID: run.ID, NextCreatedAt: &stamp}, Coverage: "complete"}}
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewSecurityAgentWorkflowSurface(http.NotFoundHandler(), handler)
	if err != nil {
		t.Fatal(err)
	}
	read := func(kind, query string) *httptest.ResponseRecorder {
		request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgentActivityRuns", map[string]string{"kind": kind, "id": activityRelatedTarget}, "GET", "/api/v1/security-agent-activity/"+kind+"/"+activityRelatedTarget+"/runs", "")
		request.URL.RawQuery = query
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-browser-session"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := read("finding", "limit=1")
	var wire struct {
		Next string `json:"next_cursor"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.Next == "" {
		t.Fatalf("cursor missing: %s", response.Body.String())
	}
	stub.page = SecurityAgentActivityRunPage{SecurityAgentRunPage: SecurityAgentRunPage{Items: []SecurityAgentRun{}}, Coverage: "complete"}
	if response := read("finding", "limit=1&cursor="+url.QueryEscape(wire.Next)); response.Code != 200 || !stub.input.BeforeCreatedAt.Equal(stamp) || stub.input.BeforeID != run.ID {
		t.Fatalf("continuation=%s input=%#v", response.Body.String(), stub.input)
	}
	before := stub.calls
	if response := read("finding", "limit=2&cursor="+url.QueryEscape(wire.Next)); response.Code != 400 || stub.calls != before {
		t.Fatal("cursor rebound to other limit")
	}
	for _, kind := range []string{"session", "audit"} {
		if response := read(kind, ""); response.Code != 403 || stub.calls != before {
			t.Fatal("kind-specific permission bypass")
		}
	}
	for _, change := range []func(*SecurityAgentActivityRunPage){
		func(p *SecurityAgentActivityRunPage) { p.Items = nil }, func(p *SecurityAgentActivityRunPage) { p.Coverage = "unknown" }, func(p *SecurityAgentActivityRunPage) { p.Items = []SecurityAgentRun{run, run} }, func(p *SecurityAgentActivityRunPage) { p.NextID = run.ID },
	} {
		stub.page = SecurityAgentActivityRunPage{SecurityAgentRunPage: SecurityAgentRunPage{Items: []SecurityAgentRun{}}, Coverage: "complete"}
		change(&stub.page)
		if response := read("finding", ""); response.Code != 503 {
			t.Fatalf("invalid page emitted: %s", response.Body.String())
		}
	}
}

func TestSecurityAgentActivityOperationRegistration(t *testing.T) {
	for _, operation := range CoreOperations() {
		if operation.OperationID == "listSecurityAgentActivityRuns" {
			if operation.Method != "GET" || operation.Pattern != "/api/v1/security-agent-activity/{kind}/{id}/runs" || operation.Permission != "view" || !equalStrings(operation.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
				t.Fatalf("relation registration=%#v", operation)
			}
			return
		}
	}
	t.Fatal("reverse activity operation is not registered")
}

func (s *activityHTTPAuthority) ListSecurityAgentActivityRuns(_ context.Context, _ RequestIdentity, input SecurityAgentActivityRunRequest, digest []byte) (SecurityAgentActivityRunPage, error) {
	s.calls++
	s.input = input
	s.digest = bytes.Clone(digest)
	return s.page, s.err
}

func TestSecurityAgentActivityHTTP(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
	run := runContextDetailFixture(t, "").Run
	for _, tc := range []struct {
		name, query   string
		change        func(*http.Request)
		err           error
		status, calls int
	}{
		{name: "exact", status: 200, calls: 1},
		{name: "limited", query: "limit=1", status: 200, calls: 1},
		{name: "empty cursor", query: "cursor=", status: 400},
		{name: "fake cursor", query: "cursor=arbitrary", status: 400},
		{name: "duplicate limit", query: "limit=1&limit=2", status: 400},
		{name: "unknown query", query: "environment_id=other", status: 400},
		{name: "too many", query: "limit=101", status: 400},
		{name: "missing cookie", change: func(r *http.Request) { r.Header.Del("Cookie") }, status: 401},
		{name: "duplicate cookie", change: func(r *http.Request) { r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "another"}) }, status: 401},
		{name: "mixed credentials", change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") }, status: 401},
		{name: "wrong method", change: func(r *http.Request) { r.Method = "POST" }, status: 400},
		{name: "body", change: func(r *http.Request) { r.ContentLength = 1 }, status: 400},
		{name: "unknown-length body", change: func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.TransferEncoding = []string{"chunked"}
		}, status: 400},
		{name: "permission", change: func(r *http.Request) {
			bad := identity
			bad.Permissions = []string{"view_audit"}
			*r = *r.WithContext(context.WithValue(r.Context(), identityContextKey{}, bad))
		}, status: 403},
		{name: "denied", err: ErrAuditExportForbidden, status: 403, calls: 1},
		{name: "missing", err: ErrRepositoryNotFound, status: 404, calls: 1},
		{name: "unavailable", err: ErrRepositoryUnavailable, status: 503, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &activityHTTPAuthority{securityAgentPublicAuthorityStub: &securityAgentPublicAuthorityStub{}, page: SecurityAgentActivityRunPage{SecurityAgentRunPage: SecurityAgentRunPage{Items: []SecurityAgentRun{run}}, Coverage: "partial"}, err: tc.err}
			handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgentActivityRuns", map[string]string{"kind": "finding", "id": activityRelatedTarget}, "GET", "/api/v1/security-agent-activity/finding/"+activityRelatedTarget+"/runs", "")
			request.URL.RawQuery = tc.query
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-browser-session"})
			if tc.change != nil {
				tc.change(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || stub.calls != tc.calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, stub.calls, response.Body.String())
			}
			if tc.status == 200 {
				var got struct {
					Items    []SecurityAgentRun `json:"items"`
					Coverage string             `json:"coverage"`
				}
				if json.Unmarshal(response.Body.Bytes(), &got) != nil || len(got.Items) != 1 || got.Items[0].ID != run.ID || got.Coverage != "partial" {
					t.Fatalf("public page=%s", response.Body.String())
				}
				digest := sha256.Sum256([]byte("owned-browser-session"))
				if !bytes.Equal(stub.digest, digest[:]) || stub.input.Kind != "finding" || stub.input.EntityID != activityRelatedTarget {
					t.Fatal("relation request lost binding")
				}
			}
		})
	}
}
