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

type activityTargetsHTTPAuthority struct {
	*securityAgentPublicAuthorityStub
	page   SecurityAgentActivityTargetPage
	err    error
	input  SecurityAgentActivityTargetRequest
	digest []byte
}

func TestSecurityAgentActivityTargetsHTTPPagination(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view"}
	stub := &activityTargetsHTTPAuthority{securityAgentPublicAuthorityStub: &securityAgentPublicAuthorityStub{}, page: SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{{Kind: "finding", ID: activityRelatedTarget}}, Coverage: "partial", NextID: activityRelatedTarget}}
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewSecurityAgentWorkflowSurface(http.NotFoundHandler(), handler)
	if err != nil {
		t.Fatal(err)
	}
	read := func(query string) *httptest.ResponseRecorder {
		request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgentRunActivity", map[string]string{"kind": "finding", "id": runContextTestRunID}, "GET", "/api/v1/security-agent-runs/"+runContextTestRunID+"/activity/finding", "")
		request.URL.RawQuery = query
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-browser-session"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := read("limit=1")
	var wire struct {
		Next string `json:"next_cursor"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.Next == "" {
		t.Fatalf("forward HTTP cursor=%s", response.Body.String())
	}
	// Returning the first page again cannot emit a nonadvancing continuation.
	if response := read("limit=1&cursor=" + url.QueryEscape(wire.Next)); response.Code != 503 {
		t.Fatalf("nonadvancing forward page=%s", response.Body.String())
	}
	stub.page = SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{}, Coverage: "partial"}
	if response := read("limit=1&cursor=" + url.QueryEscape(wire.Next)); response.Code != 200 || stub.input.AfterID != activityRelatedTarget {
		t.Fatalf("forward continuation=%s", response.Body.String())
	}
	before := stub.calls
	if response := read("limit=2&cursor=" + url.QueryEscape(wire.Next)); response.Code != 400 || stub.calls != before {
		t.Fatal("forward cursor limit rebound")
	}
	for _, change := range []func(*SecurityAgentActivityTargetPage){
		func(p *SecurityAgentActivityTargetPage) { p.Items = nil }, func(p *SecurityAgentActivityTargetPage) { p.Coverage = "unknown" }, func(p *SecurityAgentActivityTargetPage) {
			p.Items = []SecurityAgentActivityTarget{{Kind: "audit", ID: activityRelatedTarget}}
		}, func(p *SecurityAgentActivityTargetPage) {
			p.Items = []SecurityAgentActivityTarget{{Kind: "finding", ID: activityRelatedTarget}, {Kind: "finding", ID: activityRelatedTarget}}
		}, func(p *SecurityAgentActivityTargetPage) { p.NextID = activityRelatedTarget },
	} {
		stub.page = SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{}, Coverage: "complete"}
		change(&stub.page)
		if response := read(""); response.Code != 503 {
			t.Fatalf("invalid forward page emitted: %s", response.Body.String())
		}
	}
}

func (s *activityTargetsHTTPAuthority) ListSecurityAgentRunActivity(_ context.Context, _ RequestIdentity, input SecurityAgentActivityTargetRequest, digest []byte) (SecurityAgentActivityTargetPage, error) {
	s.calls++
	s.input = input
	s.digest = bytes.Clone(digest)
	return s.page, s.err
}

func TestSecurityAgentActivityTargetsHTTP(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "investigate_sessions"}
	for _, tc := range []struct {
		name, kind, id, query string
		change                func(*http.Request)
		err                   error
		status, calls         int
	}{
		{name: "finding", kind: "finding", status: 200, calls: 1}, {name: "path", kind: "attack_path", status: 200, calls: 1}, {name: "session", kind: "session", status: 200, calls: 1}, {name: "audit", kind: "audit", status: 200, calls: 1},
		{name: "unknown kind", kind: "manual", status: 400}, {name: "invalid id", kind: "finding", id: "invalid", status: 400},
		{name: "unknown query", kind: "finding", query: "extra=1", status: 400}, {name: "empty cursor", kind: "finding", query: "cursor=", status: 400}, {name: "duplicate limit", kind: "finding", query: "limit=1&limit=2", status: 400},
		{name: "missing cookie", kind: "finding", change: func(r *http.Request) { r.Header.Del("Cookie") }, status: 401},
		{name: "mixed credentials", kind: "finding", change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") }, status: 401},
		{name: "duplicate cookie", kind: "finding", change: func(r *http.Request) { r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "other"}) }, status: 401},
		{name: "wrong method", kind: "finding", change: func(r *http.Request) { r.Method = "POST" }, status: 400},
		{name: "unknown length body", kind: "finding", change: func(r *http.Request) { r.ContentLength = -1; r.Body = io.NopCloser(strings.NewReader("x")) }, status: 400},
		{name: "no session permission", kind: "session", change: func(r *http.Request) {
			bad := identity
			bad.Permissions = []string{"view"}
			*r = *r.WithContext(context.WithValue(r.Context(), identityContextKey{}, bad))
		}, status: 403},
		{name: "no audit permission", kind: "audit", change: func(r *http.Request) {
			bad := identity
			bad.Permissions = []string{"view"}
			*r = *r.WithContext(context.WithValue(r.Context(), identityContextKey{}, bad))
		}, status: 403},
		{name: "forbidden", kind: "finding", err: ErrAuditExportForbidden, status: 403, calls: 1}, {name: "missing", kind: "finding", err: ErrRepositoryNotFound, status: 404, calls: 1}, {name: "unavailable", kind: "finding", err: ErrRepositoryUnavailable, status: 503, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &activityTargetsHTTPAuthority{securityAgentPublicAuthorityStub: &securityAgentPublicAuthorityStub{}, page: SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{{Kind: tc.kind, ID: activityRelatedTarget}}, Coverage: "complete"}, err: tc.err}
			handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			id := tc.id
			if id == "" {
				id = runContextTestRunID
			}
			request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgentRunActivity", map[string]string{"kind": tc.kind, "id": id}, "GET", "/api/v1/security-agent-runs/"+id+"/activity/"+tc.kind, "")
			request.URL.RawQuery = tc.query
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-browser-session"})
			if tc.change != nil {
				tc.change(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || stub.calls != tc.calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("forward HTTP=%d calls=%d body=%s", response.Code, stub.calls, response.Body.String())
			}
			if tc.status == 200 {
				var page struct {
					Items    []SecurityAgentActivityTarget `json:"items"`
					Coverage string                        `json:"coverage"`
				}
				if json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Kind != tc.kind || page.Coverage != "complete" {
					t.Fatalf("forward response=%s", response.Body.String())
				}
				digest := sha256.Sum256([]byte("owned-browser-session"))
				if !bytes.Equal(stub.digest, digest[:]) || stub.input.Kind != tc.kind || stub.input.RunID != runContextTestRunID {
					t.Fatal("forward binding lost")
				}
			}
		})
	}
}

func TestSecurityAgentActivityTargetsOperationRegistration(t *testing.T) {
	for _, operation := range CoreOperations() {
		if operation.OperationID == "listSecurityAgentRunActivity" {
			if operation.Pattern != "/api/v1/security-agent-runs/{id}/activity/{kind}" || operation.Method != "GET" || operation.Permission != "view" || !equalStrings(operation.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
				t.Fatalf("forward registration=%#v", operation)
			}
			return
		}
	}
	t.Fatal("forward activity operation not registered")
}
