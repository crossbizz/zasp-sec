package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type auditHTTPAuthority struct {
	*securityAgentPublicAuthorityStub
	value    SecurityAgentAuditEvent
	err      error
	id       string
	digest   []byte
	identity RequestIdentity
}

func (s *auditHTTPAuthority) GetSecurityAgentAuditEvent(_ context.Context, identity RequestIdentity, id string, digest []byte) (SecurityAgentAuditEvent, error) {
	s.calls++
	s.id = id
	s.digest = bytes.Clone(digest)
	s.identity = identity
	return s.value, s.err
}

func TestSecurityAgentAuditHTTP(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit"}
	var event SecurityAgentAuditEvent
	if err := json.Unmarshal(activityAuditWire(t, identity), &event); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		change        func(*http.Request)
		err           error
		mutate        bool
		status, calls int
	}{
		{name: "exact", status: 200, calls: 1},
		{name: "missing cookie", change: func(r *http.Request) { r.Header.Del("Cookie") }, status: 401},
		{name: "duplicate cookie", change: func(r *http.Request) { r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "second"}) }, status: 401},
		{name: "bearer ambiguity", change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") }, status: 401},
		{name: "query", change: func(r *http.Request) { r.URL.RawQuery = "extra=1" }, status: 400},
		{name: "body", change: func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, status: 400},
		{name: "wrong method", change: func(r *http.Request) { r.Method = "POST" }, status: 400},
		{name: "denied", err: ErrAuditExportForbidden, status: 403, calls: 1},
		{name: "missing", err: ErrRepositoryNotFound, status: 404, calls: 1},
		{name: "unavailable", err: ErrRepositoryUnavailable, status: 503, calls: 1},
		{name: "foreign response", mutate: true, status: 503, calls: 1},
		{name: "missing permission", change: func(r *http.Request) {
			bad := identity
			bad.Permissions = []string{"view"}
			*r = *r.WithContext(context.WithValue(r.Context(), identityContextKey{}, bad))
		}, status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &auditHTTPAuthority{securityAgentPublicAuthorityStub: &securityAgentPublicAuthorityStub{}, value: event, err: tc.err}
			if tc.mutate {
				stub.value.OrganizationID = "pid_7b000099-0000-4000-8000-000000000099"
			}
			handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			handler, err = NewSecurityAgentWorkflowSurface(http.NotFoundHandler(), handler)
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "getSecurityAgentAuditEvent", map[string]string{"id": activityAuditID}, "GET", "/api/v1/security-agent-audit-events/"+activityAuditID, "")
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-browser-session"})
			if tc.change != nil {
				tc.change(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || stub.calls != tc.calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d calls=%d headers=%v body=%s", response.Code, stub.calls, response.Header(), response.Body.String())
			}
			if tc.status == 200 {
				var got SecurityAgentAuditEvent
				if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || got != event {
					t.Fatalf("audit response=%s err=%v", response.Body.String(), err)
				}
				digest := sha256.Sum256([]byte("owned-browser-session"))
				if stub.id != activityAuditID || !bytes.Equal(stub.digest, digest[:]) || stub.identity.Scope != identity.Scope {
					t.Fatal("audit request lost cookie/identity binding")
				}
			}
		})
	}
}

func TestSecurityAgentAuditOperationRegistration(t *testing.T) {
	for _, operation := range CoreOperations() {
		if operation.OperationID == "getSecurityAgentAuditEvent" {
			if operation.Method != "GET" || operation.Pattern != "/api/v1/security-agent-audit-events/{id}" || operation.Permission != "view_audit" || !equalStrings(operation.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
				t.Fatalf("audit registration=%#v", operation)
			}
			return
		}
	}
	t.Fatal("exact Security Agent audit operation is not registered")
}
