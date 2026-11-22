package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ticketReadAuthority struct{ redTeamAuthorityStub }

func (*ticketReadAuthority) GetRedTeamSchedule(_ context.Context, _ RequestIdentity, id string) (RedTeamSchedule, error) {
	return RedTeamSchedule{DefinitionID: id}, nil
}
func (*ticketReadAuthority) PutRedTeamSchedule(context.Context, RequestIdentity, RedTeamScheduleUpdate) (RedTeamSchedule, error) {
	return RedTeamSchedule{}, ErrRepositoryOperation
}
func TestScheduledTicketReadScopeComesFromAuthenticatedIdentity(t *testing.T) {
	h, err := NewRedTeamPublicHTTPHandler(&ticketReadAuthority{}, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	const id = "pid_a5000001-0000-4000-8000-000000000018"
	for _, op := range []struct{ name, path string }{{"getTest", "/api/v1/tests/" + id}, {"getTestSchedule", "/api/v1/tests/" + id + "/schedule"}, {"getTestRun", "/api/v1/test-runs/" + id}} {
		req := workflowRequest(t, identity, testCorrelationID, op.name, map[string]string{"id": id}, "GET", op.path, "")
		req.Header.Set("X-Zasp-Expected-Scope", "spoofed")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != http.StatusOK || out.Header().Get("X-Zasp-Verified-Scope") != expectedScopeValue(identity.Scope) {
			t.Fatalf("%s: %d %v", op.name, out.Code, out.Header())
		}
		req.URL.RawQuery = "unrecognized=1"
		denied := httptest.NewRecorder()
		h.ServeHTTP(denied, req)
		if denied.Code == http.StatusOK || denied.Header().Get("X-Zasp-Verified-Scope") != "" {
			t.Fatalf("%s invalid read advertised scope", op.name)
		}
	}
}
