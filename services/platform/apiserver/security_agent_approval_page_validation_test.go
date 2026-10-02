package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A permissive list response must not bypass the same authority validation as
// approval detail, nor ignore the user's requested state/run filter or bound.
func TestSecurityAgentApprovalPageAuthorityValidation(t *testing.T) {
	const id = "pid_78000001-0000-4000-8000-000000000001"
	const run = "pid_78000002-0000-4000-8000-000000000002"
	valid := SecurityAgentApproval{ID: id, RunID: run, StepID: "pid_78000003-0000-4000-8000-000000000003", State: "pending", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Version: 1, ExpectedEffect: "Move finding to under review", Reversible: true, EvidenceSummary: []string{"pid_78000004-0000-4000-8000-000000000004"}}
	for _, tc := range []struct {
		name   string
		change func(*SecurityAgentApprovalPage)
		want   int
	}{
		{"valid", func(*SecurityAgentApprovalPage) {}, http.StatusOK},
		{"valid_cursor", func(p *SecurityAgentApprovalPage) { p.NextCreatedAt = &valid.ExpiresAt; p.NextID = id }, http.StatusOK},
		{"over_limit", func(p *SecurityAgentApprovalPage) {
			second, third := valid, valid
			second.ID = run
			third.ID = valid.StepID
			p.Items = append(p.Items, second, third)
		}, http.StatusServiceUnavailable},
		{"protected_effect", func(p *SecurityAgentApprovalPage) { p.Items[0].ExpectedEffect = "protected-approval-sentinel" }, http.StatusServiceUnavailable},
		{"duplicate_ids", func(p *SecurityAgentApprovalPage) { p.Items = append(p.Items, valid) }, http.StatusServiceUnavailable},
		{"wrong_state", func(p *SecurityAgentApprovalPage) { p.Items[0].State = "approved" }, http.StatusServiceUnavailable},
		{"wrong_run", func(p *SecurityAgentApprovalPage) { p.Items[0].RunID = id }, http.StatusServiceUnavailable},
		{"incomplete_cursor", func(p *SecurityAgentApprovalPage) { p.NextID = id }, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := SecurityAgentApprovalPage{Items: []SecurityAgentApproval{valid}}
			tc.change(&page)
			stub := &securityAgentPublicAuthorityStub{approvals: page}
			handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			request := workflowRequest(t, identity, testCorrelationID, "listSecurityAgentApprovals", nil, http.MethodGet, "/api/v1/security-agent-approvals?limit=2&state=pending&run_id="+run, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want || strings.Contains(response.Body.String(), "protected-approval-sentinel") {
				t.Fatalf("authority response status=%d want=%d; protected=%t", response.Code, tc.want, strings.Contains(response.Body.String(), "protected-approval-sentinel"))
			}
		})
	}
}
