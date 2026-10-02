package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentApprovalContextHTTP(t *testing.T) {
	for _, list := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			headers []string
			want    bool
			unsafe  bool
		}{
			{"legacy", nil, false, false}, {"supported", []string{"v1"}, true, false}, {"duplicate", []string{"v1", "v1"}, false, false}, {"unsupported", []string{"v2"}, false, false}, {"unsafe legacy", nil, false, true}, {"unsafe opted in", []string{"v1"}, false, true},
		} {
			t.Run(tc.name+map[bool]string{true: " list", false: " detail"}[list], func(t *testing.T) {
				approval, wire := approvalContextFixture("update_finding_response")
				raw, _ := json.Marshal(wire)
				var err error
				approval.Context, err = decodeSecurityAgentApprovalContext(raw, approval)
				if err != nil {
					t.Fatal(err)
				}
				if tc.unsafe {
					approval.Context.Requester.ID = new(string)
					*approval.Context.Requester.ID = "protected-requester-sentinel"
				}
				stub := &securityAgentPublicAuthorityStub{approval: approval, approvals: SecurityAgentApprovalPage{Items: []SecurityAgentApproval{approval}}}
				handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
				if err != nil {
					t.Fatal(err)
				}
				identity := fixtureRequestIdentity(t)
				identity.CredentialKind = CredentialBrowserSession
				operation, path := "getSecurityAgentApproval", "/api/v1/security-agent-approvals/"+approval.ID
				if list {
					operation, path = "listSecurityAgentApprovals", "/api/v1/security-agent-approvals"
				}
				request := workflowRequest(t, identity, "pid_78000004-0000-4000-8000-000000000004", operation, map[string]string{"id": approval.ID}, http.MethodGet, path, "")
				for _, header := range tc.headers {
					request.Header.Add("X-Zasp-Approval-Context", header)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if tc.unsafe {
					if response.Code != 503 || strings.Contains(response.Body.String(), "sentinel") {
						t.Fatal("unsafe authority not refused", response.Code)
					}
					return
				}
				if response.Code != 200 || strings.Contains(response.Body.String(), `"approval_context"`) != tc.want {
					t.Fatal("context negotiation changed compatibility", response.Code, response.Body.String())
				}
				if stub.approval.Context == nil || stub.approvals.Items[0].Context == nil {
					t.Fatal("negotiation mutated repository snapshot")
				}
			})
		}
	}
}
