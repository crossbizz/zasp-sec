package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFindingResponseApprovalHTTPContext(t *testing.T) {
	for _, list := range []bool{false, true} {
		for _, header := range []string{"", "v1", "v2"} {
			for _, unbound := range []bool{false, true} {
				approval, wire := approvalContextFixture("update_finding_response")
				approval.ExpectedEffect = findingResponseApprovalEffect
				args := wire["arguments"].(map[string]any)
				args["assignee_id"], args["response_status"], args["note"] = approval.ID, "investigating", "Investigate the credential exposure"
				raw, _ := json.Marshal(wire)
				var err error
				approval.Context, err = decodeSecurityAgentApprovalContext(raw, approval)
				if err != nil {
					t.Fatal(err)
				}
				if unbound {
					approval.Context.FindingResponse.TargetID = approval.ID
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
				req := workflowRequest(t, identity, testCorrelationID, operation, map[string]string{"id": approval.ID}, http.MethodGet, path, "")
				if header != "" {
					req.Header.Set("X-Zasp-Approval-Context", header)
				}
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				if unbound {
					if res.Code != 503 {
						t.Fatal("unbound context disclosed", res.Code)
					}
					continue
				}
				if res.Code != 200 {
					t.Fatal("complete finding context rejected", res.Code)
				}
				var got SecurityAgentApproval
				if list {
					var page struct {
						Items []SecurityAgentApproval `json:"items"`
					}
					if json.Unmarshal(res.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
						t.Fatal("approval page")
					}
					got = page.Items[0]
				} else {
					if json.Unmarshal(res.Body.Bytes(), &got) != nil {
						t.Fatal("approval detail")
					}
				}
				if !requiredFindingApprovalContext(got) || got.Context.FindingResponse.Note != "Investigate the credential exposure" {
					t.Fatal("required finding context stripped", list, header)
				}
			}
		}
	}
}
