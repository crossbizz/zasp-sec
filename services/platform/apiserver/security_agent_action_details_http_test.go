package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func actionDetailHTTP(t *testing.T, detail SecurityAgentRunDetail, headers []string, contextAndBudget bool) *httptest.ResponseRecorder {
	t.Helper()
	handler, err := NewSecurityAgentPublicHTTPHandler(&securityAgentPublicAuthorityStub{runDetail: detail}, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := workflowRequest(t, identity, "pid_78000004-0000-4000-8000-000000000004", "getSecurityAgentRun", map[string]string{"id": runContextTestRunID}, http.MethodGet, "/api/v1/security-agent-runs/"+runContextTestRunID, "")
	for _, header := range headers {
		request.Header.Add("X-Zasp-Action-Details", header)
	}
	if contextAndBudget {
		request.Header.Set("X-Zasp-Run-Context", "v1")
		request.Header.Set("X-Zasp-Budget-Details", "v1")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSecurityAgentActionDetailsHTTPNegotiation(t *testing.T) {
	for _, headers := range [][]string{nil, {"v1"}, {"v2"}, {"v1", "v1"}, {"v1,v1"}} {
		for _, contextAndBudget := range []bool{false, true} {
			raw, detail := actionProjectionFixture(t, "update_finding_response", "verified", [2]int{}, [2]int{}, nil)
			var err error
			detail.ActionDetails, err = decodeSecurityAgentActionDetails(raw, detail)
			if err != nil {
				t.Fatal(err)
			}
			detail.RunContext = &SecurityAgentRunContext{}
			response := actionDetailHTTP(t, detail, headers, contextAndBudget)
			var body map[string]json.RawMessage
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatalf("valid action detail failed: status=%d", response.Code)
			}
			want := len(headers) == 1 && headers[0] == "v1"
			if (body["action_details"] != nil) != want || (body["run_context"] != nil) != contextAndBudget || (body["budget_stop_reason"] != nil) != contextAndBudget {
				t.Fatal("action detail header changed legacy or independent negotiation")
			}
		}
	}
}

func TestSecurityAgentActionDetailsHTTPRejectsUnsafeAuthority(t *testing.T) {
	for _, mutate := range []func(*SecurityAgentActionDetail){
		func(v *SecurityAgentActionDetail) {
			v.Arguments = &SecurityAgentActionArguments{TargetID: "protected-action-sentinel", ExpectedVersion: 2, TargetStatus: "under_review"}
		},
		func(v *SecurityAgentActionDetail) { v.Verification.Source = "protected-action-sentinel" },
		func(v *SecurityAgentActionDetail) { v.StepID = "pid_78000009-0000-4000-8000-000000000009" },
		func(v *SecurityAgentActionDetail) { v.Rollback.State = "completed" },
		func(v *SecurityAgentActionDetail) { v.Result.OutcomeID = "pid_78000009-0000-4000-8000-000000000000" },
		func(v *SecurityAgentActionDetail) { v.Verification.State = "inconclusive" },
	} {
		for _, headers := range [][]string{nil, {"v1"}} {
			raw, detail := actionProjectionFixture(t, "update_finding_response", "verified", [2]int{}, [2]int{}, nil)
			var err error
			detail.ActionDetails, err = decodeSecurityAgentActionDetails(raw, detail)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&detail.ActionDetails[0])
			response := actionDetailHTTP(t, detail, headers, false)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "protected-action-sentinel") {
				t.Fatal("unsafe authority was hidden by negotiation or exposed publicly")
			}
		}
	}
}
