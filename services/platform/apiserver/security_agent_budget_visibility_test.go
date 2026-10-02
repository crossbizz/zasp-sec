package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecurityAgentRunDetailNegotiatesBudgetDetails(t *testing.T) {
	const runID = "pid_78000006-0000-4000-8000-000000000006"
	for _, tc := range []struct {
		name       string
		headers    []string
		wantReason bool
	}{
		{"legacy", nil, false},
		{"supported", []string{"v1"}, true},
		{"unsupported", []string{"v2"}, false},
		{"duplicate", []string{"v1", "v1"}, false},
		{"combined", []string{"v1, v2"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &securityAgentPublicAuthorityStub{runDetail: SecurityAgentRunDetail{
				Run:         SecurityAgentRun{ID: runID, AgentID: "pid_78000001-0000-4000-8000-000000000001", State: "needs_human", EvidenceIDs: []string{"pid_78000005-0000-4000-8000-000000000005"}, DefinitionVersion: 1, Version: 4},
				EvidenceIDs: []string{"pid_78000005-0000-4000-8000-000000000005"}, Authorization: "not_planned", Approvals: []SecurityAgentApproval{}, Execution: []SecurityAgentExecutionStep{}, Verification: "inconclusive", BudgetStopReason: "budget_usage_unknown",
			}}
			handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
			if err != nil {
				t.Fatal(err)
			}
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			request := workflowRequest(t, identity, "pid_78000004-0000-4000-8000-000000000004", "getSecurityAgentRun", map[string]string{"id": runID}, http.MethodGet, "/api/v1/security-agent-runs/"+runID, "")
			for _, value := range tc.headers {
				request.Header.Add("X-Zasp-Budget-Details", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			wantCount := 7
			if tc.wantReason {
				wantCount = 8
			}
			if len(fields) != wantCount {
				t.Fatalf("unexpected response fields: %s", response.Body.String())
			}
			for _, key := range []string{"run", "evidence_ids", "plan", "authorization", "approvals", "execution", "verification"} {
				if _, ok := fields[key]; !ok {
					t.Fatalf("missing legacy field %s", key)
				}
			}
			reason, present := fields["budget_stop_reason"]
			if present != tc.wantReason || (present && string(reason) != `"budget_usage_unknown"`) {
				t.Fatalf("unexpected reason %s", reason)
			}
		})
	}
}

func TestSecurityAgentRunDetailPreservesOnlyKnownBudgetReasons(t *testing.T) {
	const runID = "pid_78000006-0000-4000-8000-000000000006"
	for _, tc := range []struct {
		reason string
		valid  bool
	}{
		{"", true}, {`"budget_deadline_exceeded"`, true}, {`"budget_steps_exceeded"`, true},
		{`"budget_tokens_exceeded"`, true}, {`"budget_cost_exceeded"`, true}, {`"budget_usage_unknown"`, true},
		{`null`, false}, {`""`, false}, {`"provider secret detail"`, false}, {`1`, false}, {`{}`, false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			payload := `{"run":{"id":"` + runID + `","agent_id":"pid_78000001-0000-4000-8000-000000000001","state":"needs_human","evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"definition_version":1,"version":4},"evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"plan":null,"authorization":"not_planned","approvals":[],"execution":[],"verification":"inconclusive"`
			if tc.reason != "" {
				payload += `,"budget_stop_reason":` + tc.reason
			}
			payload += `}`
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentRunDetailSQL: json.RawMessage(payload)}}
			repository := &PostgresRepository{database: database, securityAgentExecution: true}
			identity := fixtureRequestIdentity(t)
			identity.CredentialKind = CredentialBrowserSession
			value, err := repository.GetSecurityAgentRun(context.Background(), identity, runID)
			if !tc.valid {
				if err == nil {
					t.Fatal("accepted unknown or malformed stop reason")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["budget_stop_reason"]) != tc.reason {
				t.Fatalf("public reason=%s want=%s", fields["budget_stop_reason"], tc.reason)
			}
		})
	}
}
