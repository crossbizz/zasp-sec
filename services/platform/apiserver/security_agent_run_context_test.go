package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const runContextTestRunID = "pid_78000006-0000-4000-8000-000000000006"
const runContextTestTrigger = `{"kind":"finding","id":"pid_78000005-0000-4000-8000-000000000005","version":1}`

func runContextDetailFixture(t *testing.T, contextJSON string) SecurityAgentRunDetail {
	t.Helper()
	payload := `{"run":{"id":"` + runContextTestRunID + `","agent_id":"pid_78000001-0000-4000-8000-000000000001","state":"remediated","evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"definition_version":1,"version":4},"evidence_ids":["pid_78000005-0000-4000-8000-000000000005"],"plan":{"plan_hash":"sha256:` + strings.Repeat("a", 64) + `","catalog_version":"security-agent-actions-v1","expires_at":"2026-09-16T12:00:00Z","steps":[{"id":"pid_78000007-0000-4000-8000-000000000007","index":0,"action":"update_finding_response","authorization":"autonomous","state":"succeeded","version":1}]},"authorization":"authorized","approvals":[],"execution":[{"step_id":"pid_78000007-0000-4000-8000-000000000007","action":"update_finding_response","state":"succeeded","version":1}],"verification":"verified","budget_stop_reason":"budget_usage_unknown"`
	if contextJSON != "" {
		payload += `,"run_context":` + contextJSON
	}
	var value SecurityAgentRunDetail
	if err := json.Unmarshal([]byte(payload+"}"), &value); err != nil {
		t.Fatal("invalid test fixture")
	}
	return value
}

func runContextHTTP(t *testing.T, detail SecurityAgentRunDetail, headers []string, budget bool) *httptest.ResponseRecorder {
	t.Helper()
	stub := &securityAgentPublicAuthorityStub{runDetail: detail}
	handler, err := NewSecurityAgentPublicHTTPHandler(stub, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	request := workflowRequest(t, identity, "pid_78000004-0000-4000-8000-000000000004", "getSecurityAgentRun", map[string]string{"id": runContextTestRunID}, http.MethodGet, "/api/v1/security-agent-runs/"+runContextTestRunID, "")
	for _, header := range headers {
		request.Header.Add("X-Zasp-Run-Context", header)
	}
	if budget {
		request.Header.Set("X-Zasp-Budget-Details", "v1")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// The real handler must preserve old strict-client shapes and must not let a
// request for rationale silently opt into unrelated optional budget fields.
func TestSecurityAgentRunContextNegotiation(t *testing.T) {
	contextJSON := `{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"available","summary":"Review exposed credential."}}`
	for _, test := range []struct {
		name                string
		headers             []string
		budget, wantContext bool
	}{
		{"legacy", nil, false, false},
		{"supported", []string{"v1"}, false, true},
		{"unsupported", []string{"v2"}, false, false},
		{"duplicate", []string{"v1", "v1"}, false, false},
		{"combined", []string{"v1, v2"}, false, false},
		{"both", []string{"v1"}, true, true},
		{"budget only", nil, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := runContextHTTP(t, runContextDetailFixture(t, contextJSON), test.headers, test.budget)
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected response status=%d", response.Code)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			_, hasContext := fields["run_context"]
			_, hasBudget := fields["budget_stop_reason"]
			wantCount := 7
			if test.wantContext {
				wantCount++
			}
			if test.budget {
				wantCount++
			}
			if hasContext != test.wantContext || hasBudget != test.budget || len(fields) != wantCount {
				t.Fatal("optional projection negotiation changed the response contract")
			}
			if test.wantContext && string(fields["run_context"]) != contextJSON {
				t.Fatal("context projection changed")
			}
			if string(fields["authorization"]) != `"authorized"` {
				t.Fatal("explanation changed authorization")
			}
		})
	}
}

func TestSecurityAgentRunContextRejectsUnsafeAuthority(t *testing.T) {
	for _, test := range []struct{ name, value string }{
		{"manual ProductID without provenance", `{"trigger":` + strings.Replace(runContextTestTrigger, "finding", "manual", 1) + `,"rationale":null}`},
		{"raw credential", `{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"available","summary":"password=seeded"}}`},
		{"withheld leak", `{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"withheld","summary":"seeded"}}`},
		{"empty available", `{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"available","summary":""}}`},
		{"unknown state", `{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"approved","summary":"Review evidence"}}`},
		{"missing trigger", `{"trigger":null,"rationale":{"state":"available","summary":"Review evidence"}}`},
		{"unknown kind", `{"trigger":{"kind":"session","id":"pid_78000005-0000-4000-8000-000000000005","version":1},"rationale":null}`},
		{"bad id", `{"trigger":{"kind":"finding","id":"seeded","version":1},"rationale":null}`},
		{"zero version", `{"trigger":{"kind":"finding","id":"pid_78000005-0000-4000-8000-000000000005","version":0},"rationale":null}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := runContextHTTP(t, runContextDetailFixture(t, test.value), []string{"v1"}, false)
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "seeded") {
				t.Fatalf("invalid repository context was exposed: status=%d", response.Code)
			}
		})
	}
}

func TestSecurityAgentRunContextPreservesMissingAndWithheld(t *testing.T) {
	for _, contextJSON := range []string{
		"", `{"trigger":null,"rationale":null}`,
		`{"trigger":` + runContextTestTrigger + `,"rationale":null}`,
		`{"trigger":` + runContextTestTrigger + `,"rationale":{"state":"withheld","summary":""}}`,
		`{"trigger":` + strings.Replace(runContextTestTrigger, "finding", "attack_path", 1) + `,"rationale":null}`,
		`{"trigger":` + strings.Replace(runContextTestTrigger, "finding", "runtime_decision", 1) + `,"rationale":null}`,
	} {
		response := runContextHTTP(t, runContextDetailFixture(t, contextJSON), []string{"v1"}, false)
		if response.Code != http.StatusOK {
			t.Fatalf("missing/withheld context rejected: status=%d", response.Code)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		if string(fields["run_context"]) != contextJSON {
			t.Fatal("missing and withheld context were conflated")
		}
	}
}

func TestSecurityAgentRunContextRejectsRationaleWithoutPlan(t *testing.T) {
	value := runContextDetailFixture(t, `{"trigger":`+runContextTestTrigger+`,"rationale":{"state":"available","summary":"Review evidence."}}`)
	value.Plan = nil
	value.Authorization = "not_planned"
	value.Execution = []SecurityAgentExecutionStep{}
	response := runContextHTTP(t, value, []string{"v1"}, false)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("rationale was exposed without its matching displayed plan")
	}
}
