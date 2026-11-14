package zasp_test

// Smoke test of the generated client against a local fake of the API.
//
// It checks what a generated client can get wrong without a compile error:
// the paths, the bearer header, the cursor of auto-pagination, the request
// body, the parsing of contract-shaped responses, and the mapping of an error
// status to a typed error. The fake serves ../fixtures/responses.json.
//
// This file is not generated. It is listed in .fernignore.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"

	zasp "github.com/zasp-ai/zasp-sec/sdks/go"
	"github.com/zasp-ai/zasp-sec/sdks/go/client"
	"github.com/zasp-ai/zasp-sec/sdks/go/option"
)

type recordedRequest struct {
	Method        string
	Path          string
	Query         map[string]string
	Authorization string
	Body          map[string]any
}

type fake struct {
	fixtures map[string]json.RawMessage
	token    string
	cursor   string
	mu       sync.Mutex
	requests []recordedRequest
}

func newFake(t *testing.T) (*fake, *httptest.Server) {
	t.Helper()
	data, err := os.ReadFile("../fixtures/responses.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	f := &fake{}
	if err := json.Unmarshal(data, &f.fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if err := json.Unmarshal(f.fixtures["token"], &f.token); err != nil {
		t.Fatalf("fixture token: %v", err)
	}
	if err := json.Unmarshal(f.fixtures["next_cursor"], &f.cursor); err != nil {
		t.Fatalf("fixture cursor: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	record := recordedRequest{Method: r.Method, Path: r.URL.Path, Query: map[string]string{}, Authorization: r.Header.Get("Authorization")}
	for key, values := range r.URL.Query() {
		record.Query[key] = values[0]
	}
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &record.Body)
	}
	f.mu.Lock()
	f.requests = append(f.requests, record)
	f.mu.Unlock()

	send := func(status int, fixture string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(f.fixtures[fixture])
	}
	switch {
	case record.Authorization != "Bearer "+f.token:
		send(http.StatusUnauthorized, "error_unauthenticated")
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents":
		if record.Query["cursor"] == f.cursor {
			send(http.StatusOK, "agents_page_2")
		} else {
			send(http.StatusOK, "agents_page_1")
		}
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/findings":
		send(http.StatusOK, "findings_page")
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/guardrails/decisions":
		send(http.StatusOK, "guardrail_decision")
	default:
		send(http.StatusNotFound, "error_not_found")
	}
}

func TestListsAgentsAcrossPages(t *testing.T) {
	f, server := newFake(t)
	c := client.NewClient(option.WithBaseURL(server.URL), option.WithToken(f.token))
	limit := 1
	page, err := c.Agents.List(context.Background(), &zasp.ListAgentsRequest{Limit: &limit})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	var names []string
	iterator := page.Iterator()
	for iterator.Next(context.Background()) {
		names = append(names, iterator.Current().GetName())
	}
	if err := iterator.Err(); err != nil {
		t.Fatalf("iterate agents: %v", err)
	}
	if want := []string{"support-copilot", "claims-triage-handler"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("agent names = %v, want %v", names, want)
	}
	if len(f.requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(f.requests))
	}
	if first := f.requests[0]; first.Path != "/api/v1/agents" || first.Authorization != "Bearer "+f.token || first.Query["limit"] != "1" || first.Query["cursor"] != "" {
		t.Fatalf("first request = %+v", first)
	}
	if second := f.requests[1]; second.Query["cursor"] != f.cursor {
		t.Fatalf("second request cursor = %q, want %q", second.Query["cursor"], f.cursor)
	}
}

func TestListsFindings(t *testing.T) {
	f, server := newFake(t)
	c := client.NewClient(option.WithBaseURL(server.URL), option.WithToken(f.token))
	page, err := c.Findings.List(context.Background(), &zasp.ListFindingsRequest{})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(page.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(page.Results))
	}
	if finding := page.Results[0]; finding.GetSeverity() != zasp.FindingSeverityCritical || finding.GetRule() == nil || *finding.GetRule() != "agent_guardrail_missing" {
		t.Fatalf("finding = %+v", finding)
	}
	if f.requests[0].Path != "/api/v1/findings" {
		t.Fatalf("path = %q", f.requests[0].Path)
	}
}

func TestCreatesAGuardrailDecision(t *testing.T) {
	f, server := newFake(t)
	c := client.NewClient(option.WithBaseURL(server.URL), option.WithToken(f.token))
	agentID := "support-agent"
	decision, err := c.Guardrails.CreateDecision(context.Background(), &zasp.GuardrailInteraction{
		Direction: zasp.GuardrailInteractionDirectionInput,
		Text:      "Send the invoice to someone@example.com.",
		AgentID:   &agentID,
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}
	if decision.GetDecision() != zasp.GuardrailDecisionDecisionRedact {
		t.Fatalf("decision = %q", decision.GetDecision())
	}
	if text := decision.GetRedactedText(); text == nil || *text != "Send the invoice to [REDACTED:pii.email]." {
		t.Fatalf("redacted text = %v", text)
	}
	if rules := decision.GetMatchedRules(); len(rules) != 1 || rules[0].GetID() != zasp.GuardrailRuleIDPiiEmail {
		t.Fatalf("matched rules = %+v", rules)
	}
	var want map[string]any
	if err := json.Unmarshal(f.fixtures["guardrail_request"], &want); err != nil {
		t.Fatalf("fixture request: %v", err)
	}
	if request := f.requests[0]; request.Method != http.MethodPost || request.Path != "/api/v1/guardrails/decisions" || !reflect.DeepEqual(request.Body, want) {
		t.Fatalf("request = %+v, want body %v", request, want)
	}
}

func TestReturnsTheTypedErrorOfARefusedRequest(t *testing.T) {
	_, server := newFake(t)
	c := client.NewClient(option.WithBaseURL(server.URL), option.WithToken("wrong"), option.WithoutRetries())
	_, err := c.Findings.List(context.Background(), &zasp.ListFindingsRequest{})
	var unauthorized *zasp.UnauthorizedError
	if !errors.As(err, &unauthorized) {
		t.Fatalf("error = %v, want *zasp.UnauthorizedError", err)
	}
	if unauthorized.StatusCode != http.StatusUnauthorized || unauthorized.Body == nil || unauthorized.Body.GetCode() != "unauthenticated" {
		t.Fatalf("unauthorized = %+v", unauthorized)
	}
}
