package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// These wire cases catch permissive encoding/json decoding before any action
// is admitted. Expected rejection is independent of the candidate decoder.
func TestSecurityAgentPlannerRejectsAmbiguousCandidateFields(t *testing.T) {
	const valid = `{"version":1,"summary":"Review evidence","steps":[{"index":0,"action":"update_finding_response","target_id":"pid_71000001-0000-4000-8000-000000000001"}]}`
	for _, tc := range []struct {
		name string
		body string
	}{
		{"duplicate version", strings.Replace(valid, `"version":1`, `"version":2,"version":1`, 1)},
		{"duplicate summary", strings.Replace(valid, `"summary":`, `"summary":"Discarded instruction","summary":`, 1)},
		{"duplicate steps", strings.Replace(valid, `"steps":`, `"steps":[],"steps":`, 1)},
		{"duplicate action", strings.Replace(valid, `"action":`, `"action":"call_url","action":`, 1)},
		{"duplicate target", strings.Replace(valid, `"target_id":`, `"target_id":"foreign","target_id":`, 1)},
		{"duplicate index", strings.Replace(valid, `"index":0`, `"index":99,"index":0`, 1)},
		{"missing index", strings.Replace(valid, `"index":0,`, ``, 1)},
		{"null index", strings.Replace(valid, `"index":0`, `"index":null`, 1)},
		{"case alias outer", strings.Replace(valid, `"version"`, `"Version"`, 1)},
		{"case alias step", strings.Replace(valid, `"action"`, `"Action"`, 1)},
		{"unknown outer", strings.Replace(valid, `"version":1`, `"version":1,"ignored":true`, 1)},
		{"unknown step", strings.Replace(valid, `"index":0`, `"index":0,"ignored":true`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &securityAgentPlannerTransport{responseStatus: http.StatusOK, responseBody: openRouterPlannerResponse(tc.body)}
			planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = planner.Close() })
			result := planner.Plan(context.Background(), testSecurityAgentPlannerContext())
			if result.Failure != securityAgentPlannerRejected || result.Candidate.Version != 0 || len(result.Candidate.Steps) != 0 || !providerAckPattern.MatchString(result.OutputDigest) || transport.calls != 1 {
				t.Fatalf("ambiguous candidate admitted or rejection lost receipt: result=%+v calls=%d", result, transport.calls)
			}
		})
	}
}
