package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Removing usage capture, using floats, rounding down, or dropping usage on
// candidate rejection must fail these actual planner/controlled transport cases.
func TestSecurityAgentPlannerPreservesExactUsage(t *testing.T) {
	for _, cost := range []struct {
		raw  string
		nano int64
	}{
		{"0", 0}, {"0.000000001", 1}, {"0.0000000001", 1},
		{"1.0000000001", 1000000001}, {"0.95", 950000000},
		{"1e-9", 1}, {"1e-10", 1}, {"1E+3", 1000000000000},
		{"1000.000000001", 1000000000001},
		{"9007199.254740993", 9007199254740993},
		{"9223372036.854775807", 9223372036854775807},
		{"1e-1000", 1}, {"0." + strings.Repeat("0", 125) + "1", 1},
	} {
		for _, rejected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rejected=%v", cost.raw, rejected), func(t *testing.T) {
				usage := `{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":` + cost.raw + `,"cost_details":{"upstream_inference_cost":999}}`
				result := planWithBudgetUsage(t, usage, rejected)
				// Decode the result's public fields without requiring a new field
				// to exist before the regression runs against the original planner.
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				var got struct {
					Usage *struct{ PromptTokens, CompletionTokens, TotalTokens, CostNanoCredits int64 }
				}
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Fatal(err)
				}
				if got.Usage == nil || got.Usage.PromptTokens != 120 || got.Usage.CompletionTokens != 40 || got.Usage.TotalTokens != 160 || got.Usage.CostNanoCredits != cost.nano {
					t.Fatalf("usage=%+v want tokens120/40/160 nano%d", got.Usage, cost.nano)
				}
				wantFailure := securityAgentPlannerFailure("")
				if rejected {
					wantFailure = securityAgentPlannerRejected
				}
				if result.Failure != wantFailure || !strings.HasPrefix(result.OutputDigest, "sha256:") || !rejected && (result.Candidate.Version != 1 || len(result.Candidate.Steps) != 1) {
					t.Fatalf("candidate classification/digest changed: %+v", result)
				}
			})
		}
	}
}

func TestSecurityAgentPlannerUsageUnknownIsNotZero(t *testing.T) {
	valid := `{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":0.1}`
	invalid := []string{`null`, `{}`, `[]`, `{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160}`,
		strings.Replace(valid, `"total_tokens":160`, `"total_tokens":159`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":null`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":-1`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":"120"`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":120.0`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":12e1`, 1),
		strings.Replace(valid, `"completion_tokens":40`, `"completion_tokens":null`, 1),
		strings.Replace(valid, `"total_tokens":160`, `"total_tokens":null`, 1),
		strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":9223372036854775807`, 1),
		strings.Replace(valid, `"cost":0.1`, `"cost":0.1,"cost":0`, 1),
		strings.Replace(valid, `"total_tokens":160`, `"total_tokens":159,"total_tokens":160`, 1),
	}
	for _, cost := range []string{`null`, `"0.1"`, `-0`, `-1`, `true`, `{}`, `[]`, `9223372036.8547758071`, `1e1000`, `1e1001`, `1e-1001`, strings.Repeat("1", 129), "0." + strings.Repeat("0", 126) + "1"} {
		invalid = append(invalid, strings.Replace(valid, `0.1`, cost, 1))
	}
	for index, usage := range invalid {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			result := planWithBudgetUsage(t, usage, false)
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var got struct{ Usage json.RawMessage }
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Usage) != 0 && string(got.Usage) != "null" {
				t.Fatalf("unknown usage gained authority: %s", got.Usage)
			}
		})
	}
}

func TestSecurityAgentPlannerUsageRejectsAmbiguousResponse(t *testing.T) {
	usage := `"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":0.1}`
	model := `"model":"openai/gpt-5-mini"`
	for _, body := range []string{
		`{` + model + `}`, // missing usage is unknown
		`{` + model + `,` + usage + `,` + usage + `}`,
		`{` + model + `,` + model + `,` + usage + `}`,
		`{"model":null,` + usage + `}`,
		`{"model":"different/model",` + usage + `}`,
	} {
		result := planWithBudgetResponse(t, []byte(body))
		if result.Usage != nil {
			t.Fatalf("ambiguous identity/usage gained accounting authority: %+v", result.Usage)
		}
	}
}

func planWithBudgetUsage(t *testing.T, usage string, rejected bool) securityAgentPlannerResult {
	t.Helper()
	content := `{"version":1,"summary":"Review finding","steps":[{"index":0,"action":"update_finding_response","target_id":"pid_71000001-0000-4000-8000-000000000001"}]}`
	if rejected {
		content = `{"version":999}`
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(openRouterPlannerResponse(content), &response); err != nil {
		t.Fatal(err)
	}
	response["usage"] = json.RawMessage(usage)
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return planWithBudgetResponse(t, body)
}

func planWithBudgetResponse(t *testing.T, body []byte) securityAgentPlannerResult {
	t.Helper()
	transport := &securityAgentPlannerTransport{responseBody: body}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	defer planner.Close()
	return planner.Plan(context.Background(), testSecurityAgentPlannerContext())
}
