package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in only. This spends provider credits on one synthetic request;
// it does not change the production model pin or prove deployed authorization,
// durable budget settlement, or production-model quality. Recheck public model
// pricing/availability before opting in. There is no retry or model fallback.
func TestSecurityAgentPlannerLiveBoundedProvider(t *testing.T) {
	if os.Getenv("ZASP_RUN_LIVE_PLANNER_TEST") != "1" {
		t.Skip("paid provider test requires explicit opt-in")
	}
	const model = "mistralai/mistral-nemo"
	const maximumTokens = 512
	credential := []byte(os.Getenv("OPENROUTER_API_KEY"))
	defer clear(credential)
	if !validSecurityAgentPlannerCredential(credential) {
		t.Fatal("live provider credential unavailable")
	}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
		Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: model,
		Token: credential, Timeout: 30 * time.Second, MaximumTokens: maximumTokens,
		PolicyVersion: "security-agent-planner-v1",
	})
	if err != nil {
		t.Fatal("live planner configuration rejected")
	}
	t.Cleanup(func() { _ = planner.Close() })
	observed := &livePlannerTransport{base: planner.client.Transport}
	planner.client.Transport = observed
	input := testSecurityAgentPlannerContext()
	input.MaximumSteps = 1
	input.OperatorGoal = "Return one update_finding_response step for the sole listed finding. Keep the summary short."
	input.Evidence[0].Summary = "Synthetic integration test finding; no customer data or secrets."
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prepared, err := planner.prepareWithProviderConstraints(ctx, input, livePlannerProviderConstraints())
	if err != nil {
		t.Fatal("synthetic provider request preparation rejected")
	}
	result := prepared.Dispatch(ctx)
	// Log only bounded status/accounting. Never log tokens, headers, request
	// bodies, raw provider output, or environment values, including on failure.
	t.Logf("live provider model=%s requests=%d http_status=%d failure=%s", model, observed.requests, observed.status, result.Failure)
	if result.Usage != nil {
		t.Logf("reported usage prompt=%d completion=%d total=%d cost_nano_credits=%d", result.Usage.PromptTokens, result.Usage.CompletionTokens, result.Usage.TotalTokens, result.Usage.CostNanoCredits)
	}
	if observed.requests != 1 || observed.status != http.StatusOK || result.Failure != "" {
		t.Fatal("real provider did not produce one accepted application response")
	}
	if result.Model != model || result.PolicyVersion != "security-agent-planner-v1" || !strings.HasPrefix(result.OutputDigest, "sha256:") {
		t.Fatal("provider result identity/evidence rejected")
	}
	if result.Candidate.Version != 1 || len(result.Candidate.Steps) != 1 || result.Candidate.Steps[0].Action != "update_finding_response" || result.Candidate.Steps[0].TargetID != input.AllowedTargets[0] {
		t.Fatal("provider candidate exceeded the synthetic action/target scope")
	}
	if result.Usage == nil || result.Usage.PromptTokens <= 0 || result.Usage.CompletionTokens <= 0 || result.Usage.CompletionTokens > maximumTokens || result.Usage.CostNanoCredits < 0 || result.Usage.CostNanoCredits > 1_000_000 {
		t.Fatal("provider usage unavailable or exceeded the test accounting limit")
	}
}

// Fixed test-only route/rates, selected before request serialization and hashing.
// These unit-price ceilings are not a total-spend permit or funding authority.
func livePlannerProviderConstraints() *securityAgentProviderConstraints {
	return &securityAgentProviderConstraints{Endpoint: "dekallm/fp8", PromptMicroUSDPerMillion: 18000, CompletionMicroUSDPerMillion: 30000}
}

// This observes the actual production TLS transport; it does not fake a
// provider response or replace the production redirect/privacy behavior.
type livePlannerTransport struct {
	base     http.RoundTripper
	requests int
	status   int
}

func (transport *livePlannerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests++
	response, err := transport.base.RoundTrip(request)
	if response != nil {
		transport.status = response.StatusCode
	}
	return response, err
}
