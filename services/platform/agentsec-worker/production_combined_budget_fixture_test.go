package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"strings"
	"testing"
)

func TestCombinedBudgetFixtureAccountsEveryAutomaticAction(t *testing.T) {
	for _, action := range []string{"update_finding_response", "create_temporary_policy", "revoke_integration_connection", "isolate_session", "run_test", "rerun_test", "start_attack_lab"} {
		t.Run(action, func(t *testing.T) {
			planner, calls, closePlanner, err := newCombinedE2EOpenRouterPlanner(false)
			if err != nil {
				t.Fatal(err)
			}
			defer closePlanner()
			value := testSecurityAgentPlannerContext()
			value.AllowedActions = []string{action}
			target := value.Evidence[0].ID
			if action == "create_temporary_policy" {
				target = value.EnvironmentID
			}
			if action == "revoke_integration_connection" {
				target = "pid_71000002-0000-4000-8000-000000000002"
			}
			if action == "run_test" || action == "rerun_test" || action == "start_attack_lab" {
				value.ExistingTest = &apiserver.SecurityAgentExistingTestReference{DefinitionID: "pid_7f300002-0000-4000-8000-000000000002", DefinitionVersion: 1}
				target = value.ExistingTest.DefinitionID
			}
			value.AllowedTargets = []string{target}
			if action == "start_attack_lab" {
				value.AttackLabDigest = "sha256:" + strings.Repeat("a", 64)
			}
			prepared, err := (&budgetFixturePlanner{planner}).Prepare(context.Background(), value)
			if err != nil {
				t.Fatal(err)
			}
			result := prepared.Dispatch(context.Background())
			if result.Failure != "" || result.Candidate.Steps[0].TargetID != target || calls() != 1 {
				t.Fatalf("result=%+v calls=%d", result, calls())
			}
			if result.Usage == nil || result.Usage.PromptTokens != 120 || result.Usage.CompletionTokens != 40 || result.Usage.TotalTokens != 160 || result.Usage.CostNanoCredits != 100 {
				t.Fatalf("missing exact controlled usage: %+v", result.Usage)
			}
			policy := prepared.PlannerBudget()
			if policy.MaximumTokens != 1000 || policy.MaximumCostNanoCredits != 200 || policy.CostPolicyVersion != "controlled-transport-v1" || policy.CostUnit != "openrouter_credit" {
				t.Fatalf("unbounded fixture policy: %+v", policy)
			}
			livePrepared, err := planner.Prepare(context.Background(), value)
			if err != nil {
				t.Fatal(err)
			}
			if live := livePrepared.PlannerBudget(); live.MaximumTokens != 0 || live.MaximumCostNanoCredits != 0 || live.CostPolicyVersion != "" {
				t.Fatalf("fixture leaked live pricing: %+v", live)
			}
		})
	}
}

func TestCombinedBudgetFixture503DoesNotInventUsage(t *testing.T) {
	planner, calls, closePlanner, err := newCombinedE2EOpenRouterPlanner(true)
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	result := planner.Plan(context.Background(), testSecurityAgentPlannerContext())
	if result.Failure != securityAgentPlannerUnavailable || result.Usage != nil || calls() != 1 {
		t.Fatalf("result=%+v calls=%d", result, calls())
	}
}
