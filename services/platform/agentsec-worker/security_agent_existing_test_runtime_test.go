package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Real planner request/candidate behavior with an in-process HTTP transport.
// No request reaches a model provider or an execution target.
func TestSecurityAgentExistingTestPlannerBinding(t *testing.T) {
	const testID = "pid_89800001-0000-4000-8000-000000000001"
	for _, mode := range []string{"run_test", "rerun_test", "missing", "zero_version", "excess_version", "wrong_ref", "mixed_actions", "legacy_ref", "extra_targets", "extra_steps", "unsupported_evidence", "extra_evidence", "environment_candidate", "evidence_candidate"} {
		t.Run(mode, func(t *testing.T) {
			value := testSecurityAgentPlannerContext()
			action := "run_test"
			if mode == "rerun_test" {
				action = mode
			}
			value.AllowedActions = []string{action}
			value.AllowedTargets = []string{testID}
			encoded, _ := json.Marshal(value)
			var fields map[string]any
			json.Unmarshal(encoded, &fields)
			fields["ExistingTest"] = map[string]any{"definition_id": testID, "definition_version": 7}
			switch mode {
			case "missing":
				delete(fields, "ExistingTest")
			case "zero_version":
				fields["ExistingTest"].(map[string]any)["definition_version"] = 0
			case "excess_version":
				fields["ExistingTest"].(map[string]any)["definition_version"] = 1000001
			case "wrong_ref":
				fields["ExistingTest"].(map[string]any)["definition_id"] = value.Evidence[0].ID
			case "mixed_actions":
				fields["AllowedActions"] = []string{"run_test", "update_finding_response"}
			case "legacy_ref":
				fields["AllowedActions"] = []string{"update_finding_response"}
			case "extra_targets":
				fields["AllowedTargets"] = []string{testID, value.EnvironmentID}
			case "extra_steps":
				fields["MaximumSteps"] = 2
			case "unsupported_evidence":
				evidence := value.Evidence[0]
				evidence.Kind = "session"
				fields["Evidence"] = []securityAgentPlannerEvidence{evidence}
			case "extra_evidence":
				evidence := value.Evidence[0]
				evidence.ID = value.EnvironmentID
				fields["Evidence"] = append(value.Evidence, evidence)
			}
			encoded, _ = json.Marshal(fields)
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatal(err)
			}
			target := testID
			if mode == "environment_candidate" {
				target = value.EnvironmentID
			}
			if mode == "evidence_candidate" {
				target = value.Evidence[0].ID
			}
			transport := &securityAgentPlannerTransport{responseStatus: http.StatusOK, responseBody: openRouterPlannerResponse(fmt.Sprintf(`{"version":1,"summary":"Run configured test","steps":[{"index":0,"action":%q,"target_id":%q}]}`, action, target))}
			planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			defer planner.Close()
			result := planner.Plan(context.Background(), value)
			if mode == "run_test" || mode == "rerun_test" || mode == "environment_candidate" || mode == "evidence_candidate" {
				if transport.calls != 1 {
					t.Fatalf("valid bound context calls=%d result=%+v", transport.calls, result)
				}
				if mode == "environment_candidate" || mode == "evidence_candidate" {
					if result.Failure != securityAgentPlannerRejected {
						t.Fatalf("substituted target accepted: %+v", result)
					}
				} else if result.Failure != "" {
					t.Fatalf("configured test rejected: %+v", result)
				}
				var request struct {
					Messages []struct{ Role, Content string } `json:"messages"`
				}
				if err := json.Unmarshal(transport.requestBody, &request); err != nil || len(request.Messages) != 2 {
					t.Fatalf("request invalid: %s %v", transport.requestBody, err)
				}
				var content struct {
					ExistingTest *apiserver.SecurityAgentExistingTestReference `json:"existing_test"`
					Targets      []string                                      `json:"allowed_targets"`
				}
				if err := json.Unmarshal([]byte(request.Messages[1].Content), &content); err != nil || content.ExistingTest == nil || content.ExistingTest.DefinitionID != testID || content.ExistingTest.DefinitionVersion != 7 || len(content.Targets) != 1 || content.Targets[0] != testID {
					t.Fatalf("planner request lost exact binding: %s %v", request.Messages[1].Content, err)
				}
			} else if result.Failure != securityAgentPlannerUnavailable || transport.calls != 0 {
				t.Fatalf("invalid context made provider request: %+v calls=%d", result, transport.calls)
			}
		})
	}
}

type existingTestRuntimeAuthority struct {
	securityAgentWorkerAuthorityStub
	reference apiserver.SecurityAgentExistingTestReference
}

func (a *existingTestRuntimeAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string) (apiserver.SecurityAgentPlannerContext, error) {
	value, err := a.securityAgentWorkerAuthorityStub.LoadSecurityAgentPlannerContext(ctx, claim, worker, lease)
	value.AllowedActions = []string{"run_test"}
	value.AllowedTargets = []string{a.reference.DefinitionID}
	value.ExistingTest = &a.reference
	return value, err
}

func TestSecurityAgentExistingTestProcessorPreservesReference(t *testing.T) {
	now := time.Now().UTC()
	claim := securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", false, now)
	authority := &existingTestRuntimeAuthority{reference: apiserver.SecurityAgentExistingTestReference{DefinitionID: "pid_89800001-0000-4000-8000-000000000001", DefinitionVersion: 7}}
	planner := successfulSecurityAgentPlanner()
	planner.result.Candidate.Steps = []securityAgentPlannerStep{{Index: 0, Action: "run_test", TargetID: authority.reference.DefinitionID}}
	nextID := 0
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: authority, Planner: planner, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
		nextID++
		return fmt.Sprintf("pid_898001%02d-0000-4000-8000-000000000001", nextID), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.processClaim(context.Background(), claim, "lease-token-000000000001"); err != nil {
		t.Fatal(err)
	}
	if len(planner.contexts) != 1 {
		t.Fatalf("planner calls=%d", len(planner.contexts))
	}
	raw, _ := json.Marshal(planner.contexts[0])
	var passed struct {
		ExistingTest *apiserver.SecurityAgentExistingTestReference
	}
	if err := json.Unmarshal(raw, &passed); err != nil || passed.ExistingTest == nil || *passed.ExistingTest != authority.reference {
		t.Fatalf("processor dropped reference: %s %v", raw, err)
	}
}
