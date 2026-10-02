package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestSecurityAgentAttackLabPreparedRequestBinding(t *testing.T) {
	for _, mode := range []string{"valid", "missing_digest", "bad_digest", "missing_reference", "mixed_action", "legacy_digest"} {
		t.Run(mode, func(t *testing.T) {
			value := testSecurityAgentPlannerContext()
			value.AllowedActions = []string{"start_attack_lab"}
			value.ExistingTest = &apiserver.SecurityAgentExistingTestReference{DefinitionID: value.AllowedTargets[0], DefinitionVersion: 7}
			encoded, _ := json.Marshal(value)
			var fields map[string]any
			json.Unmarshal(encoded, &fields)
			fields["AttackLabDigest"] = "sha256:" + strings.Repeat("a", 64)
			switch mode {
			case "missing_digest":
				delete(fields, "AttackLabDigest")
			case "bad_digest":
				fields["AttackLabDigest"] = "private-evidence-reference"
			case "missing_reference":
				delete(fields, "ExistingTest")
			case "mixed_action":
				fields["AllowedActions"] = []string{"start_attack_lab", "run_test"}
			case "legacy_digest":
				fields["AllowedActions"] = []string{"run_test"}
			}
			encoded, _ = json.Marshal(fields)
			value = securityAgentPlannerContext{}
			json.Unmarshal(encoded, &value)
			transport := &securityAgentPlannerTransport{}
			planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			defer planner.Close()
			prepared, err := planner.Prepare(context.Background(), value)
			if mode != "valid" {
				if err == nil {
					t.Fatal("malformed trusted context accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid Attack Lab preparation refused: %v", err)
			}
			request := prepared.(*productionSecurityAgentPreparedPlan)
			if !strings.Contains(request.body, "attack_lab_snapshot_digest") || !strings.Contains(request.body, strings.Repeat("a", 64)) || transport.calls != 0 {
				t.Fatalf("prepared request lost bounded digest or sent I/O: %s", request.body)
			}
			fields["AttackLabDigest"] = "sha256:" + strings.Repeat("b", 64)
			encoded, _ = json.Marshal(fields)
			json.Unmarshal(encoded, &value)
			changed, err := planner.Prepare(context.Background(), value)
			if err != nil || changed.(*productionSecurityAgentPreparedPlan).identity.BodyDigest == request.identity.BodyDigest {
				t.Fatal("source snapshot change did not bind request bytes")
			}
		})
	}
}

type attackLabRuntimeAuthority struct {
	existingTestRuntimeAuthority
	snapshot json.RawMessage
}

func (a *attackLabRuntimeAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string) (apiserver.SecurityAgentPlannerContext, error) {
	value, err := a.existingTestRuntimeAuthority.LoadSecurityAgentPlannerContext(ctx, claim, worker, lease)
	value.AllowedActions = []string{"start_attack_lab"}
	value.AttackLab = append(json.RawMessage(nil), a.snapshot...)
	return value, err
}

func TestSecurityAgentAttackLabProcessorPreservesDigestOnly(t *testing.T) {
	now := time.Now().UTC()
	authority := &attackLabRuntimeAuthority{existingTestRuntimeAuthority: existingTestRuntimeAuthority{reference: apiserver.SecurityAgentExistingTestReference{DefinitionID: "pid_89800001-0000-4000-8000-000000000001", DefinitionVersion: 7}}, snapshot: json.RawMessage(`{"source_evidence":{"reference":"private-artifact-reference"},"source_attempt":3}`)}
	planner := successfulSecurityAgentPlanner()
	planner.result.Candidate.Steps = []securityAgentPlannerStep{{Index: 0, Action: "start_attack_lab", TargetID: authority.reference.DefinitionID}}
	nextID := 0
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: authority, Planner: planner, WorkerID: "security-agent-worker-1", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: func() (string, error) {
		nextID++
		return fmt.Sprintf("pid_898001%02d-0000-4000-8000-000000000001", nextID), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.processClaim(context.Background(), securityAgentTestClaim("pid_78000001-0000-4000-8000-000000000001", false, now), "lease-token-000000000001"); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(authority.snapshot)
	if len(planner.contexts) != 1 || planner.contexts[0].AttackLabDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("processor dropped trusted snapshot digest")
	}
	raw, _ := json.Marshal(planner.contexts[0])
	if strings.Contains(string(raw), "private-artifact-reference") {
		t.Fatal("private artifact escaped into model context")
	}
}
