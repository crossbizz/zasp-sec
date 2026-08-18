package redteam

import (
	"context"
	"testing"
	"time"
)

func TestPromptfooDomainSelectionSafetyAndEvidence(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	attempt, err := NormalizePromptfoo(PromptfooOutput{Objective: "Prevent unsafe tool use", InputArtifactRef: "artifact://input/1", Behavior: "tool call blocked", Passed: true, Evidence: []string{"evidence-1"}, At: now})
	if err != nil || attempt.Verdict != VerdictPass || attempt.EngineError != "" || attempt.InputArtifactRef == "" {
		t.Fatalf("attempt=%+v err=%v", attempt, err)
	}
	failed, err := NormalizePromptfoo(PromptfooOutput{Objective: "Prevent unsafe tool use", InputArtifactRef: "artifact://input/2", Behavior: "engine unavailable", EngineError: "bounded engine error", At: now})
	if err != nil || failed.Verdict != VerdictEngineError {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	recommendations := SelectCuratedPacks(CapabilityProfile{CanCallTools: true, ReadsSensitiveData: true})
	if len(recommendations) != 2 || recommendations[0].Explanation == "" {
		t.Fatalf("recommendations=%+v", recommendations)
	}
	if _, err := TestSafetyPreflight(SafetyInput{Environment: "production", CredentialClass: "production_write", ExpectedSideEffects: []string{"test request"}}); err == nil {
		t.Fatal("unsafe test passed preflight")
	}
	decision, err := AttackLabPreflight(AttackLabInput{Environment: "test", CredentialClass: "test_write", Destination: "canary.internal", AllowedDestinations: []string{"canary.internal"}, SuccessCriterion: "canary touched"})
	if err != nil || !decision.Approved {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	evidence, err := CollectAttackLabEvidence(EvidenceInput{Semantic: "criterion matched", Gateway: "allowed", Egress: "canary.internal", Kubernetes: "job complete", CloudSideEffect: "canary touched"})
	if err != nil || len(evidence.Sources) != 5 || evidence.UsesEBPF {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestStoreWorkerArtifactsAndSandboxContracts(t *testing.T) {
	store := NewMemoryStore()
	definition := TestDefinition{ID: "test-1", Name: "Tool safety", TargetID: "agent-1", Categories: []string{"tool_abuse"}, Safety: SafetyMetadata{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"test request"}}}
	if err := store.CreateDefinition(context.Background(), definition); err != nil {
		t.Fatal(err)
	}
	run, err := store.CreateRun(context.Background(), "run-1", definition.ID)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(store, NewMemoryArtifactStore())
	for range 2 {
		if err := worker.Consume(context.Background(), run.ID, PromptfooOutput{Objective: "Tool safety", InputArtifactRef: "artifact://input/1", Behavior: "blocked", Passed: true, Evidence: []string{"evidence-1"}, At: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := store.AttemptCount(run.ID); got != 1 {
		t.Fatalf("attempt count=%d", got)
	}
	redacted, err := NormalizePromptfoo(PromptfooOutput{Objective: "Tool safety", InputArtifactRef: "artifact://input/2", Behavior: "secret=must-not-persist", Passed: false, Evidence: []string{"evidence-2"}, At: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)})
	if err != nil || redacted.Behavior != "[REDACTED]" {
		t.Fatalf("redacted=%+v err=%v", redacted, err)
	}
	spec, err := BuildFargateSpec("run-1", SandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300})
	if err != nil || spec.ServiceAccount == "product-worker" || spec.SecurityGroupPolicy == "" || spec.Profile != "fargate-attack-lab" || spec.Isolation != "fargate_pod" || spec.AllowsDirectEgress {
		t.Fatalf("spec=%+v err=%v", spec, err)
	}
}

func TestEgressTokenAndCanaryAreBounded(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	token, err := SignEgressToken([]byte("0123456789abcdef0123456789abcdef"), "run-1", []string{"canary.internal"}, []string{"POST"}, now.Add(time.Minute))
	if err != nil || VerifyEgressToken([]byte("0123456789abcdef0123456789abcdef"), token, "canary.internal", "POST", now) != nil {
		t.Fatalf("token err=%v", err)
	}
	if VerifyEgressToken([]byte("0123456789abcdef0123456789abcdef"), token, "other.internal", "POST", now) == nil || VerifyEgressToken([]byte("0123456789abcdef0123456789abcdef"), token, "canary.internal", "POST", now.Add(2*time.Minute)) == nil {
		t.Fatal("token accepted undeclared or expired use")
	}
	canary, err := BuildCanary("run-1", "test-resource", "test_write", "canary touched")
	if err != nil || canary.ExpectedTouch == "" {
		t.Fatalf("canary=%+v err=%v", canary, err)
	}
}

func TestAttackLabVerdictWorkerAndGate(t *testing.T) {
	verified := EvaluateAttackLabVerdict(VerdictInput{CriterionObserved: true, CanaryTouched: true})
	inconclusive := EvaluateAttackLabVerdict(VerdictInput{InfrastructureFailed: true})
	if verified != AttackLabVerified || inconclusive != AttackLabInconclusive || EvaluateAttackLabVerdict(VerdictInput{}) != AttackLabNotReproduced {
		t.Fatalf("verdicts=%q/%q", verified, inconclusive)
	}
	provider := &fakeSandboxProvider{}
	worker := NewAttackLabWorker(provider)
	input := AttackLabJob{ID: "run-lab-1", Safety: AttackLabInput{Environment: "test", CredentialClass: "test_write", Destination: "canary.internal", AllowedDestinations: []string{"canary.internal"}, SuccessCriterion: "canary touched"}, Limits: SandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, Evidence: EvidenceInput{Semantic: "matched", Gateway: "allowed", Egress: "canary.internal", Kubernetes: "complete", CloudSideEffect: "canary touched"}}
	for range 2 {
		result, err := worker.Consume(context.Background(), input)
		if err != nil || result.Verdict != AttackLabVerified || !result.Cleanup {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	}
	if provider.creates != 1 || provider.runs != 1 || provider.destroys != 1 {
		t.Fatalf("provider calls=%d/%d/%d", provider.creates, provider.runs, provider.destroys)
	}
	report, err := EvaluateM5Gate(M5GateFixture{RedTeamPassed: true, VerifiedCanary: true, ProductionWriteRejected: true, Cleanup: true})
	if err != nil || report.Status != "PASS" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

type fakeSandboxProvider struct{ creates, runs, destroys int }

func (provider *fakeSandboxProvider) Create(context.Context, FargateSpec) error {
	provider.creates++
	return nil
}
func (provider *fakeSandboxProvider) Run(context.Context, string) error    { provider.runs++; return nil }
func (provider *fakeSandboxProvider) Cancel(context.Context, string) error { return nil }
func (provider *fakeSandboxProvider) Destroy(context.Context, string) error {
	provider.destroys++
	return nil
}
func (provider *fakeSandboxProvider) Capabilities(context.Context) ([]string, error) {
	return []string{"fargate_pod"}, nil
}
