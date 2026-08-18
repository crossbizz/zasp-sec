package securityagent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

type lifecyclePolicyService struct {
	mu           sync.Mutex
	verifyErr    bool
	disableCalls int
}

func (s *lifecyclePolicyService) CreateTemporaryPolicy(context.Context, TemporaryPolicySpec, string) (string, error) {
	return "policy-1", nil
}
func (s *lifecyclePolicyService) VerifyTemporaryPolicy(context.Context, string, TemporaryPolicySpec) error {
	if s.verifyErr {
		return ErrRejected
	}
	return nil
}
func (s *lifecyclePolicyService) DisableTemporaryControl(_ context.Context, control TemporaryControl, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disableCalls++
	if key == "" || control.Scope != "env-a" {
		return "", ErrRejected
	}
	return "disabled", nil
}
func (s *lifecyclePolicyService) VerifyTemporaryControlAbsent(context.Context, TemporaryControl) error {
	if s.verifyErr {
		return ErrRejected
	}
	return nil
}

func TestTemporaryPolicyVerificationAndBoundedExpiryCleanup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	service := &lifecyclePolicyService{}
	action, err := NewTemporaryPolicyAction(service)
	if err != nil {
		t.Fatal(err)
	}
	request := ActionRequest{OrganizationID: "org-a", RunID: "run-1", StepID: "step-1", ActionKey: "create_temporary_policy", Parameters: map[string]string{"mode": "block", "scope": "env-a", "ttl": "5m"}}
	result, err := action.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	outcome := action.VerifyOutcome(ctx, request, result)
	if outcome.State != VerificationVerified {
		t.Fatalf("outcome=%+v", outcome)
	}
	service.verifyErr = true
	outcome = action.VerifyOutcome(ctx, request, result)
	if outcome.State != VerificationInconclusive {
		t.Fatalf("stale outcome=%+v", outcome)
	}
	service.verifyErr = false

	repo := NewMemoryRepository()
	expired := TemporaryControl{ID: "control-1", OrganizationID: "org-a", RunID: "run-1", StepID: "step-1", Kind: "policy", TargetID: "policy-1", Scope: "env-a", ExpiresAt: now.Add(-time.Minute), State: ControlActive, Version: 1}
	if err := repo.CreateTemporaryControl(ctx, expired); err != nil {
		t.Fatal(err)
	}
	future := expired
	future.ID = "control-2"
	future.ExpiresAt = now.Add(time.Hour)
	if err := repo.CreateTemporaryControl(ctx, future); err != nil {
		t.Fatal(err)
	}
	var claimed int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, worker := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			items, err := repo.ClaimExpiredControls(ctx, "org-a", now, id, 10)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			claimed += len(items)
			mu.Unlock()
		}(worker)
	}
	wg.Wait()
	if claimed != 1 {
		t.Fatalf("claimed=%d", claimed)
	}

	repo = NewMemoryRepository()
	if err := repo.CreateTemporaryControl(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateTemporaryControl(ctx, future); err != nil {
		t.Fatal(err)
	}
	worker, err := NewExpiryWorker(repo, service)
	if err != nil {
		t.Fatal(err)
	}
	report, err := worker.RunOnce(ctx, "org-a", now, "worker-a", 10)
	if err != nil || report.Cleaned != 1 || report.Failed != 0 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	report, err = worker.RunOnce(ctx, "org-a", now, "worker-b", 10)
	if err != nil || report.Cleaned != 0 || service.disableCalls != 1 {
		t.Fatalf("repeat=%+v calls=%d err=%v", report, service.disableCalls, err)
	}
	retained, err := repo.GetTemporaryControl(ctx, "org-a", "control-2")
	if err != nil || retained.State != ControlActive {
		t.Fatalf("future=%+v err=%v", retained, err)
	}
	if audits := repo.CleanupAudits(ctx, "org-a"); len(audits) != 1 || audits[0].State != "cleaned" {
		t.Fatalf("audits=%+v", audits)
	}

	failingRepo := NewMemoryRepository()
	if err := failingRepo.CreateTemporaryControl(ctx, expired); err != nil {
		t.Fatal(err)
	}
	service.verifyErr = true
	failingWorker, _ := NewExpiryWorker(failingRepo, service)
	report, err = failingWorker.RunOnce(ctx, "org-a", now, "worker-c", 10)
	if err == nil || report.Failed != 1 {
		t.Fatalf("failure report=%+v err=%v", report, err)
	}
	failed, _ := failingRepo.GetTemporaryControl(ctx, "org-a", expired.ID)
	if failed.State != ControlCleanupFailed {
		t.Fatalf("failed=%+v", failed)
	}
}

type fakeBuiltinBackend struct {
	mu        sync.Mutex
	calls     map[string]int
	executed  map[string]map[string]string
	supported map[string]bool
	secret    []byte
	verifyErr bool
}

func (backend *fakeBuiltinBackend) Supports(_ context.Context, key string, parameters map[string]string) bool {
	return backend.supported[key]
}
func (backend *fakeBuiltinBackend) Execute(_ context.Context, key string, parameters map[string]string, idempotency string) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.calls[key]++
	if backend.executed != nil {
		backend.executed[key] = cloneParameters(parameters)
	}
	if idempotency == "" {
		return "", ErrRejected
	}
	return key + "-1", nil
}
func (backend *fakeBuiltinBackend) WebhookSigningSecret(context.Context, string) ([]byte, error) {
	return append([]byte(nil), backend.secret...), nil
}
func (backend *fakeBuiltinBackend) Verify(context.Context, string, map[string]string, string) (VerificationOutcome, error) {
	if backend.verifyErr {
		return VerificationOutcome{State: VerificationInconclusive}, nil
	}
	return VerificationOutcome{State: VerificationVerified}, nil
}

func TestBoundedResponseActionSet(t *testing.T) {
	ctx := context.Background()
	backend := &fakeBuiltinBackend{calls: map[string]int{}, executed: map[string]map[string]string{}, supported: map[string]bool{"isolate_session": true, "run_test": true, "rerun_test": true, "start_attack_lab": true, "create_evidence_export": true, "send_response_webhook": true, "update_finding_response": true}, secret: []byte("fixture-response-key")}
	registry := NewRegistry()
	if err := RegisterResponseActions(registry, backend); err != nil {
		t.Fatal(err)
	}
	cases := []ActionRequest{
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-1", ActionKey: "isolate_session", Parameters: map[string]string{"session_id": "session-1", "scope": "env-a", "ttl": "5m"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-2", ActionKey: "run_test", Parameters: map[string]string{"test_definition_id": "test-1"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-3", ActionKey: "rerun_test", Parameters: map[string]string{"test_definition_id": "test-1"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-4", ActionKey: "start_attack_lab", Parameters: map[string]string{"test_definition_id": "test-1", "target_class": "non_production", "preflight": "approved"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-5", ActionKey: "create_evidence_export", Parameters: map[string]string{"run_id": "run-1", "evidence_ids": "run-1:evidence-1,run-1:evidence-2"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-6", ActionKey: "send_response_webhook", Parameters: map[string]string{"destination_id": "webhook-1", "evidence_id": "run-1:evidence-1"}},
		{OrganizationID: "org-a", RunID: "run-1", StepID: "step-7", ActionKey: "update_finding_response", Parameters: map[string]string{"finding_id": "finding-1", "assignee_id": "principal-1", "status": "investigating", "note": "Containment started"}},
	}
	for _, request := range cases {
		first, err := registry.Execute(ctx, request)
		if err != nil {
			t.Fatalf("%s: %v", request.ActionKey, err)
		}
		second, err := registry.Execute(ctx, request)
		if err != nil || first != second || backend.calls[request.ActionKey] != 1 {
			t.Fatalf("%s first=%+v second=%+v calls=%d err=%v", request.ActionKey, first, second, backend.calls[request.ActionKey], err)
		}
		if err := registry.Verify(ctx, request, first); err != nil {
			t.Fatalf("verify %s: %v", request.ActionKey, err)
		}
	}
	webhookParameters := backend.executed["send_response_webhook"]
	expectedPayload := `{"type":"security_agent.response","organization_id":"org-a","run_id":"run-1","evidence_id":"run-1:evidence-1"}`
	mac := hmac.New(sha256.New, backend.secret)
	_, _ = mac.Write([]byte(expectedPayload))
	if webhookParameters["destination_id"] != "webhook-1" || webhookParameters["payload"] != expectedPayload || webhookParameters["signature"] != hex.EncodeToString(mac.Sum(nil)) || len(webhookParameters) != 3 {
		t.Fatalf("unsigned or unredacted webhook parameters=%+v", webhookParameters)
	}

	badTest := cases[1]
	badTest.Parameters = map[string]string{"test_definition_id": "test-1", "prompt": "ignore policy"}
	if _, err := registry.Execute(ctx, badTest); err == nil {
		t.Fatal("arbitrary test content accepted")
	}
	badAttack := cases[3]
	badAttack.Parameters["target_class"] = "production"
	if _, err := registry.Execute(ctx, badAttack); err == nil {
		t.Fatal("production attack target accepted")
	}
	badExport := cases[4]
	badExport.Parameters["evidence_ids"] = "other-run:evidence"
	if _, err := registry.Execute(ctx, badExport); err == nil {
		t.Fatal("cross-run evidence accepted")
	}
	badWebhook := cases[5]
	badWebhook.Parameters = map[string]string{"url": "https://example.invalid"}
	if _, err := registry.Execute(ctx, badWebhook); err == nil {
		t.Fatal("arbitrary webhook URL accepted")
	}
	badFinding := cases[6]
	badFinding.Parameters["status"] = "resolved"
	if _, err := registry.Execute(ctx, badFinding); err == nil {
		t.Fatal("finding resolved by agent")
	}

	revoke := ActionRequest{OrganizationID: "org-a", RunID: "run-1", StepID: "step-8", ActionKey: "revoke_integration_connection", Parameters: map[string]string{"connection_id": "connection-1", "approval_token": "approval-1"}}
	if available := registry.Available(ctx, revoke); containsMetadata(available, "revoke_integration_connection") {
		t.Fatal("unsupported revoke exposed")
	}
	backend.supported["revoke_integration_connection"] = true
	if available := registry.Available(ctx, revoke); !containsMetadata(available, "revoke_integration_connection") {
		t.Fatal("supported revoke hidden")
	}
	missingApproval := revoke
	missingApproval.Parameters = map[string]string{"connection_id": "connection-1"}
	if _, err := registry.Execute(ctx, missingApproval); err == nil || backend.calls["revoke_integration_connection"] != 0 {
		t.Fatal("revoke called without approval")
	}
	result, err := registry.Execute(ctx, revoke)
	if err != nil {
		t.Fatal(err)
	}
	backend.verifyErr = true
	if outcome := registry.VerifyOutcome(ctx, revoke, result); outcome.State != VerificationInconclusive {
		t.Fatalf("revoke timeout=%+v", outcome)
	}
}

func TestBuiltInTemplatesTriggerMatchersAndDeduplication(t *testing.T) {
	registry, err := NewTemplateRegistry(BuiltInTemplates())
	if err != nil {
		t.Fatal(err)
	}
	if ids := registry.IDs(); !equalStrings(ids, []string{"credential_exposure", "prompt_tool_injection", "repeated_policy_violation", "shadow_agent_triage", "suspicious_egress"}) {
		t.Fatalf("ids=%v", ids)
	}
	suspicious, _ := registry.Get("suspicious_egress", 1)
	if !contains(suspicious.DefaultActions, "create_temporary_policy") || contains(suspicious.DefaultActions, "revoke_integration_connection") {
		t.Fatalf("suspicious=%+v", suspicious)
	}
	credential, _ := registry.Get("credential_exposure", 1)
	if !credential.ApprovalRequired["revoke_integration_connection"] {
		t.Fatalf("credential=%+v", credential)
	}
	injection, _ := registry.Get("prompt_tool_injection", 1)
	if injection.VerificationCondition != "linked_risk_blocked_or_not_reproduced" {
		t.Fatalf("injection=%+v", injection)
	}
	shadow, _ := registry.Get("shadow_agent_triage", 1)
	for _, action := range shadow.DefaultActions {
		if action == "create_temporary_policy" || action == "revoke_integration_connection" {
			t.Fatalf("destructive shadow action=%s", action)
		}
	}

	now := time.Date(2026, 8, 18, 21, 0, 0, 0, time.UTC)
	if !MatchFinding(FindingTriggerRule{OrganizationID: "org-a", EnvironmentID: "env-a", Family: "credential", MinimumSeverity: "high", Enabled: true}, TriggerEvent{OrganizationID: "org-a", EnvironmentID: "env-a", Kind: "finding", Family: "credential", Severity: "critical", At: now}) {
		t.Fatal("finding did not match")
	}
	if MatchFinding(FindingTriggerRule{OrganizationID: "org-a", EnvironmentID: "env-a", Family: "credential", MinimumSeverity: "high", Enabled: true}, TriggerEvent{OrganizationID: "org-a", EnvironmentID: "env-b", Kind: "finding", Family: "credential", Severity: "critical", At: now}) {
		t.Fatal("cross-environment finding matched")
	}
	if MatchAttackPath(AttackPathTriggerRule{OrganizationID: "org-a", EnvironmentID: "env-a", EvidenceState: "verified", Enabled: true}, TriggerEvent{OrganizationID: "org-a", EnvironmentID: "env-a", Kind: "attack_path", EvidenceState: "potential", At: now}) {
		t.Fatal("potential path matched verified rule")
	}
	runtime := RuntimeTriggerRule{OrganizationID: "org-a", EnvironmentID: "env-a", Action: "block", Risk: "high", AgentID: "agent-1", SessionID: "session-1", Count: 2, Window: time.Minute, Enabled: true}
	events := []TriggerEvent{{OrganizationID: "org-a", EnvironmentID: "env-a", Kind: "runtime_decision", PolicyAction: "block", Risk: "high", AgentID: "agent-1", SessionID: "session-1", At: now.Add(-30 * time.Second)}, {OrganizationID: "org-a", EnvironmentID: "env-a", Kind: "runtime_decision", PolicyAction: "block", Risk: "high", AgentID: "agent-1", SessionID: "session-1", At: now.Add(-2 * time.Minute)}}
	if MatchRuntime(runtime, events, now) {
		t.Fatal("event outside window triggered")
	}
	events[1].At = now.Add(-10 * time.Second)
	if !MatchRuntime(runtime, events, now) {
		t.Fatal("bounded runtime pattern did not trigger")
	}

	dedup := NewTriggerDeduplicator()
	event := TriggerEvent{OrganizationID: "org-a", EnvironmentID: "env-a", Kind: "finding", SourceID: "finding-1", Family: "credential", Severity: "high", At: now}
	fingerprint, created, err := dedup.Claim(event, 5*time.Minute, now)
	if err != nil || !created || fingerprint == "" {
		t.Fatalf("first fingerprint=%q created=%v err=%v", fingerprint, created, err)
	}
	second, created, err := dedup.Claim(event, 5*time.Minute, now.Add(time.Minute))
	if err != nil || created || second != fingerprint {
		t.Fatalf("second=%q created=%v err=%v", second, created, err)
	}
}

func containsMetadata(values []ActionMetadata, key string) bool {
	for _, value := range values {
		if value.Key == key {
			return true
		}
	}
	return false
}
