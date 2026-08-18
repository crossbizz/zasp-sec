package securityagent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureAgent() SecurityAgent {
	return SecurityAgent{
		ID: "agent-1", OrganizationID: "org-a", Name: "Contain suspicious runtime action",
		Trigger:        Trigger{Kind: "finding", Source: "runtime"},
		Scope:          Scope{OrganizationID: "org-a", EnvironmentIDs: []string{"env-a"}},
		Autonomy:       AutonomySupervised,
		Limits:         RunLimits{MaxSteps: 4, MaxDuration: 10 * time.Minute, TemporaryPolicyTTL: time.Hour, MaxAITokens: 4000, MaxConcurrent: 2},
		AllowedActions: []string{"create_temporary_policy"},
		Verification:   Verification{Kind: "policy_state"}, DefinitionVersion: 1, Enabled: true,
	}
}

func fixtureMetadata() ActionMetadata {
	return ActionMetadata{Key: "create_temporary_policy", InputSchema: map[string]string{"mode": "enum:monitor,block", "scope": "string", "ttl": "duration"}, RiskClass: "containment", TargetTypes: []string{"environment"}, ApprovalFloor: "operator", Reversible: true, Idempotent: true, VerificationKind: "policy_state"}
}

func TestDomainPlanMetadataAndMigrationContracts(t *testing.T) {
	agent := fixtureAgent()
	if err := ValidateAgent(agent); err != nil {
		t.Fatal(err)
	}
	invalid := agent
	invalid.Scope.EnvironmentIDs = nil
	if ValidateAgent(invalid) == nil {
		t.Fatal("empty scope accepted")
	}
	invalid = agent
	invalid.AllowedActions = nil
	if ValidateAgent(invalid) == nil {
		t.Fatal("empty action set accepted")
	}
	invalid = agent
	invalid.Limits.MaxSteps = 0
	if ValidateAgent(invalid) == nil {
		t.Fatal("non-positive limit accepted")
	}

	if CanTransition(RunRemediated, RunRunning) {
		t.Fatal("terminal run resumed")
	}
	if !CanTransition(RunQueued, RunPlanning) {
		t.Fatal("valid transition rejected")
	}
	metadata := fixtureMetadata()
	if err := ValidateActionMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Version: 1, Summary: "Apply bounded containment", Steps: []PlanStep{{Index: 0, ActionKey: metadata.Key, Parameters: map[string]string{"mode": "monitor", "scope": "env-a", "ttl": "5m"}}}}
	if err := ValidatePlan(plan, map[string]ActionMetadata{metadata.Key: metadata}); err != nil {
		t.Fatal(err)
	}
	plan.Version = 2
	if ValidatePlan(plan, map[string]ActionMetadata{metadata.Key: metadata}) == nil {
		t.Fatal("unknown plan version accepted")
	}

	sql := MigrationSQL()
	for _, token := range []string{"security_agents", "security_agent_runs", "security_agent_steps", "security_agent_approvals", "security_action_idempotency", "ENABLE ROW LEVEL SECURITY", "organization_id"} {
		if !strings.Contains(sql, token) {
			t.Fatalf("migration missing %q", token)
		}
	}
	if err := ValidateMigration(sql); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMigration(sql); err != nil {
		t.Fatal("migration validation is not repeatable")
	}
}

func TestScopedRepositoriesCASOrderingApprovalAndIdempotency(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 18, 18, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository()
	agent := fixtureAgent()
	if err := repo.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetAgent(ctx, "org-b", agent.ID); err == nil {
		t.Fatal("cross-organization read succeeded")
	}
	listed, cursor, err := repo.ListAgents(ctx, "org-a", "", 10)
	if err != nil || len(listed) != 1 || cursor != "" {
		t.Fatalf("listed=%+v cursor=%q err=%v", listed, cursor, err)
	}
	agent.Name = "Updated"
	agent.Version = 1
	if err := repo.UpdateAgent(ctx, agent, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SoftDeleteAgent(ctx, "org-a", agent.ID, 2, now); err != nil {
		t.Fatal(err)
	}
	matched, err := repo.MatchAgents(ctx, "org-a", Trigger{Kind: "finding", Source: "runtime"})
	if err != nil || len(matched) != 0 {
		t.Fatalf("deleted trigger match=%+v err=%v", matched, err)
	}

	run := SecurityAgentRun{ID: "run-1", OrganizationID: "org-a", AgentID: agent.ID, State: RunQueued, TriggerEvidenceIDs: []string{"evidence-1"}, DefinitionVersion: 1, Version: 1}
	if err := repo.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	var winners int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := repo.TransitionRun(ctx, "org-a", run.ID, RunQueued, RunPlanning, 1); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("CAS winners=%d", winners)
	}

	for _, step := range []RunStep{{ID: "step-2", OrganizationID: "org-a", RunID: run.ID, Index: 2, ActionKey: "create_temporary_policy", State: "queued", Version: 1}, {ID: "step-1", OrganizationID: "org-a", RunID: run.ID, Index: 1, ActionKey: "create_temporary_policy", State: "queued", Version: 1}} {
		if err := repo.AppendStep(ctx, step); err != nil {
			t.Fatal(err)
		}
	}
	steps, err := repo.ListSteps(ctx, "org-a", run.ID)
	if err != nil || len(steps) != 2 || steps[0].Index != 1 {
		t.Fatalf("steps=%+v err=%v", steps, err)
	}
	if err := repo.AppendStep(ctx, RunStep{ID: "duplicate", OrganizationID: "org-a", RunID: run.ID, Index: 1, ActionKey: "create_temporary_policy", State: "queued", Version: 1}); err == nil {
		t.Fatal("duplicate step index accepted")
	}

	approval := Approval{ID: "approval-1", OrganizationID: "org-a", RunID: run.ID, StepID: "step-1", State: ApprovalPending, ExpiresAt: now.Add(time.Minute), Version: 1}
	if err := repo.CreateApproval(ctx, approval); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DecideApproval(ctx, "org-a", approval.ID, "principal-1", now, ApprovalApproved, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DecideApproval(ctx, "org-a", approval.ID, "principal-2", now, ApprovalRejected, 2); err == nil {
		t.Fatal("terminal approval reused")
	}
	expired := approval
	expired.ID = "approval-2"
	expired.ExpiresAt = now.Add(-time.Second)
	if err := repo.CreateApproval(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DecideApproval(ctx, "org-a", expired.ID, "principal-1", now, ApprovalApproved, 1); err == nil {
		t.Fatal("expired approval accepted")
	}

	claim := IdempotencyRecord{OrganizationID: "org-a", RunID: run.ID, StepID: "step-1", ActionKey: "create_temporary_policy", State: "succeeded", OutcomeID: "policy-1"}
	first, created, err := repo.ClaimAction(ctx, claim)
	if err != nil || !created || first.OutcomeID != "policy-1" {
		t.Fatalf("first=%+v created=%v err=%v", first, created, err)
	}
	prior, created, err := repo.ClaimAction(ctx, claim)
	if err != nil || created || prior.OutcomeID != first.OutcomeID {
		t.Fatalf("prior=%+v created=%v err=%v", prior, created, err)
	}
}

type fakePolicyService struct {
	mu       sync.Mutex
	calls    int
	policyID string
}

type recordingMigrationExecutor struct {
	calls int
	sql   []string
}

func (executor *recordingMigrationExecutor) Exec(_ context.Context, statement string, arguments ...any) error {
	if len(arguments) != 0 {
		return ErrRejected
	}
	executor.calls++
	executor.sql = append(executor.sql, statement)
	return nil
}

func TestMigrationExecutesRepeatablyThroughDatabaseBoundary(t *testing.T) {
	executor := &recordingMigrationExecutor{}
	if err := ApplyMigration(context.Background(), executor); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigration(context.Background(), executor); err != nil {
		t.Fatal(err)
	}
	if executor.calls != 2 || len(executor.sql) != 2 || executor.sql[0] != MigrationSQL() || executor.sql[1] != MigrationSQL() {
		t.Fatalf("calls=%d sql=%q", executor.calls, executor.sql)
	}
	for _, table := range []string{"security_agents", "security_agent_runs", "security_agent_steps", "security_agent_approvals", "security_action_idempotency"} {
		if !strings.Contains(executor.sql[0], "EXCEPTION WHEN duplicate_object THEN NULL") || !strings.Contains(executor.sql[0], "CREATE POLICY "+table+"_tenant") {
			t.Fatalf("migration is not repeatably safe for %s", table)
		}
	}
}

func (s *fakePolicyService) CreateTemporaryPolicy(_ context.Context, spec TemporaryPolicySpec, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if spec.TTL <= 0 || key == "" {
		return "", ErrRejected
	}
	if s.policyID == "" {
		s.policyID = "policy-1"
	}
	return s.policyID, nil
}
func (s *fakePolicyService) VerifyTemporaryPolicy(_ context.Context, id string, spec TemporaryPolicySpec) error {
	if id != "policy-1" || spec.Scope != "env-a" {
		return ErrRejected
	}
	return nil
}

func TestRegistryAndTemporaryRuntimePolicyAction(t *testing.T) {
	ctx := context.Background()
	service := &fakePolicyService{}
	registry := NewRegistry()
	action, err := NewTemporaryPolicyAction(service)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(action); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(action); err == nil {
		t.Fatal("duplicate action registered")
	}
	metadata := action.Metadata()
	if err := ValidateActionMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	bad := ActionRequest{OrganizationID: "org-a", RunID: "run-1", StepID: "step-1", ActionKey: metadata.Key, Parameters: map[string]string{"mode": "monitor", "scope": "env-a"}}
	if _, err := registry.Execute(ctx, bad); err == nil {
		t.Fatal("permanent/no-TTL action accepted")
	}
	request := bad
	request.Parameters["ttl"] = "5m"
	first, err := registry.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Execute(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.OutcomeID != second.OutcomeID || service.calls != 1 {
		t.Fatalf("first=%+v second=%+v calls=%d", first, second, service.calls)
	}
	if err := registry.Verify(ctx, request, first); err != nil {
		t.Fatal(err)
	}
}
