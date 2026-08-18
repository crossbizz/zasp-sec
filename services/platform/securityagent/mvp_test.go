package securityagent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestApprovalNotificationIsSignedRedactedAndIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	approval := Approval{ID: "approval-1", OrganizationID: "org-a", RunID: "run-1", StepID: "step-1", State: ApprovalPending, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Version: 1}
	run := SecurityAgentRun{ID: "run-1", OrganizationID: "org-a", AgentID: "agent-1", State: RunWaitingApproval, TriggerEvidenceIDs: []string{"evidence-1"}, DefinitionVersion: 1, Version: 2}
	event, signature, err := BuildApprovalRequiredWebhook([]byte("fixture-signing-key"), approval, run)
	if err != nil || !strings.Contains(string(event), `"type":"security_agent.approval_required"`) || strings.Contains(string(event), "evidence-1") || len(signature) != 64 {
		t.Fatalf("event=%s signature=%q err=%v", event, signature, err)
	}
	ledger := NewApprovalNotificationLedger()
	calls := 0
	for range 2 {
		if err := ledger.DeliverOnce(context.Background(), approval, func(context.Context, []byte, string) error { calls++; return nil }, event, signature); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("delivery calls=%d", calls)
	}
}

func TestSecurityAgentAttentionAndMVPGate(t *testing.T) {
	now := time.Date(2026, 8, 18, 20, 0, 0, 0, time.UTC)
	summary, err := BuildSecurityAgentAttention("org-a", now, []Approval{
		{ID: "approval-a", OrganizationID: "org-a", State: ApprovalPending, CreatedAt: now.Add(-20 * time.Minute), ExpiresAt: now.Add(40 * time.Minute)},
		{ID: "approval-b", OrganizationID: "org-b", State: ApprovalPending, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
	}, []SecurityAgentRun{
		{ID: "run-a", OrganizationID: "org-a", State: RunNeedsHuman},
		{ID: "run-b", OrganizationID: "org-a", State: RunContained},
		{ID: "run-c", OrganizationID: "org-b", State: RunFailed},
	})
	if err != nil || summary.PendingApprovals != 1 || summary.OldestApprovalAgeSeconds != 1200 || summary.NeedsHumanRuns != 1 || summary.RecentContained != 1 || summary.FailedRuns != 0 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	checks := SecurityAgentMVPChecks{AutomaticTrigger: true, Simulation: true, Planning: true, Authorization: true, AutoAction: true, Approval: true, Execution: true, TemporaryCleanup: true, Verification: true, HomeAttention: true, Audit: true, DegradedSafety: true, TenantIsolation: true, SingleTenantParity: true}
	if err := EvaluateSecurityAgentMVPGate(checks); err != nil {
		t.Fatal(err)
	}
	checks.DegradedSafety = false
	if EvaluateSecurityAgentMVPGate(checks) == nil {
		t.Fatal("incomplete gate passed")
	}
}
