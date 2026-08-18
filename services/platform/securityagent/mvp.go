package securityagent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type SecurityAgentAttention struct {
	PendingApprovals         int
	OldestApprovalAgeSeconds int
	NeedsHumanRuns           int
	FailedRuns               int
	InconclusiveRuns         int
	RecentContained          int
	RecentRemediated         int
}

func BuildSecurityAgentAttention(organizationID string, now time.Time, approvals []Approval, runs []SecurityAgentRun) (SecurityAgentAttention, error) {
	if !bounded(organizationID, 128) || now.IsZero() || now.Location() != time.UTC || len(approvals) > 10_000 || len(runs) > 10_000 {
		return SecurityAgentAttention{}, ErrRejected
	}
	result := SecurityAgentAttention{}
	for _, value := range approvals {
		if value.OrganizationID != organizationID || value.State != ApprovalPending {
			continue
		}
		result.PendingApprovals++
		age := int(now.Sub(value.ExpiresAt).Seconds())
		if age > result.OldestApprovalAgeSeconds {
			result.OldestApprovalAgeSeconds = age
		}
	}
	for _, value := range runs {
		if value.OrganizationID != organizationID {
			continue
		}
		switch value.State {
		case RunNeedsHuman:
			result.NeedsHumanRuns++
		case RunFailed:
			result.FailedRuns++
		case RunInconclusive:
			result.InconclusiveRuns++
		case RunContained:
			result.RecentContained++
		case RunRemediated:
			result.RecentRemediated++
		}
	}
	return result, nil
}

type approvalRequiredEvent struct {
	Type           string `json:"type"`
	ApprovalID     string `json:"approval_id"`
	RunID          string `json:"run_id"`
	OrganizationID string `json:"organization_id"`
	ExpiresAt      string `json:"expires_at"`
}

func BuildApprovalRequiredWebhook(secret []byte, approval Approval, run SecurityAgentRun) ([]byte, string, error) {
	if len(secret) < 16 || len(secret) > 256 || approval.State != ApprovalPending || approval.OrganizationID != run.OrganizationID || approval.RunID != run.ID || approval.ExpiresAt.IsZero() || approval.ExpiresAt.Location() != time.UTC {
		return nil, "", ErrRejected
	}
	body, err := json.Marshal(approvalRequiredEvent{Type: "security_agent.approval_required", ApprovalID: approval.ID, RunID: run.ID, OrganizationID: run.OrganizationID, ExpiresAt: approval.ExpiresAt.Format(time.RFC3339Nano)})
	if err != nil {
		return nil, "", ErrRejected
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return body, hex.EncodeToString(mac.Sum(nil)), nil
}

type ApprovalNotificationLedger struct {
	mu        sync.Mutex
	delivered map[string]bool
}

func NewApprovalNotificationLedger() *ApprovalNotificationLedger {
	return &ApprovalNotificationLedger{delivered: map[string]bool{}}
}

func (ledger *ApprovalNotificationLedger) DeliverOnce(ctx context.Context, approval Approval, deliver func(context.Context, []byte, string) error, body []byte, signature string) error {
	if ledger == nil || invalidContext(ctx) || approval.State != ApprovalPending || deliver == nil || len(body) == 0 || len(body) > 4096 || len(signature) != 64 {
		return ErrRejected
	}
	key, err := idempotencyKey(approval.OrganizationID, approval.ID)
	if err != nil {
		return err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.delivered[key] {
		return nil
	}
	if err := deliver(ctx, append([]byte(nil), body...), signature); err != nil {
		return ErrRejected
	}
	ledger.delivered[key] = true
	return nil
}

type SecurityAgentMVPChecks struct {
	AutomaticTrigger, Simulation, Planning, Authorization, AutoAction  bool
	Approval, Execution, TemporaryCleanup, Verification, HomeAttention bool
	Audit, DegradedSafety, TenantIsolation, SingleTenantParity         bool
}

func EvaluateSecurityAgentMVPGate(value SecurityAgentMVPChecks) error {
	if !value.AutomaticTrigger || !value.Simulation || !value.Planning || !value.Authorization || !value.AutoAction || !value.Approval || !value.Execution || !value.TemporaryCleanup || !value.Verification || !value.HomeAttention || !value.Audit || !value.DegradedSafety || !value.TenantIsolation || !value.SingleTenantParity {
		return ErrRejected
	}
	return nil
}
