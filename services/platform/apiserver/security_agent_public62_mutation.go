package apiserver

import (
	"context"
	"strconv"
	"time"
)

type SecurityAgentPublicDecision struct {
	RunID           string
	RunVersion      int64
	ApprovalID      string
	ApprovalVersion int64
	Decision        string
	IdempotencyKey  string
}
type SecurityAgentPublicCancellation struct {
	RunID          string
	RunVersion     int64
	IdempotencyKey string
}
type SecurityAgentPublicDecisionResult struct {
	ContractVersion int    `json:"contract_version"`
	OrganizationID  string `json:"organization_id"`
	WorkspaceID     string `json:"workspace_id"`
	EnvironmentID   string `json:"environment_id"`
	RunID           string `json:"run_id"`
	RunState        string `json:"run_state"`
	RunVersion      int64  `json:"run_version"`
	StepID          string `json:"step_id"`
	StepState       string `json:"step_state"`
	StepVersion     int64  `json:"step_version"`
	ApprovalID      string `json:"approval_id"`
	ApprovalVersion int64  `json:"approval_version"`
	Decision        string `json:"decision"`
	Outcome         string `json:"outcome"`
	AuditID         string `json:"audit_id"`
	ReceiptID       string `json:"receipt_id"`
	Replayed        bool   `json:"replayed"`
}
type SecurityAgentPublicCancellationResult struct {
	ContractVersion   int     `json:"contract_version"`
	OrganizationID    string  `json:"organization_id"`
	WorkspaceID       string  `json:"workspace_id"`
	EnvironmentID     string  `json:"environment_id"`
	RunID             string  `json:"run_id"`
	RunState          string  `json:"run_state"`
	RunVersion        int64   `json:"run_version"`
	StepID            *string `json:"step_id"`
	StepState         *string `json:"step_state"`
	StepVersion       int64   `json:"step_version"`
	CleanupRequired   bool    `json:"cleanup_required"`
	CancellationPhase string  `json:"cancellation_phase"`
	Outcome           string  `json:"outcome"`
	AuditID           string  `json:"audit_id"`
	ReceiptID         string  `json:"receipt_id"`
	Replayed          bool    `json:"replayed"`
}

func public62MutationVersion(v int64) bool { return v >= 1 && v < 1000000 }
func public62MutationStepIndex(id RequestIdentity, run, step string) (int64, bool) {
	for i := int64(0); i < 2; i++ {
		canonical, err := CanonicalDiscoveryID(id.Scope, "security_agent_step", run+"\x1f"+strconv.FormatInt(i, 10))
		if err == nil && canonical == step {
			return i, true
		}
	}
	return 0, false
}
func public62MutationIdentity(id RequestIdentity, op, key, audit, receipt string) bool {
	a, err := CanonicalDiscoveryID(id.Scope, "public62_mutation_audit", id.PrincipalID.String()+"\x1f"+op+"\x1f"+key)
	if err != nil || a != audit {
		return false
	}
	r, err := CanonicalDiscoveryID(id.Scope, "public62_mutation_receipt", id.PrincipalID.String()+"\x1f"+op+"\x1f"+key)
	return err == nil && r == receipt
}

// Decide derives the authentication instant from authenticated session expiry.
// Neither callers nor response DTOs can choose tenant, actor, or current step.
func (r *SecurityAgentPublicRepository) Decide(ctx context.Context, id RequestIdentity, q SecurityAgentPublicDecision) (SecurityAgentPublicDecisionResult, error) {
	var zero, v SecurityAgentPublicDecisionResult
	now := time.Now()
	if !r.valid(ctx, id) || !id.FreshAuthenticated || id.FreshAuthExpiresAt.IsZero() || id.FreshAuthExpiresAt.Location() != time.UTC || !id.FreshAuthExpiresAt.After(now) || id.FreshAuthExpiresAt.After(now.Add(5*time.Minute+5*time.Second)) || !public62ID(q.RunID) || !public62ID(q.ApprovalID) || !public62MutationVersion(q.RunVersion) || !public62MutationVersion(q.ApprovalVersion) || !public62OneOf(q.Decision, "approved", "rejected") || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "decide", map[string]any{"run_id": q.RunID, "run_version": q.RunVersion, "approval_id": q.ApprovalID, "approval_version": q.ApprovalVersion, "decision": q.Decision, "idempotency_key": q.IdempotencyKey, "fresh_auth_at": id.FreshAuthExpiresAt.Add(-5 * time.Minute).Format(time.RFC3339Nano)})
	if err != nil {
		return zero, err
	}
	if len(raw) > 4096 || public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.OrganizationID != id.Scope.OrganizationID().String() || v.WorkspaceID != id.Scope.WorkspaceID().String() || v.EnvironmentID != id.Scope.EnvironmentID().String() || v.RunID != q.RunID || v.RunVersion != q.RunVersion+1 || v.ApprovalID != q.ApprovalID || v.ApprovalVersion != q.ApprovalVersion+1 || v.Decision != q.Decision || !public62ID(v.StepID) || v.StepID == v.RunID || v.StepID == v.ApprovalID || v.StepVersion < 2 || !public62Version(v.StepVersion) || !public62MutationIdentity(id, "decide", q.IdempotencyKey, v.AuditID, v.ReceiptID) {
		return zero, ErrRepositoryUnavailable
	}
	approval, identityErr := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", q.RunID+"\x1f"+v.StepID)
	if identityErr != nil || approval != v.ApprovalID {
		return zero, ErrRepositoryUnavailable
	}
	index, canonical := public62MutationStepIndex(id, q.RunID, v.StepID)
	if !canonical || v.StepVersion != index+2 {
		return zero, ErrRepositoryUnavailable
	}
	if q.Decision == "approved" && (v.RunState != "running" || v.StepState != "authorized" || v.Outcome != "approved") || q.Decision == "rejected" && (v.RunState != "needs_human" || v.StepState != "cancelled" || v.Outcome != "blocked") {
		return zero, ErrRepositoryUnavailable
	}
	return v, nil
}

// Cancel does not require or manufacture fresh browser authentication. The
// facade adapts its required transition timestamp from the database clock.
func (r *SecurityAgentPublicRepository) Cancel(ctx context.Context, id RequestIdentity, q SecurityAgentPublicCancellation) (SecurityAgentPublicCancellationResult, error) {
	var zero, v SecurityAgentPublicCancellationResult
	if !r.valid(ctx, id) || !public62ID(q.RunID) || !public62MutationVersion(q.RunVersion) || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "cancel", map[string]any{"run_id": q.RunID, "run_version": q.RunVersion, "idempotency_key": q.IdempotencyKey})
	if err != nil {
		return zero, err
	}
	if len(raw) > 4096 || public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.OrganizationID != id.Scope.OrganizationID().String() || v.WorkspaceID != id.Scope.WorkspaceID().String() || v.EnvironmentID != id.Scope.EnvironmentID().String() || v.RunID != q.RunID || v.RunVersion != q.RunVersion+1 || v.Outcome != "cancelled-request" || !public62MutationIdentity(id, "cancel", q.IdempotencyKey, v.AuditID, v.ReceiptID) {
		return zero, ErrRepositoryUnavailable
	}
	if v.StepID == nil {
		if v.CancellationPhase != "before-admission" || v.StepState != nil || v.StepVersion != 0 || v.CleanupRequired || !public62OneOf(v.RunState, "cancelled", "needs_human") || v.RunState == "cancelled" && q.RunVersion != 1 || v.RunState == "needs_human" && q.RunVersion < 2 {
			return zero, ErrRepositoryUnavailable
		}
	} else if !public62ID(*v.StepID) || *v.StepID == v.RunID || v.StepState == nil || v.StepVersion < 2 || !public62Version(v.StepVersion) || !public62OneOf(*v.StepState, "cancelled", "executing") || v.RunState != "cancelled" || q.RunVersion < 3 {
		return zero, ErrRepositoryUnavailable
	} else {
		index, canonical := public62MutationStepIndex(id, q.RunID, *v.StepID)
		if !canonical {
			return zero, ErrRepositoryUnavailable
		}
		var expected int64
		switch v.CancellationPhase {
		case "queued":
			if index != 1 || *v.StepState != "cancelled" {
				return zero, ErrRepositoryUnavailable
			}
			expected = 2
		case "pending-approval":
			if *v.StepState != "cancelled" {
				return zero, ErrRepositoryUnavailable
			}
			expected = index + 2
		case "authorized":
			if *v.StepState != "cancelled" {
				return zero, ErrRepositoryUnavailable
			}
			expected = index + 3
		case "executing":
			if *v.StepState != "executing" || !v.CleanupRequired {
				return zero, ErrRepositoryUnavailable
			}
			expected = index + 3
		default:
			return zero, ErrRepositoryUnavailable
		}
		if v.StepVersion != expected {
			return zero, ErrRepositoryUnavailable
		}
	}
	return v, nil
}
