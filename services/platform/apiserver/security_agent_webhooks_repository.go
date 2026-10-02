package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

type ResponseWebhookScope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}
type ResponseWebhookAuthority struct {
	Scope                  ResponseWebhookScope
	PrincipalID, SessionID string
}
type ResponseWebhookAcceptance struct {
	Claim                                                                                   SecurityAgentRunClaim
	WorkerID, LeaseToken, ApprovalID, AuditID, CorrelationID, IdempotencyKey, DestinationID string
	ApprovalExpiresAt                                                                       time.Time
	Submission                                                                              SecurityAgentPlannerSubmission
	Evidence                                                                                []securityagent.ResponseWebhookEvidence
}
type ResponseWebhookFence struct {
	Scope             ResponseWebhookScope
	DeliveryID, Token string
	Generation        int64
}
type ResponseWebhookRead struct {
	Authority                  ResponseWebhookAuthority
	AgentID, RunID, DeliveryID string
}
type ResponseWebhookStatus struct {
	DeliveryID                    string     `json:"delivery_id"`
	RunID                         string     `json:"run_id"`
	StepID                        string     `json:"step_id"`
	DestinationIntegrationID      string     `json:"destination_integration_id"`
	DestinationIntegrationVersion int64      `json:"destination_integration_version"`
	PayloadDigest                 string     `json:"payload_digest"`
	SelectionDigest               string     `json:"selection_digest"`
	SigningVersion                string     `json:"signing_version"`
	State                         string     `json:"state"`
	ErrorCode                     string     `json:"error_code"`
	AcknowledgedAt                *time.Time `json:"acknowledged_at"`
	ReceiverVerification          string     `json:"receiver_verification"`
}
type ResponseWebhookClaim struct {
	Scope                                           ResponseWebhookScope
	DeliveryID, Token                               string
	Generation                                      int64
	ExpiresAt                                       time.Time
	DestinationURL, SecretReference, SigningVersion string
	Payload                                         []byte
	PayloadDigest, SelectionDigest, RunID, StepID   string
}
type ResponseWebhookSettlementClaim struct {
	Scope                            ResponseWebhookScope
	DeliveryID, RunID, StepID, Token string
	Generation                       int64
	ExpiresAt                        time.Time
	State                            string
}
type ResponseWebhookSettlementResult struct {
	DeliveryID    string `json:"delivery_id"`
	RunID         string `json:"run_id"`
	StepID        string `json:"step_id"`
	State         string `json:"state"`
	DeliveryState string `json:"delivery_state"`
	OutcomeID     string `json:"outcome_id"`
	Reason        string `json:"reason"`
}
type ResponseWebhookRepository interface {
	AcceptAndPrepareResponseWebhook(context.Context, ResponseWebhookAcceptance) (ResponseWebhookStatus, error)
	ClaimResponseWebhook(context.Context) (ResponseWebhookClaim, bool, error)
	BeginResponseWebhookDispatch(context.Context, ResponseWebhookFence) error
	CompleteResponseWebhook(context.Context, ResponseWebhookFence, securityagent.ResponseWebhookReceipt) (ResponseWebhookStatus, error)
	ExpireResponseWebhooks(context.Context, int) (int, error)
	ClaimResponseWebhookSettlements(context.Context, string, string, int, int) ([]ResponseWebhookSettlementClaim, error)
	SettleResponseWebhookParent(context.Context, ResponseWebhookSettlementClaim, string, string, string, string) (ResponseWebhookSettlementResult, error)
	GetResponseWebhook(context.Context, ResponseWebhookRead) (ResponseWebhookStatus, error)
}

type SecurityAgentWebhooksRepository struct{ database JSONDatabase }

func validResponseWebhookDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validExistingTestPublicDigest(strings.TrimPrefix(value, "sha256:"))
}

var _ ResponseWebhookRepository = (*SecurityAgentWebhooksRepository)(nil)

func NewSecurityAgentWebhooksRepository(db JSONDatabase) (*SecurityAgentWebhooksRepository, error) {
	if nilInterface(db) {
		return nil, ErrRepositoryUnavailable
	}
	return &SecurityAgentWebhooksRepository{database: db}, nil
}
func validResponseWebhookScope(s ResponseWebhookScope) bool {
	return validProductID(s.OrganizationID) && validProductID(s.WorkspaceID) && validProductID(s.EnvironmentID)
}
func validResponseWebhookFence(f ResponseWebhookFence) bool {
	return validResponseWebhookScope(f.Scope) && validProductID(f.DeliveryID) && validSecurityAgentText(f.Token, 128) && len(f.Token) >= 16 && f.Generation > 0 && f.Generation <= 3
}
func (r *SecurityAgentWebhooksRepository) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, sql, args...)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	if ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	return raw, nil
}

func (r *SecurityAgentWebhooksRepository) AcceptAndPrepareResponseWebhook(ctx context.Context, a ResponseWebhookAcceptance) (ResponseWebhookStatus, error) {
	fail := ResponseWebhookStatus{}
	input, inputOK := decodeSecurityAgentDigest(a.Submission.InputDigest)
	output, outputOK := decodeSecurityAgentDigest(a.Submission.OutputDigest)
	if !validSecurityAgentRunClaim(a.Claim) || a.Claim.Prepared || !validSecurityAgentWorkerIdentity(a.WorkerID, a.LeaseToken) || !inputOK || !outputOK || !validSecurityAgentText(a.Submission.Model, 128) || !validSecurityAgentText(a.Submission.PolicyVersion, 64) || !validSecurityAgentText(a.Submission.Summary, 500) || a.Submission.Action != "send_response_webhook" || a.Submission.TargetID != a.DestinationID || !validProductID(a.DestinationID) || a.Submission.EvidenceIDs != nil || !validProductID(a.ApprovalID) || !validProductID(a.AuditID) || !validProductID(a.CorrelationID) || !validPublicIdempotency(a.IdempotencyKey) || a.ApprovalExpiresAt.IsZero() || a.ApprovalExpiresAt.Location() != time.UTC {
		return fail, ErrRepositoryOperation
	}
	// The domain encoder validates the selection's closed canonical grammar. The
	// actual immutable delivery/step/plan identities are derived only by SQL.
	_, _, err := securityagent.EncodeResponseWebhookPayload(securityagent.ResponseWebhookPayload{SchemaVersion: 1, Type: "security_agent.response", DeliveryID: a.Claim.RunID, OrganizationID: a.Claim.OrganizationID, WorkspaceID: a.Claim.WorkspaceID, EnvironmentID: a.Claim.EnvironmentID, RunID: a.Claim.RunID, StepID: a.Claim.RunID, PlanHash: a.Submission.InputDigest, Evidence: a.Evidence})
	if err != nil {
		return fail, ErrRepositoryOperation
	}
	evidence, err := json.Marshal(a.Evidence)
	if err != nil {
		return fail, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_accept_security_agent_webhook_plan($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, a.Claim.OrganizationID, a.Claim.WorkspaceID, a.Claim.EnvironmentID, a.Claim.RunID, a.WorkerID, a.LeaseToken, a.Claim.Attempt, a.Claim.DefinitionID, a.Claim.DefinitionVersion, input, output, a.Submission.Model, a.Submission.PolicyVersion, a.Submission.Summary, a.Submission.Action, a.Submission.TargetID, a.ApprovalID, a.ApprovalExpiresAt, a.AuditID, a.CorrelationID, a.IdempotencyKey, a.DestinationID, json.RawMessage(evidence))
	if err != nil {
		return fail, err
	}
	result, err := decodeResponseWebhookStatus(raw)
	if err != nil || result.RunID != a.Claim.RunID || result.DestinationIntegrationID != a.DestinationID {
		return fail, ErrRepositoryUnavailable
	}
	return result, nil
}

func decodeResponseWebhookStatus(raw json.RawMessage) (ResponseWebhookStatus, error) {
	fail := ResponseWebhookStatus{}
	fields, err := auditExportClosedObject(raw, 4096, "delivery_id", "run_id", "step_id", "destination_integration_id", "destination_integration_version", "payload_digest", "selection_digest", "signing_version", "state", "error_code", "acknowledged_at", "receiver_verification")
	var v ResponseWebhookStatus
	if err != nil || decodeStrictDiscovery(raw, &v) != nil || !validProductID(v.DeliveryID) || !validProductID(v.RunID) || !validProductID(v.StepID) || !validProductID(v.DestinationIntegrationID) || v.DestinationIntegrationVersion < 1 || v.DestinationIntegrationVersion > 1000000 || !validResponseWebhookDigest(v.PayloadDigest) || !validResponseWebhookDigest(v.SelectionDigest) || !validResponseWebhookSigningVersion(v.SigningVersion) || !stringIn(v.State, "prepared", "leased", "dispatching", "acknowledged", "failed", "uncertain", "cancelled") || !stringIn(v.ErrorCode, "", "invalid_request", "response_rejected", "delivery_uncertain", "secret_unavailable", "authority_changed", "claim_exhausted") || v.ReceiverVerification != "unproven" || string(fields["error_code"]) == "null" || (v.State == "acknowledged") != (v.AcknowledgedAt != nil) || v.AcknowledgedAt != nil && v.AcknowledgedAt.IsZero() {
		return fail, ErrRepositoryUnavailable
	}
	validState := stringIn(v.State, "prepared", "leased", "dispatching", "acknowledged") && v.ErrorCode == "" || v.State == "uncertain" && v.ErrorCode == "delivery_uncertain" || v.State == "cancelled" && v.ErrorCode == "authority_changed" || v.State == "failed" && stringIn(v.ErrorCode, "invalid_request", "response_rejected", "secret_unavailable", "claim_exhausted")
	if !validState {
		return fail, ErrRepositoryUnavailable
	}
	return v, nil
}

func (r *SecurityAgentWebhooksRepository) GetResponseWebhook(ctx context.Context, q ResponseWebhookRead) (ResponseWebhookStatus, error) {
	fail := ResponseWebhookStatus{}
	a := q.Authority
	if !validResponseWebhookScope(a.Scope) || !validProductID(a.PrincipalID) || !validSecurityAgentText(a.SessionID, 4096) || len(a.SessionID) < 32 || !validProductID(q.AgentID) || !validProductID(q.RunID) || !validProductID(q.DeliveryID) {
		return fail, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_get_security_agent_webhook($1,$2,$3,$4,$5,$6,$7,$8)`, a.Scope.OrganizationID, a.Scope.WorkspaceID, a.Scope.EnvironmentID, a.PrincipalID, a.SessionID, q.AgentID, q.RunID, q.DeliveryID)
	if err != nil {
		return fail, err
	}
	v, err := decodeResponseWebhookStatus(raw)
	if err != nil || v.DeliveryID != q.DeliveryID || v.RunID != q.RunID {
		return fail, ErrRepositoryUnavailable
	}
	return v, nil
}

func (r *SecurityAgentWebhooksRepository) ClaimResponseWebhook(ctx context.Context) (ResponseWebhookClaim, bool, error) {
	fail := ResponseWebhookClaim{}
	raw, err := r.query(ctx, `SELECT public.zasp_claim_security_agent_webhook()`)
	if err != nil {
		return fail, false, err
	}
	if string(raw) == "null" {
		return fail, false, nil
	}
	var v struct {
		ResponseWebhookScope
		DeliveryID      string    `json:"delivery_id"`
		Token           string    `json:"token"`
		Generation      int64     `json:"generation"`
		ExpiresAt       time.Time `json:"expires_at"`
		DestinationURL  string    `json:"destination_url"`
		SecretReference string    `json:"secret_reference"`
		SigningVersion  string    `json:"signing_version"`
		Payload         string    `json:"payload"`
		PayloadDigest   string    `json:"payload_digest"`
		SelectionDigest string    `json:"selection_digest"`
		RunID           string    `json:"run_id"`
		StepID          string    `json:"step_id"`
	}
	_, err = auditExportClosedObject(raw, 32768, "organization_id", "workspace_id", "environment_id", "delivery_id", "token", "generation", "expires_at", "destination_url", "secret_reference", "signing_version", "payload", "payload_digest", "selection_digest", "run_id", "step_id")
	if err != nil || decodeStrictDiscovery(raw, &v) != nil || !validResponseWebhookFence(ResponseWebhookFence{v.ResponseWebhookScope, v.DeliveryID, v.Token, v.Generation}) || !v.ExpiresAt.After(time.Now()) || !validIntegrationWebhookDestination(v.DestinationURL) || !validIntegrationWebhookSecretReference(v.SecretReference) || !validResponseWebhookSigningVersion(v.SigningVersion) || !validResponseWebhookDigest(v.SelectionDigest) {
		return fail, false, ErrRepositoryUnavailable
	}
	var payload securityagent.ResponseWebhookPayload
	if _, err = auditExportClosedObject(json.RawMessage(v.Payload), 16384, "schema_version", "type", "delivery_id", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "plan_hash", "evidence"); err != nil || decodeStrictDiscovery(json.RawMessage(v.Payload), &payload) != nil {
		return fail, false, ErrRepositoryUnavailable
	}
	canonical, digest, err := securityagent.EncodeResponseWebhookPayload(payload)
	selection, selectionErr := json.Marshal(payload.Evidence)
	if err != nil || selectionErr != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(selection)) != v.SelectionDigest || !bytes.Equal(canonical, []byte(v.Payload)) || digest != v.PayloadDigest || payload.DeliveryID != v.DeliveryID || payload.RunID != v.RunID || payload.StepID != v.StepID || payload.OrganizationID != v.OrganizationID || payload.WorkspaceID != v.WorkspaceID || payload.EnvironmentID != v.EnvironmentID {
		return fail, false, ErrRepositoryUnavailable
	}
	return ResponseWebhookClaim{Scope: v.ResponseWebhookScope, DeliveryID: v.DeliveryID, Token: v.Token, Generation: v.Generation, ExpiresAt: v.ExpiresAt, DestinationURL: v.DestinationURL, SecretReference: v.SecretReference, SigningVersion: v.SigningVersion, Payload: bytes.Clone(canonical), PayloadDigest: v.PayloadDigest, SelectionDigest: v.SelectionDigest, RunID: v.RunID, StepID: v.StepID}, true, nil
}

func (r *SecurityAgentWebhooksRepository) BeginResponseWebhookDispatch(ctx context.Context, f ResponseWebhookFence) error {
	if !validResponseWebhookFence(f) {
		return ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_begin_security_agent_webhook_dispatch($1,$2,$3,$4,$5,$6)`, f.Scope.OrganizationID, f.Scope.WorkspaceID, f.Scope.EnvironmentID, f.DeliveryID, f.Token, f.Generation)
	if err != nil {
		return err
	}
	fields, err := auditExportClosedObject(raw, 1024, "begun")
	if err != nil || string(fields["begun"]) != "true" {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (r *SecurityAgentWebhooksRepository) CompleteResponseWebhook(ctx context.Context, f ResponseWebhookFence, receipt securityagent.ResponseWebhookReceipt) (ResponseWebhookStatus, error) {
	fail := ResponseWebhookStatus{}
	if !validResponseWebhookFence(f) || !(receipt.Outcome == "acknowledged" && receipt.ErrorCode == "" || receipt.Outcome == "failed" && stringIn(receipt.ErrorCode, "invalid_request", "response_rejected", "secret_unavailable") || receipt.Outcome == "uncertain" && receipt.ErrorCode == "delivery_uncertain") {
		return fail, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_complete_security_agent_webhook($1,$2,$3,$4,$5,$6,$7,$8)`, f.Scope.OrganizationID, f.Scope.WorkspaceID, f.Scope.EnvironmentID, f.DeliveryID, f.Token, f.Generation, receipt.Outcome, receipt.ErrorCode)
	if err != nil {
		return fail, err
	}
	v, err := decodeResponseWebhookStatus(raw)
	if err != nil || v.DeliveryID != f.DeliveryID || v.State != receipt.Outcome || v.ErrorCode != receipt.ErrorCode {
		return fail, ErrRepositoryUnavailable
	}
	return v, nil
}
func (r *SecurityAgentWebhooksRepository) ExpireResponseWebhooks(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 100 {
		return 0, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_expire_security_agent_webhooks($1)`, limit)
	if err != nil {
		return 0, err
	}
	fields, err := auditExportClosedObject(raw, 1024, "expired")
	var n int
	if err != nil || string(fields["expired"]) == "null" || json.Unmarshal(fields["expired"], &n) != nil || n < 0 || n > limit {
		return 0, ErrRepositoryUnavailable
	}
	return n, nil
}
func (r *SecurityAgentWebhooksRepository) ClaimResponseWebhookSettlements(ctx context.Context, worker, token string, seconds, limit int) ([]ResponseWebhookSettlementClaim, error) {
	if !validSecurityAgentWorkerIdentity(worker, token) || seconds < 1 || seconds > 120 || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements($1,$2,$3,$4)`, worker, token, seconds, limit)
	if err != nil {
		return nil, err
	}
	fields, err := auditExportClosedObject(raw, 32768, "claims")
	var items []json.RawMessage
	if err != nil || json.Unmarshal(fields["claims"], &items) != nil || items == nil || len(items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	result := make([]ResponseWebhookSettlementClaim, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		var v struct {
			ResponseWebhookScope
			DeliveryID string    `json:"delivery_id"`
			RunID      string    `json:"run_id"`
			StepID     string    `json:"step_id"`
			Token      string    `json:"token"`
			Generation int64     `json:"generation"`
			ExpiresAt  time.Time `json:"expires_at"`
			State      string    `json:"state"`
		}
		_, err := auditExportClosedObject(item, 4096, "organization_id", "workspace_id", "environment_id", "delivery_id", "run_id", "step_id", "token", "generation", "expires_at", "state")
		if err != nil || decodeStrictDiscovery(item, &v) != nil || !validResponseWebhookScope(v.ResponseWebhookScope) || !validProductID(v.DeliveryID) || !validProductID(v.RunID) || !validProductID(v.StepID) || v.Token != token || v.Generation < 1 || !v.ExpiresAt.After(time.Now()) || !stringIn(v.State, "acknowledged", "failed", "uncertain", "cancelled") || seen[v.DeliveryID] {
			return nil, ErrRepositoryUnavailable
		}
		seen[v.DeliveryID] = true
		result = append(result, ResponseWebhookSettlementClaim{v.ResponseWebhookScope, v.DeliveryID, v.RunID, v.StepID, v.Token, v.Generation, v.ExpiresAt, v.State})
	}
	return result, nil
}
func (r *SecurityAgentWebhooksRepository) SettleResponseWebhookParent(ctx context.Context, c ResponseWebhookSettlementClaim, worker, audit, correlation, outcome string) (ResponseWebhookSettlementResult, error) {
	fail := ResponseWebhookSettlementResult{}
	if !validResponseWebhookScope(c.Scope) || !validProductID(c.DeliveryID) || !validProductID(c.RunID) || !validProductID(c.StepID) || !validSecurityAgentWorkerIdentity(worker, c.Token) || c.Generation < 1 || !validProductID(audit) || !validProductID(correlation) || !validProductID(outcome) || !stringIn(c.State, "acknowledged", "failed", "uncertain", "cancelled") {
		return fail, ErrRepositoryOperation
	}
	raw, err := r.query(ctx, `SELECT public.zasp_settle_security_agent_webhook_parent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.Scope.OrganizationID, c.Scope.WorkspaceID, c.Scope.EnvironmentID, c.DeliveryID, c.Token, c.Generation, worker, audit, correlation, outcome)
	if err != nil {
		return fail, err
	}
	_, err = auditExportClosedObject(raw, 4096, "delivery_id", "run_id", "step_id", "state", "delivery_state", "outcome_id", "reason")
	var v ResponseWebhookSettlementResult
	if err != nil || decodeStrictDiscovery(raw, &v) != nil || v.DeliveryID != c.DeliveryID || v.RunID != c.RunID || v.StepID != c.StepID || v.DeliveryState != c.State || !validProductID(v.OutcomeID) {
		return fail, ErrRepositoryUnavailable
	}
	valid := v.State == "cancelled" && v.Reason == "webhook_parent_cancelled" || v.DeliveryState == "acknowledged" && v.State == "needs_human" && v.Reason == "webhook_handoff_acknowledged" || v.DeliveryState == "uncertain" && v.State == "needs_human" && v.Reason == "webhook_delivery_uncertain" || v.DeliveryState == "failed" && v.State == "failed" && v.Reason == "webhook_delivery_failed" || v.DeliveryState == "cancelled" && v.State == "cancelled" && v.Reason == "webhook_delivery_cancelled"
	valid = valid || v.DeliveryState == "cancelled" && stringIn(v.State, "contained", "remediated", "failed", "inconclusive", "needs_human", "simulated") && v.Reason == "webhook_parent_outcome_preserved"
	if !valid {
		return fail, ErrRepositoryUnavailable
	}
	return v, nil
}
