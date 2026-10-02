package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// ErrSecurityAgentNotOwned is the only result permitting a later router to
// consider legacy authority. No error from classification or lifecycle does so.
var ErrSecurityAgentNotOwned = errors.New("security agent resource not owned")

type SecurityAgentMutationKind string

const (
	SecurityAgentMutationActivate SecurityAgentMutationKind = "activate"
	SecurityAgentMutationTrigger  SecurityAgentMutationKind = "trigger"
)

// Only the immutable trigger fields needed to derive its canonical run. This
// is not a caller-supplied run ID, receipt ID, or execution permission.
type SecurityAgentMutationTriggerIdentity struct {
	TriggerID      string `json:"trigger_id"`
	TriggerVersion int64  `json:"trigger_version"`
}

// ResolveMutation classifies immutable receipt ownership, not permission to
// execute. It accepts bearer identities for classification only. The requested
// definition may differ from retained intent: the mutation must then conflict.
func (r *SecurityAgentOwnershipResolver) ResolveMutation(ctx context.Context, id RequestIdentity, kind SecurityAgentMutationKind, definition, key string, trigger *SecurityAgentMutationTriggerIdentity) (SecurityAgentFamily, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || (id.CredentialKind != CredentialBrowserSession && id.CredentialKind != CredentialBearerToken) || !validRequestIdentity(id, id.CredentialKind == CredentialBrowserSession) || !public62ID(definition) || !securityAgentPublicIdempotency.MatchString(key) || (kind != SecurityAgentMutationActivate && kind != SecurityAgentMutationTrigger) {
		return "", ErrRepositoryOperation
	}
	if kind == SecurityAgentMutationActivate && trigger != nil || kind == SecurityAgentMutationTrigger && (trigger == nil || !public62ID(trigger.TriggerID) || !public62Version(trigger.TriggerVersion)) {
		return "", ErrRepositoryOperation
	}
	q := map[string]any{"operation": "classify_mutation", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "mutation_kind": kind, "definition_id": definition, "idempotency_key": key}
	if trigger != nil {
		q["trigger"] = trigger
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return "", ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(raw))
	if err != nil {
		return "", public62ProviderError(err, "classify_mutation")
	}
	var v struct {
		ContractVersion int                                   `json:"contract_version"`
		Kind            SecurityAgentMutationKind             `json:"mutation_kind"`
		DefinitionID    string                                `json:"definition_id"`
		IdempotencyKey  string                                `json:"idempotency_key"`
		Family          SecurityAgentFamily                   `json:"family"`
		Trigger         *SecurityAgentMutationTriggerIdentity `json:"trigger"`
	}
	if bounded.Err() != nil || len(response) > 1024 || public62Decode(response, &v) != nil || v.ContractVersion != 62 || v.Kind != kind || v.DefinitionID != definition || v.IdempotencyKey != key || (v.Family != SecurityAgentFamilyOrderedRelease61 && v.Family != SecurityAgentFamilyLegacyOrMissing) {
		return "", ErrRepositoryUnavailable
	}
	if (v.Trigger == nil) != (trigger == nil) || trigger != nil && *v.Trigger != *trigger {
		return "", ErrRepositoryUnavailable
	}
	return v.Family, nil
}

// SecurityAgentOrderedResourceAuthority is dormant: no route or default
// composition constructs it. It has no reference to any legacy repository.
type SecurityAgentOrderedResourceAuthority struct {
	resolver   *SecurityAgentOwnershipResolver
	repository *SecurityAgentPublicRepository
}
type SecurityAgentOrderedActivation struct {
	DefinitionID   string
	Version        int64
	Activation     string
	IdempotencyKey string
}
type SecurityAgentOrderedTrigger struct {
	SecurityAgentPublicTrigger
	TriggerKind   string
	TriggerSource string
}
type SecurityAgentOrderedDecision struct {
	ApprovalID     string
	Version        int64
	Decision       string
	IdempotencyKey string
}
type SecurityAgentOrderedRunResource struct {
	Detail    SecurityAgentRunDetail
	Steps     []SecurityAgentPublicStep
	CreatedAt time.Time
}
type SecurityAgentOrderedApprovalResource struct {
	Approval   SecurityAgentApproval
	RunVersion int64
	CreatedAt  time.Time
}
type SecurityAgentOrderedCancellationResult struct {
	Result          SecurityAgentRunResult
	CleanupRequired bool
}

func NewSecurityAgentOrderedResourceAuthority(db JSONDatabase) (*SecurityAgentOrderedResourceAuthority, error) {
	r, err := NewSecurityAgentPublicRepository(db)
	if err != nil {
		return nil, err
	}
	resolver, err := NewSecurityAgentOwnershipResolver(db)
	if err != nil {
		return nil, err
	}
	return &SecurityAgentOrderedResourceAuthority{resolver, r}, nil
}
func (a *SecurityAgentOrderedResourceAuthority) own(ctx context.Context, id RequestIdentity, kind SecurityAgentResourceKind, resource string) error {
	if a == nil || a.resolver == nil || a.repository == nil {
		return ErrRepositoryOperation
	}
	family, err := a.resolver.Resolve(ctx, id, kind, resource)
	if err != nil {
		return err
	}
	if family == SecurityAgentFamilyLegacyOrMissing {
		return ErrSecurityAgentNotOwned
	}
	// Classification is the only ordered SQL that a bearer may reach.
	if id.CredentialKind != CredentialBrowserSession {
		return ErrRepositoryOperation
	}
	return nil
}

func (a *SecurityAgentOrderedResourceAuthority) ownMutation(ctx context.Context, id RequestIdentity, kind SecurityAgentMutationKind, definition, key string, trigger *SecurityAgentMutationTriggerIdentity) error {
	if a == nil || a.resolver == nil || a.repository == nil {
		return ErrRepositoryOperation
	}
	family, err := a.resolver.ResolveMutation(ctx, id, kind, definition, key, trigger)
	if err != nil {
		return err
	}
	if family == SecurityAgentFamilyLegacyOrMissing {
		return ErrSecurityAgentNotOwned
	}
	if id.CredentialKind != CredentialBrowserSession {
		return ErrRepositoryOperation
	}
	return nil
}

func (a *SecurityAgentOrderedResourceAuthority) GetActivation(ctx context.Context, id RequestIdentity, definition string) (SecurityAgentActivationState, error) {
	var zero SecurityAgentActivationState
	if err := a.own(ctx, id, SecurityAgentResourceDefinition, definition); err != nil {
		return zero, err
	}
	raw, err := a.repository.invoke(ctx, id, "resource_activation", map[string]any{"definition_id": definition})
	if err != nil {
		return zero, err
	}
	var v struct {
		ContractVersion int    `json:"contract_version"`
		ID              string `json:"id"`
		Activation      string `json:"activation"`
		Enabled         bool   `json:"enabled"`
		Version         int64  `json:"version"`
	}
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.ID != definition || !public62Version(v.Version) || !public62OneOf(v.Activation, "draft", "supervised") || v.Enabled != (v.Activation == "supervised") {
		return zero, ErrRepositoryUnavailable
	}
	return SecurityAgentActivationState{ID: v.ID, Activation: v.Activation, Enabled: v.Enabled, Version: v.Version}, nil
}
func (a *SecurityAgentOrderedResourceAuthority) Activate(ctx context.Context, id RequestIdentity, q SecurityAgentOrderedActivation) (SecurityAgentActivationResult, error) {
	var zero SecurityAgentActivationResult
	if !public62MutationVersion(q.Version) || q.Activation != "supervised" || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	if err := a.ownMutation(ctx, id, SecurityAgentMutationActivate, q.DefinitionID, q.IdempotencyKey, nil); err != nil {
		return zero, err
	}
	raw, err := a.repository.invoke(ctx, id, "activate_resource", map[string]any{"definition_id": q.DefinitionID, "definition_version": q.Version, "activation": q.Activation, "idempotency_key": q.IdempotencyKey})
	if err != nil {
		return zero, err
	}
	var v struct {
		ContractVersion int    `json:"contract_version"`
		ID              string `json:"id"`
		Activation      string `json:"activation"`
		Enabled         bool   `json:"enabled"`
		Version         int64  `json:"version"`
		AuditID         string `json:"audit_id"`
		CorrelationID   string `json:"correlation_id"`
		ReceiptID       string `json:"receipt_id"`
		Replayed        bool   `json:"replayed"`
	}
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.ID != q.DefinitionID || v.Activation != "supervised" || !v.Enabled || v.Version != q.Version+1 || v.CorrelationID != v.AuditID || !public62MutationIdentity(id, "activate_resource", q.IdempotencyKey, v.AuditID, v.ReceiptID) {
		return zero, ErrRepositoryUnavailable
	}
	return SecurityAgentActivationResult{ID: v.ID, Activation: v.Activation, Enabled: v.Enabled, Version: v.Version, AuditID: v.AuditID, CorrelationID: v.CorrelationID, ReceiptID: v.ReceiptID, Replayed: v.Replayed}, nil
}

func (a *SecurityAgentOrderedResourceAuthority) Trigger(ctx context.Context, id RequestIdentity, q SecurityAgentOrderedTrigger) (SecurityAgentRunResult, error) {
	var zero SecurityAgentRunResult
	if !public62ID(q.TriggerID) || !public62Version(q.DefinitionVersion) || !public62Version(q.TriggerVersion) || !public62OneOf(q.TriggerKind, "finding", "attack_path") || !validSecurityAgentText(q.TriggerSource, 128) || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	if err := a.ownMutation(ctx, id, SecurityAgentMutationTrigger, q.DefinitionID, q.IdempotencyKey, &SecurityAgentMutationTriggerIdentity{q.TriggerID, q.TriggerVersion}); err != nil {
		return zero, err
	}
	raw, err := a.repository.invoke(ctx, id, "trigger_resource", map[string]any{"definition_id": q.DefinitionID, "definition_version": q.DefinitionVersion, "trigger_id": q.TriggerID, "trigger_version": q.TriggerVersion, "trigger_kind": q.TriggerKind, "trigger_source": q.TriggerSource, "idempotency_key": q.IdempotencyKey})
	if err != nil {
		return zero, err
	}
	var v struct {
		ContractVersion   int      `json:"contract_version"`
		ID                string   `json:"id"`
		AgentID           string   `json:"agent_id"`
		State             string   `json:"state"`
		EvidenceIDs       []string `json:"evidence_ids"`
		DefinitionVersion int64    `json:"definition_version"`
		Version           int64    `json:"version"`
		AuditID           string   `json:"audit_id"`
		CorrelationID     string   `json:"correlation_id"`
		ReceiptID         string   `json:"receipt_id"`
		Replayed          bool     `json:"replayed"`
	}
	run, _ := CanonicalDiscoveryID(id.Scope, "security_agent_run", q.DefinitionID+"\x1f"+q.TriggerID+"\x1f"+strconv.FormatInt(q.TriggerVersion, 10))
	audit, _ := CanonicalDiscoveryID(id.Scope, "public62_trigger", run)
	receipt, _ := CanonicalDiscoveryID(id.Scope, "public62_receipt", id.PrincipalID.String()+"\x1f"+q.IdempotencyKey)
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.ID != run || v.AgentID != q.DefinitionID || v.DefinitionVersion != q.DefinitionVersion || v.State != "queued" || v.Version != 1 || len(v.EvidenceIDs) != 1 || v.EvidenceIDs[0] != q.TriggerID || v.AuditID != audit || v.CorrelationID != audit || v.ReceiptID != receipt {
		return zero, ErrRepositoryUnavailable
	}
	return SecurityAgentRunResult{ID: v.ID, AgentID: v.AgentID, State: v.State, EvidenceIDs: v.EvidenceIDs, DefinitionVersion: v.DefinitionVersion, Version: v.Version, AuditID: v.AuditID, CorrelationID: v.CorrelationID, ReceiptID: v.ReceiptID, Replayed: v.Replayed}, nil
}

type orderedResourcePlan struct {
	PlanHash       string `json:"plan_hash"`
	CatalogVersion string `json:"catalog_version"`
	ExpiresAt      string `json:"expires_at"`
}
type orderedResourceApproval struct {
	ID             string `json:"id"`
	RunID          string `json:"run_id"`
	StepID         string `json:"step_id"`
	State          string `json:"state"`
	Version        int64  `json:"version"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
	ExpectedEffect string `json:"expected_effect"`
	Reversible     bool   `json:"reversible"`
	TTLSeconds     int    `json:"ttl_seconds"`
}
type orderedResourceWire struct {
	ContractVersion int                       `json:"contract_version"`
	Ordered         SecurityAgentPublicRun    `json:"ordered"`
	TriggerID       string                    `json:"trigger_id"`
	CreatedAt       string                    `json:"created_at"`
	Plan            *orderedResourcePlan      `json:"plan"`
	Approvals       []orderedResourceApproval `json:"approvals"`
}

var orderedResourceTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

func orderedResourceTime(s string) (time.Time, bool) {
	v, err := time.Parse(time.RFC3339Nano, s)
	return v, err == nil && orderedResourceTimestamp.MatchString(s) && v.Location() == time.UTC && v.Year() >= 2000 && v.Year() <= 9999
}
func orderedResourceProjection(v orderedResourceWire, id RequestIdentity) (SecurityAgentOrderedRunResource, bool) {
	var zero SecurityAgentOrderedRunResource
	created, ok := orderedResourceTime(v.CreatedAt)
	r := v.Ordered
	if !ok || created.After(time.Now().Add(5*time.Second)) || v.ContractVersion != 62 || !public62ID(v.TriggerID) || !public62ValidRun(r, id) || (v.Plan != nil) != r.Admitted || len(v.Approvals) > 2 {
		return zero, false
	}
	detail := SecurityAgentRunDetail{Run: SecurityAgentRun{ID: r.RunID, AgentID: r.DefinitionID, State: r.State, EvidenceIDs: []string{v.TriggerID}, DefinitionVersion: r.DefinitionVersion, Version: r.Version}, EvidenceIDs: []string{v.TriggerID}, Authorization: "not_planned", Approvals: []SecurityAgentApproval{}, Execution: []SecurityAgentExecutionStep{}, Verification: "not_started"}
	if r.Admitted {
		expiry, valid := orderedResourceTime(v.Plan.ExpiresAt)
		if !valid || !expiry.After(created) || !public62Digest.MatchString(v.Plan.PlanHash) || v.Plan.CatalogVersion != "security-agent-actions-v1" {
			return zero, false
		}
		detail.Plan = &SecurityAgentPlanSummary{PlanHash: v.Plan.PlanHash, CatalogVersion: v.Plan.CatalogVersion, ExpiresAt: expiry, Steps: []SecurityAgentPlanStep{}}
		detail.Authorization = "approval_required"
		detail.Verification = "pending"
		cursor := 0
		for _, s := range r.Steps {
			state := s.State
			if state == "blocked" {
				state = "queued"
			} // Stored queued state; dependency remains explicit in Steps.
			detail.Plan.Steps = append(detail.Plan.Steps, SecurityAgentPlanStep{ID: s.StepID, Index: s.Index, Action: s.Action, Authorization: s.Authorization, State: state, Version: s.Version})
			execution := SecurityAgentExecutionStep{StepID: s.StepID, Action: s.Action, State: state, Version: s.Version}
			// A safe receipt reference is not an effect outcome ID; never relabel it.
			if s.Receipt != nil {
				execution.ResultDigest = s.Receipt.Digest
			}
			detail.Execution = append(detail.Execution, execution)
			if s.Approval.ApprovalID == nil {
				continue
			}
			if cursor >= len(v.Approvals) {
				return zero, false
			}
			a := v.Approvals[cursor]
			cursor++
			expires, validExpiry := orderedResourceTime(a.ExpiresAt)
			ac, validCreated := orderedResourceTime(a.CreatedAt)
			if a.ID != *s.Approval.ApprovalID || a.RunID != r.RunID || a.StepID != s.StepID || a.State != s.Approval.State || a.Version != s.Approval.Version || !validExpiry || !expires.Equal(expiry) || !validCreated || ac.Before(created) || ac.After(time.Now().Add(5*time.Second)) {
				return zero, false
			}
			if s.Index == 0 && (a.ExpectedEffect != "Apply temporary containment policy" || !a.Reversible || a.TTLSeconds < 60 || a.TTLSeconds > 3600) || s.Index == 1 && (a.ExpectedEffect != "Run existing test" || a.Reversible || a.TTLSeconds != 0) {
				return zero, false
			}
			detail.Approvals = append(detail.Approvals, SecurityAgentApproval{ID: a.ID, RunID: a.RunID, StepID: a.StepID, State: a.State, ExpiresAt: expires, Version: a.Version, ExpectedEffect: a.ExpectedEffect, Reversible: a.Reversible, TTLSeconds: a.TTLSeconds, EvidenceSummary: []string{v.TriggerID}})
		}
		if cursor != len(v.Approvals) {
			return zero, false
		}
	} else if len(v.Approvals) != 0 {
		return zero, false
	}
	if public62Terminal(r.State) {
		switch r.State {
		case "contained", "remediated":
			detail.Verification = "verified"
		case "failed":
			detail.Verification = "failed"
		default:
			detail.Verification = "inconclusive"
		}
		if r.Admitted && r.State == "cancelled" {
			detail.Authorization = "cancelled"
		}
	}
	if !orderedResourceDetailMatches(detail, v) {
		return zero, false
	}
	return SecurityAgentOrderedRunResource{Detail: detail, Steps: r.Steps, CreatedAt: created}, true
}

// The closed wire and exact-pair checks above are the ordered authority. Bind
// every legacy-shaped DTO field to that validated wire, without depending on
// the generic legacy validator (which does not support run_test approvals).
// HTTP routing must explicitly adopt ordered validation in a later packet.
func orderedResourceDetailMatches(d SecurityAgentRunDetail, v orderedResourceWire) bool {
	r := v.Ordered
	evidence := func(ids []string) bool { return len(ids) == 1 && ids[0] == v.TriggerID }
	if d.Run.ID != r.RunID || d.Run.AgentID != r.DefinitionID || d.Run.State != r.State || d.Run.DefinitionVersion != r.DefinitionVersion || d.Run.Version != r.Version || !evidence(d.Run.EvidenceIDs) || !evidence(d.EvidenceIDs) || len(d.Approvals) != len(v.Approvals) {
		return false
	}
	authorization, verification := "not_planned", "not_started"
	if r.Admitted {
		authorization, verification = "approval_required", "pending"
		if r.State == "cancelled" {
			authorization = "cancelled"
		}
	}
	if public62Terminal(r.State) {
		verification = "inconclusive"
		if r.State == "contained" || r.State == "remediated" {
			verification = "verified"
		} else if r.State == "failed" {
			verification = "failed"
		}
	}
	if d.Authorization != authorization || d.Verification != verification {
		return false
	}
	if !r.Admitted {
		return d.Plan == nil && len(d.Approvals) == 0 && len(d.Execution) == 0
	}
	if v.Plan == nil || d.Plan == nil || len(r.Steps) != 2 || len(d.Plan.Steps) != 2 || len(d.Execution) != 2 || d.Plan.PlanHash != v.Plan.PlanHash || d.Plan.CatalogVersion != v.Plan.CatalogVersion {
		return false
	}
	expiry, valid := orderedResourceTime(v.Plan.ExpiresAt)
	if !valid || d.Plan.ExpiresAt.Location() != time.UTC || !d.Plan.ExpiresAt.Equal(expiry) {
		return false
	}
	for i, s := range r.Steps {
		p, x := d.Plan.Steps[i], d.Execution[i]
		state, digest := s.State, ""
		if state == "blocked" {
			state = "queued"
		}
		if s.Receipt != nil {
			digest = s.Receipt.Digest
		}
		if p.ID != s.StepID || p.Index != i || p.Action != s.Action || p.Authorization != s.Authorization || p.State != state || p.Version != s.Version || x.StepID != s.StepID || x.Action != s.Action || x.State != state || x.Version != s.Version || x.OutcomeID != "" || x.ResultDigest != digest {
			return false
		}
	}
	for i, a := range v.Approvals {
		out := d.Approvals[i]
		if out.ID != a.ID || out.RunID != a.RunID || out.StepID != a.StepID || out.State != a.State || out.Version != a.Version || out.ExpiresAt.Location() != time.UTC || !out.ExpiresAt.Equal(expiry) || out.ExpectedEffect != a.ExpectedEffect || out.Reversible != a.Reversible || out.TTLSeconds != a.TTLSeconds || !evidence(out.EvidenceSummary) {
			return false
		}
	}
	return true
}

func (a *SecurityAgentOrderedResourceAuthority) resource(ctx context.Context, id RequestIdentity, op, key, value string) (orderedResourceWire, SecurityAgentOrderedRunResource, error) {
	var v orderedResourceWire
	var zero SecurityAgentOrderedRunResource
	raw, err := a.repository.invoke(ctx, id, op, map[string]any{key: value})
	if err != nil {
		return v, zero, err
	}
	if len(raw) > 16384 || public62Decode(raw, &v) != nil {
		return orderedResourceWire{}, zero, ErrRepositoryUnavailable
	}
	result, ok := orderedResourceProjection(v, id)
	if !ok {
		return orderedResourceWire{}, zero, ErrRepositoryUnavailable
	}
	if op == "resource_run" && v.Ordered.RunID != value {
		return orderedResourceWire{}, zero, ErrRepositoryUnavailable
	}
	return v, result, nil
}
func (a *SecurityAgentOrderedResourceAuthority) Run(ctx context.Context, id RequestIdentity, run string) (SecurityAgentOrderedRunResource, error) {
	if err := a.own(ctx, id, SecurityAgentResourceRun, run); err != nil {
		return SecurityAgentOrderedRunResource{}, err
	}
	_, result, err := a.resource(ctx, id, "resource_run", "run_id", run)
	return result, err
}
func (a *SecurityAgentOrderedResourceAuthority) Approval(ctx context.Context, id RequestIdentity, approval string) (SecurityAgentOrderedApprovalResource, error) {
	var zero SecurityAgentOrderedApprovalResource
	if err := a.own(ctx, id, SecurityAgentResourceApproval, approval); err != nil {
		return zero, err
	}
	v, result, err := a.resource(ctx, id, "resource_approval", "approval_id", approval)
	if err != nil {
		return zero, err
	}
	for i, item := range result.Detail.Approvals {
		if item.ID == approval {
			created, _ := orderedResourceTime(v.Approvals[i].CreatedAt)
			return SecurityAgentOrderedApprovalResource{item, result.Detail.Run.Version, created}, nil
		}
	}
	return zero, ErrRepositoryUnavailable
}
func (a *SecurityAgentOrderedResourceAuthority) Cancel(ctx context.Context, id RequestIdentity, q SecurityAgentPublicCancellation) (SecurityAgentOrderedCancellationResult, error) {
	var zero SecurityAgentOrderedCancellationResult
	if !public62MutationVersion(q.RunVersion) || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	if err := a.own(ctx, id, SecurityAgentResourceRun, q.RunID); err != nil {
		return zero, err
	}
	_, projection, err := a.resource(ctx, id, "resource_run", "run_id", q.RunID)
	if err != nil {
		return zero, err
	}
	mutation, err := a.repository.Cancel(ctx, id, q)
	if err != nil {
		return zero, err
	}
	// Identity/evidence are stable. State and version come only from the retained
	// mutation result, including replay and conservative planning cancellation.
	r := projection.Detail.Run
	return SecurityAgentOrderedCancellationResult{Result: SecurityAgentRunResult{ID: r.ID, AgentID: r.AgentID, State: mutation.RunState, EvidenceIDs: r.EvidenceIDs, DefinitionVersion: r.DefinitionVersion, Version: mutation.RunVersion, AuditID: mutation.AuditID, CorrelationID: mutation.AuditID, ReceiptID: mutation.ReceiptID, Replayed: mutation.Replayed}, CleanupRequired: mutation.CleanupRequired}, nil
}
func (a *SecurityAgentOrderedResourceAuthority) Decide(ctx context.Context, id RequestIdentity, q SecurityAgentOrderedDecision) (SecurityAgentApprovalResult, error) {
	var zero SecurityAgentApprovalResult
	if !public62MutationVersion(q.Version) || !public62OneOf(q.Decision, "approved", "rejected") || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return zero, ErrRepositoryOperation
	}
	if err := a.own(ctx, id, SecurityAgentResourceApproval, q.ApprovalID); err != nil {
		return zero, err
	}
	if !id.FreshAuthenticated || id.FreshAuthExpiresAt.Location() != time.UTC || !validSecurityAgentFreshAuthentication(time.Now(), id.FreshAuthExpiresAt) {
		return zero, ErrRepositoryOperation
	}
	raw, err := a.repository.invoke(ctx, id, "decide_resource", map[string]any{"approval_id": q.ApprovalID, "approval_version": q.Version, "decision": q.Decision, "idempotency_key": q.IdempotencyKey, "fresh_auth_at": id.FreshAuthExpiresAt.Add(-5 * time.Minute).Format(time.RFC3339Nano)})
	if err != nil {
		return zero, err
	}
	var wire struct {
		Mutation SecurityAgentPublicDecisionResult `json:"mutation"`
		Resource orderedResourceWire               `json:"resource"`
	}
	if len(raw) > 16384 || public62Decode(raw, &wire) != nil {
		return zero, ErrRepositoryUnavailable
	}
	m := wire.Mutation
	projection, valid := orderedResourceProjection(wire.Resource, id)
	index, canonical := public62MutationStepIndex(id, m.RunID, m.StepID)
	if !valid || !canonical || m.ContractVersion != 62 || m.OrganizationID != id.Scope.OrganizationID().String() || m.WorkspaceID != id.Scope.WorkspaceID().String() || m.EnvironmentID != id.Scope.EnvironmentID().String() || m.RunID != projection.Detail.Run.ID || !public62Version(m.RunVersion) || m.RunVersion < 4 || m.RunVersion > projection.Detail.Run.Version || m.ApprovalID != q.ApprovalID || m.ApprovalVersion != q.Version+1 || m.Decision != q.Decision || m.StepVersion != index+2 || !public62MutationIdentity(id, "decide", q.IdempotencyKey, m.AuditID, m.ReceiptID) || q.Decision == "approved" && (m.RunState != "running" || m.StepState != "authorized" || m.Outcome != "approved") || q.Decision == "rejected" && (m.RunState != "needs_human" || m.StepState != "cancelled" || m.Outcome != "blocked") {
		return zero, ErrRepositoryUnavailable
	}
	for _, approval := range projection.Detail.Approvals {
		if approval.ID != q.ApprovalID {
			continue
		}
		if approval.StepID != m.StepID || approval.State != m.Decision || approval.Version != m.ApprovalVersion {
			return zero, ErrRepositoryUnavailable
		}
		return SecurityAgentApprovalResult{ID: approval.ID, RunID: approval.RunID, StepID: approval.StepID, State: approval.State, ExpiresAt: approval.ExpiresAt, Version: approval.Version, ExpectedEffect: approval.ExpectedEffect, Reversible: approval.Reversible, TTLSeconds: approval.TTLSeconds, EvidenceSummary: approval.EvidenceSummary, AuditID: m.AuditID, CorrelationID: m.AuditID, ReceiptID: m.ReceiptID, Replayed: m.Replayed}, nil
	}
	return zero, ErrRepositoryUnavailable
}
