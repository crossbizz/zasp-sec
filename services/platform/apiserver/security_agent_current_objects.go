package apiserver

import (
	"context"
	"encoding/json"
)

// SecurityAgentOrderedDetail is the ordered release's extension of a run
// detail: the contract it was read under and the ordered steps.
type SecurityAgentOrderedDetail struct {
	ContractVersion int                       `json:"contract_version"`
	Steps           []SecurityAgentPublicStep `json:"steps"`
}

// SecurityAgentOrderedCancellation is the ordered release's extension of a
// cancellation: whether an effect that had started still needs cleanup.
type SecurityAgentOrderedCancellation struct {
	CleanupRequired bool `json:"cleanup_required"`
}

// securityAgentObjectEnvelope opens the envelope of an authorized Security
// Agent run or approval statement: the family PostgreSQL selected under the
// proof, and that family's own result.
func securityAgentObjectEnvelope(envelope json.RawMessage, families ...string) (string, json.RawMessage, error) {
	var wire struct {
		Family string          `json:"family"`
		Result json.RawMessage `json:"result"`
	}
	if !exactJSONFields(envelope, "family", "result") || decodeStrictDiscovery(envelope, &wire) != nil || !stringIn(wire.Family, families...) || !validJSONObjectBody(wire.Result) {
		return "", nil, ErrRepositoryUnavailable
	}
	return wire.Family, wire.Result, nil
}

func (repository *PostgresRepository) securityAgentScopeArguments(identity RequestIdentity, object string) []any {
	return []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), object, identity.PrincipalID.String()}
}

// getSecurityAgentRunCurrent reads one run under current authorization with
// one authorized statement.
func (repository *PostgresRepository) getSecurityAgentRunCurrent(ctx context.Context, identity RequestIdentity, runID string) (SecurityAgentRunDetail, error) {
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentRunDetailSQL, repository.securityAgentScopeArguments(identity, runID)...)
	if err != nil {
		return SecurityAgentRunDetail{}, discoveryProviderError(err)
	}
	family, payload, err := securityAgentObjectEnvelope(envelope, "ordered", "finding", "legacy")
	if err != nil {
		return SecurityAgentRunDetail{}, err
	}
	if family != "ordered" {
		return decodeSecurityAgentRunContextEnvelope(payload, runID)
	}
	if identity.CredentialKind != CredentialBrowserSession {
		return SecurityAgentRunDetail{}, ErrRepositoryOperation
	}
	_, resource, err := orderedResourceFromRaw(payload, identity, runID)
	if err != nil {
		return SecurityAgentRunDetail{}, err
	}
	detail := resource.Detail
	detail.Ordered = &SecurityAgentOrderedDetail{ContractVersion: 62, Steps: append([]SecurityAgentPublicStep{}, resource.Steps...)}
	return detail, nil
}

// cancelSecurityAgentRunCurrent cancels one run under current authorization
// with one authorized statement.
func (repository *PostgresRepository) cancelSecurityAgentRunCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentCancelRequest) (SecurityAgentRunResult, error) {
	arguments := append(repository.securityAgentScopeArguments(identity, input.RunID), input.IdempotencyKey, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID)
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentCancelRunSQL, arguments...)
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	family, payload, err := securityAgentObjectEnvelope(envelope, "ordered", "test", "legacy")
	if err != nil {
		return SecurityAgentRunResult{}, err
	}
	if family == "ordered" {
		return orderedCancellationFromEnvelope(payload, identity, input)
	}
	var result SecurityAgentRunResult
	if !securityAgentManualReadFields(payload, []string{"agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version"}) || decodeStrictDiscovery(payload, &result) != nil {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	read := SecurityAgentRun{ManualTrigger: result.ManualTrigger, ID: result.ID, AgentID: result.AgentID, State: result.State, EvidenceIDs: result.EvidenceIDs, DefinitionVersion: result.DefinitionVersion, Version: result.Version}
	if result.ID != input.RunID || result.State != "cancelled" || result.Version != input.ExpectedVersion+1 || !validSecurityAgentRun(read) || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// orderedCancellationFromEnvelope combines the ordered resource read before
// the cancellation with the retained mutation result, as the ordered
// authority does: identity and evidence come from the resource, state and
// version only from the mutation.
func orderedCancellationFromEnvelope(payload json.RawMessage, identity RequestIdentity, input SecurityAgentCancelRequest) (SecurityAgentRunResult, error) {
	var wire struct {
		Resource json.RawMessage `json:"resource"`
		Mutation json.RawMessage `json:"mutation"`
	}
	request := SecurityAgentPublicCancellation{RunID: input.RunID, RunVersion: input.ExpectedVersion, IdempotencyKey: input.IdempotencyKey}
	if identity.CredentialKind != CredentialBrowserSession || !public62MutationVersion(request.RunVersion) || !securityAgentPublicIdempotency.MatchString(request.IdempotencyKey) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	if !exactJSONFields(payload, "resource", "mutation") || decodeStrictDiscovery(payload, &wire) != nil {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	_, projection, err := orderedResourceFromRaw(wire.Resource, identity, input.RunID)
	if err != nil {
		return SecurityAgentRunResult{}, err
	}
	mutation, err := public62CancellationResult(wire.Mutation, identity, request)
	if err != nil {
		return SecurityAgentRunResult{}, err
	}
	run := projection.Detail.Run
	return SecurityAgentRunResult{ID: run.ID, AgentID: run.AgentID, State: mutation.RunState, EvidenceIDs: run.EvidenceIDs, DefinitionVersion: run.DefinitionVersion, Version: mutation.RunVersion, AuditID: mutation.AuditID, CorrelationID: mutation.AuditID, ReceiptID: mutation.ReceiptID, Replayed: mutation.Replayed,
		Ordered: &SecurityAgentOrderedCancellation{CleanupRequired: mutation.CleanupRequired}}, nil
}

// getSecurityAgentApprovalCurrent reads one approval under current
// authorization with one authorized statement.
func (repository *PostgresRepository) getSecurityAgentApprovalCurrent(ctx context.Context, identity RequestIdentity, approvalID string) (SecurityAgentApproval, error) {
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentApprovalSQL, repository.securityAgentScopeArguments(identity, approvalID)...)
	if err != nil {
		return SecurityAgentApproval{}, discoveryProviderError(err)
	}
	family, payload, err := securityAgentObjectEnvelope(envelope, "ordered", "finding", "legacy")
	if err != nil {
		return SecurityAgentApproval{}, err
	}
	if family != "ordered" {
		return decodeApprovalContextEnvelope(payload, approvalID)
	}
	if identity.CredentialKind != CredentialBrowserSession {
		return SecurityAgentApproval{}, ErrRepositoryOperation
	}
	_, resource, err := orderedResourceFromRaw(payload, identity, "")
	if err != nil {
		return SecurityAgentApproval{}, err
	}
	for _, item := range resource.Detail.Approvals {
		if item.ID == approvalID {
			item.ordered = true
			return item, nil
		}
	}
	return SecurityAgentApproval{}, ErrRepositoryUnavailable
}

// decideSecurityAgentApprovalCurrent decides one approval of a family other
// than the ordered release under current authorization with one authorized
// statement. The ordered release decides its own approvals.
func (repository *PostgresRepository) decideSecurityAgentApprovalCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentApprovalDecisionRequest) (SecurityAgentApprovalResult, error) {
	if !input.FreshAuthAt.Equal(identity.FreshAuthExpiresAt.Add(-securityAgentFreshAuthenticationTTL)) {
		return SecurityAgentApprovalResult{}, ErrRepositoryOperation
	}
	arguments := append(repository.securityAgentScopeArguments(identity, input.ApprovalID), input.IdempotencyKey, input.ExpectedVersion, input.Decision, input.FreshAuthAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentDecideApprovalSQL, arguments...)
	if err != nil {
		return SecurityAgentApprovalResult{}, discoveryProviderError(err)
	}
	_, payload, err := securityAgentObjectEnvelope(envelope, "finding", "test", "legacy")
	if err != nil {
		return SecurityAgentApprovalResult{}, err
	}
	var result SecurityAgentApprovalResult
	fields := []string{"audit_id", "correlation_id", "evidence_summary", "expected_effect", "expires_at", "id", "receipt_id", "replayed", "reversible", "run_id", "state", "step_id", "ttl_seconds", "version"}
	if !attackLabApprovalFields(payload, fields...) && !exactJSONFields(payload, append(fields, "approval_context")...) || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentApprovalResult(result, input) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentApprovalResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// simulateSecurityAgentCurrent stores one simulation under current
// authorization with one authorized statement.
func (repository *PostgresRepository) simulateSecurityAgentCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentSimulationRequest, evidence json.RawMessage) (SecurityAgentSimulationResult, error) {
	arguments := append(repository.securityAgentScopeArguments(identity, input.DefinitionID), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.Goal, evidence, input.ExpiresAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentSimulateSQL, arguments...)
	if err != nil {
		return SecurityAgentSimulationResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentSimulationResult
	if !exactJSONFields(payload, "audit_id", "catalog_version", "correlation_id", "definition_id", "definition_version", "expires_at", "matched_evidence_ids", "plan_hash", "receipt_id", "replayed", "run_id", "side_effects", "steps", "summary", "version") || json.Unmarshal(payload, &result) != nil || !validSecurityAgentSimulation(result, input.DefinitionID, input.ExpectedVersion, input.EvidenceIDs, input.ExpiresAt) || !result.Replayed && (result.RunID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentSimulationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// runSecurityAgentManualCurrent starts a run by hand (no trigger) under
// current authorization with one authorized statement.
func (repository *PostgresRepository) runSecurityAgentManualCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	if input.TriggerKind != "manual" || input.TriggerID != "" || input.TriggerVersion != nil || input.TriggerSource != nil {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	arguments := append(repository.securityAgentScopeArguments(identity, input.DefinitionID), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.AuditID, input.CorrelationID, input.ReceiptID)
	raw, err := repository.database.QueryJSON(ctx, currentSecurityAgentManualRunSQL, arguments...)
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentRunResult
	var replay struct {
		Replayed *bool `json:"replayed"`
	}
	if !securityAgentManualReadFields(raw, []string{"agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version"}) || json.Unmarshal(raw, &replay) != nil || replay.Replayed == nil || decodeStrictDiscovery(raw, &result) != nil || !validSecurityAgentRunResult(result, input) || !result.Replayed && (result.ID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
