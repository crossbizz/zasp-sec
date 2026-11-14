package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

// SecurityAgentRunClosure is the record of a human closing a run that needed
// a human: who, when and why. The run keeps its state.
type SecurityAgentRunClosure struct {
	ClosedAt string `json:"closed_at"`
	ClosedBy string `json:"closed_by"`
	Reason   string `json:"reason"`
	Note     string `json:"note,omitempty"`
}

// SecurityAgentRunCloseRequest closes one run that needs a human.
type SecurityAgentRunCloseRequest struct {
	RunID           string
	IdempotencyKey  string
	ExpectedVersion int64
	Reason          string
	Note            string
	AuditID         string
	CorrelationID   string
	ReceiptID       string
}

// SecurityAgentRunCloseResult is the stored answer of a closure.
type SecurityAgentRunCloseResult struct {
	ID                string                  `json:"id"`
	AgentID           string                  `json:"agent_id"`
	State             string                  `json:"state"`
	DefinitionVersion int64                   `json:"definition_version"`
	Version           int64                   `json:"version"`
	Closure           SecurityAgentRunClosure `json:"closure"`
	AuditID           string                  `json:"audit_id"`
	CorrelationID     string                  `json:"correlation_id"`
	ReceiptID         string                  `json:"receipt_id"`
	Replayed          bool                    `json:"replayed"`
}

func validSecurityAgentCloseReason(reason string) bool {
	return stringIn(reason, "no_action_required", "resolved_outside_product", "usage_unknown_accepted")
}

func validSecurityAgentCloseNote(note string) bool {
	return validSecurityAgentText(note, 500)
}

var securityAgentStopReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validSecurityAgentRunClosure(closure SecurityAgentRunClosure) bool {
	stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", closure.ClosedAt)
	return err == nil && !stamp.IsZero() && validProductID(closure.ClosedBy) && validSecurityAgentCloseReason(closure.Reason) && (closure.Note == "" || validSecurityAgentCloseNote(closure.Note))
}

// securityAgentRunLifecycle reads the lifecycle a run detail carries beside
// its family result: the recorded reason the run stopped (a closed code) and
// its closure. Both are optional.
func securityAgentRunLifecycle(envelope json.RawMessage) (string, *SecurityAgentRunClosure, error) {
	var outer struct {
		Lifecycle json.RawMessage `json:"lifecycle"`
	}
	if json.Unmarshal(envelope, &outer) != nil || !validJSONObjectBody(outer.Lifecycle) {
		return "", nil, ErrRepositoryUnavailable
	}
	var fields map[string]json.RawMessage
	var wire struct {
		StopReason string                   `json:"stop_reason"`
		Closure    *SecurityAgentRunClosure `json:"closure"`
	}
	if json.Unmarshal(outer.Lifecycle, &fields) != nil || decodeStrictDiscovery(outer.Lifecycle, &wire) != nil {
		return "", nil, ErrRepositoryUnavailable
	}
	if _, present := fields["stop_reason"]; present && !securityAgentStopReasonPattern.MatchString(wire.StopReason) {
		return "", nil, ErrRepositoryUnavailable
	}
	if _, present := fields["closure"]; present != (wire.Closure != nil) || wire.Closure != nil && (!validSecurityAgentRunClosure(*wire.Closure) || !exactJSONFields(fields["closure"], "closed_at", "closed_by", "reason") && !exactJSONFields(fields["closure"], "closed_at", "closed_by", "reason", "note")) {
		return "", nil, ErrRepositoryUnavailable
	}
	return wire.StopReason, wire.Closure, nil
}

// securityAgentRunDetailEnvelope opens the envelope of the authorized run
// detail: the family, its result and the lifecycle.
func securityAgentRunDetailEnvelope(envelope json.RawMessage) (string, json.RawMessage, string, *SecurityAgentRunClosure, error) {
	var wire struct {
		Family    string          `json:"family"`
		Result    json.RawMessage `json:"result"`
		Lifecycle json.RawMessage `json:"lifecycle"`
	}
	if !exactJSONFields(envelope, "family", "result", "lifecycle") || decodeStrictDiscovery(envelope, &wire) != nil || !stringIn(wire.Family, "ordered", "finding", "legacy") || !validJSONObjectBody(wire.Result) {
		return "", nil, "", nil, ErrRepositoryUnavailable
	}
	reason, closure, err := securityAgentRunLifecycle(envelope)
	if err != nil {
		return "", nil, "", nil, err
	}
	return wire.Family, wire.Result, reason, closure, nil
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
	family, payload, reason, closure, err := securityAgentRunDetailEnvelope(envelope)
	if err != nil {
		return SecurityAgentRunDetail{}, err
	}
	if family != "ordered" {
		detail, err := decodeSecurityAgentRunContextEnvelope(payload, runID)
		if err != nil {
			return SecurityAgentRunDetail{}, err
		}
		detail.StopReason, detail.Closure = reason, closure
		return detail, nil
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
	detail.StopReason, detail.Closure = reason, closure
	return detail, nil
}

// CloseSecurityAgentRun records that a human reviewed a run that needs a
// human and closed it, with one authorized statement. The run keeps its
// state; it stops holding its agent's capacity for a provider outcome that
// is still unknown.
func (repository *PostgresRepository) CloseSecurityAgentRun(ctx context.Context, identity RequestIdentity, input SecurityAgentRunCloseRequest) (SecurityAgentRunCloseResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) ||
		!validProductID(input.RunID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validSecurityAgentCloseReason(input.Reason) || input.Note != "" && !validSecurityAgentCloseNote(input.Note) ||
		!validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || input.AuditID == input.CorrelationID || input.AuditID == input.ReceiptID || input.CorrelationID == input.ReceiptID {
		return SecurityAgentRunCloseResult{}, ErrRepositoryOperation
	}
	// Only a request with a current proof can close a run: the statement is
	// refused by the database without one.
	if _, checked := requestAuthorizationFromContext(ctx); !checked {
		return SecurityAgentRunCloseResult{}, ErrRepositoryAuthorization
	}
	var note any
	if input.Note != "" {
		note = input.Note
	}
	arguments := append(repository.securityAgentScopeArguments(identity, input.RunID), input.IdempotencyKey, input.ExpectedVersion, input.Reason, note, input.AuditID, input.CorrelationID, input.ReceiptID)
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentCloseRunSQL, arguments...)
	if err != nil {
		return SecurityAgentRunCloseResult{}, discoveryProviderError(err)
	}
	return decodeSecurityAgentRunCloseResult(payload, identity, input)
}

func decodeSecurityAgentRunCloseResult(payload json.RawMessage, identity RequestIdentity, input SecurityAgentRunCloseRequest) (SecurityAgentRunCloseResult, error) {
	var result SecurityAgentRunCloseResult
	var fields map[string]json.RawMessage
	if !exactJSONFields(payload, "agent_id", "audit_id", "closure", "correlation_id", "definition_version", "id", "receipt_id", "replayed", "state", "version") || json.Unmarshal(payload, &fields) != nil || decodeStrictDiscovery(payload, &result) != nil ||
		!exactJSONFields(fields["closure"], "closed_at", "closed_by", "reason") && !exactJSONFields(fields["closure"], "closed_at", "closed_by", "reason", "note") {
		return SecurityAgentRunCloseResult{}, ErrRepositoryUnavailable
	}
	if result.ID != input.RunID || !validProductID(result.AgentID) || result.State != "needs_human" || result.DefinitionVersion < 1 || result.DefinitionVersion > 1000000 || result.Version != input.ExpectedVersion ||
		!validSecurityAgentRunClosure(result.Closure) || result.Closure.ClosedBy != identity.PrincipalID.String() || result.Closure.Reason != input.Reason || result.Closure.Note != input.Note ||
		!validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) ||
		!result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunCloseResult{}, ErrRepositoryUnavailable
	}
	return result, nil
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
	if grant, _ := requestAuthorizationFromContext(ctx); grant.OperationID == "decideSecurityAgentApproval" && grant.PathParameters["id"] == approvalID {
		// A decision reads the approval it decides before it decides it (an
		// approval of a destructive action needs an identity administrator).
		// The request's proof is for the decision, and neither the statement
		// gate nor PostgreSQL serves a read under it: the read is authorized
		// by a second decision of its own, at the same projection revision.
		// Without it every approval through the API was refused.
		read, err := secondaryRequestAuthorization(ctx, identity, RoutedOperation{OperationID: "getSecurityAgentApproval", PathParameters: map[string]string{"id": approvalID}})
		if err != nil {
			return SecurityAgentApproval{}, secondaryAuthorizationError(err)
		}
		ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, read)
	}
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

// securityAgentStatementRefused reports whether an authorized statement
// raised exactly this refusal (insufficient privilege, with this message).
func securityAgentStatementRefused(err error, message string) bool {
	var provider *pgconn.PgError
	return errors.As(err, &provider) && provider.Code == "42501" && provider.Message == message
}

// securityAgentEvidenceOperation is the operation of the second decision a
// simulation makes for its evidence: the mixed collection of the Environment
// with permission 'view'.
const securityAgentEvidenceOperation = "globalSearch"

// simulateSecurityAgentCurrent stores one simulation under current
// authorization with one authorized statement.
func (repository *PostgresRepository) simulateSecurityAgentCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentSimulationRequest, evidence json.RawMessage) (SecurityAgentSimulationResult, error) {
	// The definition is the object of the request's proof. The evidence is
	// named in the body, so it is authorized by a second decision: the mixed
	// collection of the Environment, whose attestation lists every object
	// the requester may read. The statement verifies that attestation and
	// refuses evidence it does not allow. Without a checked request nothing
	// is attested and the database refuses the statement itself.
	var evidenceProof any
	if _, checked := requestAuthorizationFromContext(ctx); checked {
		grant, grantErr := secondaryRequestAuthorization(ctx, identity, RoutedOperation{OperationID: securityAgentEvidenceOperation})
		if grantErr != nil {
			return SecurityAgentSimulationResult{}, secondaryAuthorizationError(grantErr)
		}
		proof, proofErr := authorizationProofJSON(grant)
		if proofErr != nil {
			return SecurityAgentSimulationResult{}, ErrRepositoryAuthorization
		}
		evidenceProof = string(proof)
	}
	arguments := append(repository.securityAgentScopeArguments(identity, input.DefinitionID), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.Goal, evidence, input.ExpiresAt, input.AuditID, input.CorrelationID, input.ReceiptID, evidenceProof)
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentSimulateSQL, arguments...)
	if err != nil {
		// The statement refuses evidence the second decision does not allow.
		// That is a denial of this request, not an unavailable provider.
		if securityAgentStatementRefused(err, "current security agent evidence authorization required") {
			return SecurityAgentSimulationResult{}, ErrRepositoryAuthorization
		}
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
