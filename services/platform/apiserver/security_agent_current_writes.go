package apiserver

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

// securityAgentFamilyResult opens the envelope of an authorized Security
// Agent write: the family PostgreSQL selected under the proof, and that
// family's own result. The ordered family's result carries its contract
// version, which is verified and removed so every family has one shape.
func securityAgentFamilyResult(envelope json.RawMessage) (string, json.RawMessage, error) {
	var wire struct {
		Family string          `json:"family"`
		Result json.RawMessage `json:"result"`
	}
	if !exactJSONFields(envelope, "family", "result") || decodeStrictDiscovery(envelope, &wire) != nil || !stringIn(wire.Family, "finding", "test", "ordered", "legacy") || !validJSONObjectBody(wire.Result) {
		return "", nil, ErrRepositoryUnavailable
	}
	if wire.Family != "ordered" {
		return wire.Family, wire.Result, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire.Result, &fields) != nil || string(fields["contract_version"]) != "62" {
		return "", nil, ErrRepositoryUnavailable
	}
	delete(fields, "contract_version")
	result, err := json.Marshal(fields)
	if err != nil {
		return "", nil, ErrRepositoryUnavailable
	}
	return wire.Family, result, nil
}

// runSecurityAgentCurrent starts a run under current authorization with one
// authorized statement. A run with no trigger is the manual trigger, which
// has its own statement.
func (repository *PostgresRepository) runSecurityAgentCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) ||
		!validProductID(input.DefinitionID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validProductID(input.RunID) || !stringIn(input.TriggerKind, "finding", "session", "attack_path", "manual") ||
		!validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || (input.TriggerVersion == nil) != (input.TriggerSource == nil) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	if input.Remediation != nil {
		return repository.runSecurityAgentRemediationCurrent(ctx, identity, input)
	}
	if input.TriggerKind == "manual" {
		return repository.runSecurityAgentManualCurrent(ctx, identity, input)
	}
	if !validProductID(input.TriggerID) || input.TriggerVersion != nil && (*input.TriggerVersion < 1 || !validSecurityAgentText(*input.TriggerSource, 128)) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	o, w, e, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	admission, err := json.Marshal(securityAgentRunAdmission{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ActorID: actor, DefinitionID: input.DefinitionID, DefinitionVersion: input.ExpectedVersion, IdempotencyKey: input.IdempotencyKey, RunID: input.RunID, TriggerKind: input.TriggerKind, TriggerID: input.TriggerID, TriggerVersion: input.TriggerVersion, TriggerSource: input.TriggerSource, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID})
	if err != nil {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	// The definition is the object of the request's proof. The trigger is
	// named in the body, so it is authorized by a second decision whose
	// attestation the statement verifies.
	var triggerProof any
	_, checked := requestAuthorizationFromContext(ctx)
	// Without a checked request nothing is attested; the database then
	// refuses the statement itself (it carries no proof).
	if operation := securityAgentRunTriggerOperation(input.TriggerKind); operation != "" && checked {
		grant, grantErr := secondaryRequestAuthorization(ctx, identity, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": input.TriggerID}})
		if grantErr != nil {
			return SecurityAgentRunResult{}, secondaryAuthorizationError(grantErr)
		}
		proof, proofErr := authorizationProofJSON(grant)
		if proofErr != nil {
			return SecurityAgentRunResult{}, ErrRepositoryAuthorization
		}
		triggerProof = string(proof)
	}
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentRunSQL, o, w, e, input.DefinitionID, actor, json.RawMessage(admission), triggerProof)
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	family, payload, err := securityAgentFamilyResult(envelope)
	if err != nil {
		return SecurityAgentRunResult{}, err
	}
	var result SecurityAgentRunResult
	if !exactJSONFields(payload, "agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version") || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentRunResult(result, input) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	if family == "ordered" {
		// The ordered family derives the run, audit and receipt identities
		// from the definition, the trigger occurrence, the actor and the key.
		run, _ := CanonicalDiscoveryID(identity.Scope, "security_agent_run", input.DefinitionID+"\x1f"+input.TriggerID+"\x1f"+strconv.FormatInt(*input.TriggerVersion, 10))
		audit, _ := CanonicalDiscoveryID(identity.Scope, "public62_trigger", run)
		receipt, _ := CanonicalDiscoveryID(identity.Scope, "public62_receipt", actor+"\x1f"+input.IdempotencyKey)
		if run == "" || result.ID != run || result.State != "queued" || result.Version != 1 || result.AuditID != audit || result.CorrelationID != audit || result.ReceiptID != receipt {
			return SecurityAgentRunResult{}, ErrRepositoryUnavailable
		}
		return result, nil
	}
	if !result.Replayed && (result.ID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// setSecurityAgentExecutionControlCurrent changes one execution switch under
// current authorization with one authorized statement.
func (repository *PostgresRepository) setSecurityAgentExecutionControlCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentExecutionControlMutation) (SecurityAgentExecutionControlResult, error) {
	validTarget := input.Target == "environment" && input.ActionKey == "*" || input.Target == "action" && stringIn(input.ActionKey, securityAgentExecutionControlActions...)
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || identity.FreshAuthExpiresAt.Location() != time.UTC || input.FreshAuthExpiresAt != identity.FreshAuthExpiresAt || !validTarget || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 0 || input.ExpectedVersion > 1000000 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || input.AuditID == input.CorrelationID || input.AuditID == input.ReceiptID || input.CorrelationID == input.ReceiptID {
		return SecurityAgentExecutionControlResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentSetExecutionControlSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.Target, input.ActionKey, input.Enabled, input.ExpectedVersion, input.FreshAuthExpiresAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentExecutionControlResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentExecutionControlResult
	if !exactJSONFields(payload, "action_key", "audit_id", "correlation_id", "enabled", "receipt_id", "replayed", "target", "version") || decodeStrictDiscovery(payload, &result) != nil || result.Target != input.Target || result.ActionKey != input.ActionKey || result.Enabled != input.Enabled || result.Version != input.ExpectedVersion+1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentExecutionControlResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
