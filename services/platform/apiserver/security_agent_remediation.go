package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

// A provider remediation is a Security Agent run whose request names the
// action and its parameters: POST /security-agents/{id}/runs with a finding
// trigger and a remediation. PostgreSQL writes the plan and the pending
// approval in the admission (completion.sql, section V6); nothing is planned
// by a model.

const currentSecurityAgentRemediationRunSQL = `SELECT zasp_authorization80.security_agent_remediation_run($1,$2,$3,$4,$5,$6::jsonb,$7)`

// SecurityAgentRunRemediation is the remediation of a run request.
type SecurityAgentRunRemediation struct {
	Action     string
	Parameters map[string]string
	ApprovalID string
}

// The refusals of a remediation request that a person can act on. Each is a
// refusal before anything was written.
var (
	// The integration that describes the agent names no remediation role.
	ErrSecurityAgentRemediationRoleMissing = errors.Join(ErrRepositoryConflict, errors.New("security agent remediation role not configured"))
	// The integration is not an active AWS integration of the agent's account.
	ErrSecurityAgentRemediationIntegrationUnavailable = errors.Join(ErrRepositoryConflict, errors.New("security agent remediation integration unavailable"))
	// The same Security Agent already acted on this version of the finding.
	ErrSecurityAgentRemediationAlreadyRequested = errors.Join(ErrRepositoryConflict, errors.New("security agent remediation already requested"))
	// The finding's rule is not the one the action answers.
	ErrSecurityAgentRemediationRuleMismatch = errors.Join(ErrRepositoryOperation, errors.New("security agent remediation finding rule mismatch"))
	// The finding is not on a Bedrock agent an AWS integration describes.
	ErrSecurityAgentRemediationTargetUnsupported = errors.Join(ErrRepositoryOperation, errors.New("security agent remediation target unsupported"))
	// Execution is switched off for the Environment or for the action.
	ErrSecurityAgentRemediationDisabled = errors.Join(ErrRepositoryConflict, errors.New("security agent execution disabled"))
)

// classifySecurityAgentRemediationError names the refusals of section V6.
// It returns nil for any other provider error.
func classifySecurityAgentRemediationError(provider *pgconn.PgError) error {
	if provider == nil {
		return nil
	}
	switch provider.Code + " " + provider.Message {
	case "55000 security agent remediation role not configured":
		return ErrSecurityAgentRemediationRoleMissing
	case "55000 security agent remediation integration unavailable":
		return ErrSecurityAgentRemediationIntegrationUnavailable
	case "23505 security agent remediation already requested":
		return ErrSecurityAgentRemediationAlreadyRequested
	case "22023 security agent remediation finding rule mismatch":
		return ErrSecurityAgentRemediationRuleMismatch
	case "22023 security agent remediation target unsupported":
		return ErrSecurityAgentRemediationTargetUnsupported
	}
	return nil
}

// securityAgentRemediationErrorResponse is the API answer to a named refusal.
func securityAgentRemediationErrorResponse(err error) (status int, code, message string, ok bool) {
	switch {
	case errors.Is(err, ErrSecurityAgentRemediationRoleMissing):
		return 409, "remediation_role_not_configured", "The integration that describes this agent has no remediation role. Set one with PUT /api/v1/integrations/{id}/remediation-role; the role discovery reads with is never used to make changes.", true
	case errors.Is(err, ErrSecurityAgentRemediationIntegrationUnavailable):
		return 409, "remediation_integration_unavailable", "The agent is not described by an active AWS integration of its own account", true
	case errors.Is(err, ErrSecurityAgentRemediationAlreadyRequested):
		return 409, "remediation_already_requested", "This Security Agent already has a remediation run for this version of the finding", true
	case errors.Is(err, ErrSecurityAgentRemediationRuleMismatch):
		return 400, "remediation_rule_mismatch", "The action does not answer this finding's rule", true
	case errors.Is(err, ErrSecurityAgentRemediationTargetUnsupported):
		return 400, "remediation_target_unsupported", "The finding is not on a Bedrock agent that an AWS integration describes", true
	}
	return 0, "", "", false
}

type securityAgentRemediationInput struct {
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters"`
}

func decodeSecurityAgentRemediationInput(raw json.RawMessage) (*securityAgentRemediationInput, error) {
	if _, err := auditExportClosedObject(raw, 4096, "action", "parameters"); err != nil {
		return nil, ErrRepositoryOperation
	}
	var value securityAgentRemediationInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.More() || !securityagent.ValidProviderRemediationParameters(value.Action, value.Parameters, "", "") {
		return nil, ErrRepositoryOperation
	}
	return &value, nil
}

type securityAgentRemediationAdmission struct {
	OrganizationID    string            `json:"organization_id"`
	WorkspaceID       string            `json:"workspace_id"`
	EnvironmentID     string            `json:"environment_id"`
	ActorID           string            `json:"actor_id"`
	DefinitionID      string            `json:"definition_id"`
	DefinitionVersion int64             `json:"definition_version"`
	IdempotencyKey    string            `json:"idempotency_key"`
	RunID             string            `json:"run_id"`
	TriggerKind       string            `json:"trigger_kind"`
	TriggerID         string            `json:"trigger_id"`
	Action            string            `json:"action"`
	Parameters        map[string]string `json:"parameters"`
	ApprovalID        string            `json:"approval_id"`
	AuditID           string            `json:"audit_id"`
	CorrelationID     string            `json:"correlation_id"`
	ReceiptID         string            `json:"receipt_id"`
}

func validSecurityAgentRemediationAdmission(value securityAgentRemediationAdmission) bool {
	ids := map[string]struct{}{value.RunID: {}, value.ApprovalID: {}, value.AuditID: {}, value.CorrelationID: {}, value.ReceiptID: {}}
	return value.DefinitionVersion >= 1 && value.DefinitionVersion <= 1000000 && validPublicIdempotency(value.IdempotencyKey) && value.TriggerKind == "finding" &&
		validProductID(value.RunID) && validProductID(value.TriggerID) && validProductID(value.ApprovalID) && validProductID(value.AuditID) && validProductID(value.CorrelationID) && validProductID(value.ReceiptID) && len(ids) == 5 &&
		securityagent.ValidProviderRemediationParameters(value.Action, value.Parameters, "", "")
}

// runSecurityAgentRemediationCurrent starts a remediation run with one
// authorized statement. The request's proof is for the Security Agent; the
// finding is authorized by a second decision whose attestation the statement
// verifies, as for every run on a finding.
func (repository *PostgresRepository) runSecurityAgentRemediationCurrent(ctx context.Context, identity RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	if input.Remediation == nil || input.TriggerKind != "finding" || input.TriggerVersion != nil || input.TriggerSource != nil || !validProductID(input.TriggerID) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	o, w, e, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	value := securityAgentRemediationAdmission{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ActorID: actor, DefinitionID: input.DefinitionID, DefinitionVersion: input.ExpectedVersion, IdempotencyKey: input.IdempotencyKey, RunID: input.RunID, TriggerKind: "finding", TriggerID: input.TriggerID,
		Action: input.Remediation.Action, Parameters: input.Remediation.Parameters, ApprovalID: input.Remediation.ApprovalID, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}
	if !validSecurityAgentRemediationAdmission(value) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	admission, err := json.Marshal(value)
	if err != nil {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	grant, grantErr := secondaryRequestAuthorization(ctx, identity, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": input.TriggerID}})
	if grantErr != nil {
		return SecurityAgentRunResult{}, secondaryAuthorizationError(grantErr)
	}
	proof, proofErr := authorizationProofJSON(grant)
	if proofErr != nil {
		return SecurityAgentRunResult{}, ErrRepositoryAuthorization
	}
	envelope, err := repository.database.QueryJSON(ctx, currentSecurityAgentRemediationRunSQL, o, w, e, input.DefinitionID, actor, json.RawMessage(admission), string(proof))
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	var wire struct {
		Family string          `json:"family"`
		Result json.RawMessage `json:"result"`
	}
	if !exactJSONFields(envelope, "family", "result") || decodeStrictDiscovery(envelope, &wire) != nil || wire.Family != "remediation" {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	var result SecurityAgentRunResult
	if !exactJSONFields(wire.Result, "agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version") || decodeStrictDiscovery(wire.Result, &result) != nil || !validSecurityAgentRunResult(result, input) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	if !result.Replayed && (result.ID != input.RunID || result.State != "waiting_approval" || result.Version != 1 || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// securityAgentRemediationStatementAllowed admits the remediation admission
// for the checked request it belongs to. PostgreSQL compares the same values
// with the attested proofs.
func securityAgentRemediationStatementAllowed(g RequestAuthorization, args []any) bool {
	if len(args) != 7 || g.OperationID != "runSecurityAgent" || g.Collection || !stringIn(string(g.Identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) {
		return false
	}
	values, ok := securityAgentWriteStrings(args, 0, 1, 2, 3, 4)
	raw, rawOK := args[5].(json.RawMessage)
	proof, proofOK := args[6].(string)
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	if !ok || !rawOK || !proofOK || len(raw) > 8192 || proof == "" || len(proof) > 12*1024*1024 || values[0] != o || values[1] != w || values[2] != e || values[4] != actor || !validProductID(values[3]) || g.PathParameters["id"] != values[3] || !authorizationNativeTargetAllowed(g, "security_agent", values[3]) {
		return false
	}
	var admission securityAgentRemediationAdmission
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&admission) != nil || decoder.More() {
		return false
	}
	return admission.OrganizationID == o && admission.WorkspaceID == w && admission.EnvironmentID == e && admission.ActorID == actor && admission.DefinitionID == values[3] && validSecurityAgentRemediationAdmission(admission)
}

func securityAgentRemediationNamedError(err error) bool {
	_, _, _, named := securityAgentRemediationErrorResponse(err)
	return named
}

// securityAgentExecutionControlActions are the actions with an execution
// switch, in the order PostgreSQL lists them.
var securityAgentExecutionControlActions = []string{"attach_bedrock_guardrail", "create_evidence_export", "create_temporary_policy", "detach_role_administrator_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"}
