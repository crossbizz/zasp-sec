package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

const (
	postgresSecurityAgentAuthorityReadySQL       = `SELECT jsonb_build_object('release',zasp_security_agent_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresIdentityAdminSecurityAgentReadySQL   = `SELECT jsonb_build_object('release',zasp_identity_administration_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresSecurityAgentControlsReadySQL        = `SELECT jsonb_build_object('release',zasp_security_agent_controls_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresSecurityAgentAutonomousReadySQL      = `SELECT jsonb_build_object('release',zasp_security_agent_autonomous_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresSecurityAgentExecutionControlsSQL    = `SELECT zasp_security_agent_execution_control_detail($1,$2,$3)`
	postgresSecurityAgentSetExecutionControlSQL  = `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresSecurityAgentDefinitionPageSQL       = `SELECT zasp_security_agent_definition_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresSecurityAgentDefinitionValueSQL      = `SELECT zasp_security_agent_definition_value($1,$2,$3,$4)`
	postgresSecurityAgentDefinitionReplaySQL     = `SELECT zasp_security_agent_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb)`
	postgresSecurityAgentDefinitionMutateSQL     = `SELECT zasp_security_agent_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
	postgresSecurityAgentDefinitionActivationSQL = `SELECT zasp_security_agent_definition_detail($1,$2,$3,$4)`
	postgresSecurityAgentActivateSQL             = `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	postgresSecurityAgentSimulateSQL             = `SELECT zasp_security_agent_simulate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)`
	postgresSecurityAgentRunSQL                  = `SELECT zasp_security_agent_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	postgresSecurityAgentRunPageSQL              = `SELECT zasp_security_agent_run_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8)`
	postgresSecurityAgentRunDetailSQL            = `SELECT zasp_security_agent_run_detail($1,$2,$3,$4)`
	postgresSecurityAgentCancelRunSQL            = `SELECT zasp_security_agent_cancel_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresSecurityAgentApprovalPageSQL         = `SELECT zasp_security_agent_approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8)`
	postgresSecurityAgentApprovalDetailSQL       = `SELECT zasp_security_agent_approval_detail($1,$2,$3,$4)`
	postgresSecurityAgentDecideApprovalSQL       = `SELECT zasp_security_agent_decide_approval($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
)

func (repository *PostgresRepository) GetSecurityAgentExecutionControls(ctx context.Context, identity RequestIdentity) (SecurityAgentExecutionControls, error) {
	if repository == nil || !stringIn(repository.schema, SecurityAgentControlsSchemaVersion, SecurityAgentAutonomousSchemaVersion) || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession {
		return SecurityAgentExecutionControls{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentExecutionControlsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	if err != nil {
		return SecurityAgentExecutionControls{}, discoveryProviderError(err)
	}
	var result SecurityAgentExecutionControls
	if !exactJSONFields(payload, "actions", "environment", "global") || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentExecutionControls(result) {
		return SecurityAgentExecutionControls{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) SetSecurityAgentExecutionControl(ctx context.Context, identity RequestIdentity, input SecurityAgentExecutionControlMutation) (SecurityAgentExecutionControlResult, error) {
	validTarget := input.Target == "environment" && input.ActionKey == "*" || input.Target == "action" && input.ActionKey == "update_finding_response"
	if repository == nil || !stringIn(repository.schema, SecurityAgentControlsSchemaVersion, SecurityAgentAutonomousSchemaVersion) || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || identity.FreshAuthExpiresAt.Location() != time.UTC || input.FreshAuthExpiresAt != identity.FreshAuthExpiresAt || !validTarget || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 0 || input.ExpectedVersion > 1000000 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || input.AuditID == input.CorrelationID || input.AuditID == input.ReceiptID || input.CorrelationID == input.ReceiptID {
		return SecurityAgentExecutionControlResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentSetExecutionControlSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IdempotencyKey, input.Target, input.ActionKey, input.Enabled, input.ExpectedVersion, input.FreshAuthExpiresAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentExecutionControlResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentExecutionControlResult
	if !exactJSONFields(payload, "action_key", "audit_id", "correlation_id", "enabled", "receipt_id", "replayed", "target", "version") || decodeStrictDiscovery(payload, &result) != nil || result.Target != input.Target || result.ActionKey != input.ActionKey || result.Enabled != input.Enabled || result.Version != input.ExpectedVersion+1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentExecutionControlResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func NewSecurityAgentPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, schema := range []string{SecurityAgentAutonomousSchemaVersion, SecurityAgentControlsSchemaVersion, IdentityAdministrationSchemaVersion, SecurityAgentExecutionSchemaVersion} {
		repository := &PostgresRepository{database: database, schema: schema, securityAgentExecution: true}
		if repository.readySecurityAgentAuthority(ctx) == nil {
			return repository, nil
		}
	}
	return nil, ErrRepositoryConfiguration
}

func (repository *PostgresRepository) GetSecurityAgentActivation(ctx context.Context, identity RequestIdentity, definitionID string) (SecurityAgentActivationState, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(definitionID) {
		return SecurityAgentActivationState{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentDefinitionActivationSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), definitionID)
	if err != nil {
		return SecurityAgentActivationState{}, discoveryProviderError(err)
	}
	var wire struct {
		OrganizationID    string          `json:"organization_id"`
		WorkspaceID       string          `json:"workspace_id"`
		EnvironmentID     string          `json:"environment_id"`
		DefinitionID      string          `json:"definition_id"`
		Activation        string          `json:"activation"`
		Version           int64           `json:"version"`
		DefinitionVersion int64           `json:"definition_version"`
		Body              json.RawMessage `json:"body"`
		UpdatedAt         time.Time       `json:"updated_at"`
	}
	var body struct {
		ID                     string   `json:"id"`
		Name                   string   `json:"name"`
		TriggerKind            string   `json:"trigger_kind"`
		TriggerSource          string   `json:"trigger_source"`
		EnvironmentIDs         []string `json:"environment_ids"`
		Autonomy               string   `json:"autonomy"`
		MaxSteps               int      `json:"max_steps"`
		MaxDurationSeconds     int      `json:"max_duration_seconds"`
		TemporaryPolicySeconds int      `json:"temporary_policy_seconds"`
		AITokenBudget          int      `json:"ai_token_budget"`
		ConcurrencyLimit       int      `json:"concurrency_limit"`
		AllowedActions         []string `json:"allowed_actions"`
		VerificationKind       string   `json:"verification_kind"`
		DefinitionVersion      int      `json:"definition_version"`
		Enabled                bool     `json:"enabled"`
	}
	if !exactJSONFields(payload, "activation", "body", "definition_id", "definition_version", "environment_id", "organization_id", "updated_at", "version", "workspace_id") || decodeStrictDiscovery(payload, &wire) != nil || !exactJSONFields(wire.Body, "ai_token_budget", "allowed_actions", "autonomy", "concurrency_limit", "definition_version", "enabled", "environment_ids", "id", "max_duration_seconds", "max_steps", "name", "temporary_policy_seconds", "trigger_kind", "trigger_source", "verification_kind") || decodeStrictDiscovery(wire.Body, &body) != nil || wire.OrganizationID != identity.Scope.OrganizationID().String() || wire.WorkspaceID != identity.Scope.WorkspaceID().String() || wire.EnvironmentID != identity.Scope.EnvironmentID().String() || wire.DefinitionID != definitionID || body.ID != definitionID || int64(body.DefinitionVersion) != wire.DefinitionVersion || !stringIn(wire.Activation, "draft", "validated", "supervised", "autonomous") || body.Enabled != (wire.Activation == "supervised" || wire.Activation == "autonomous") || wire.Version < 1 || wire.Version > 1000000 || wire.DefinitionVersion < 1 || wire.DefinitionVersion > 1000000 || wire.UpdatedAt.IsZero() || wire.UpdatedAt.Location() != time.UTC {
		return SecurityAgentActivationState{}, ErrRepositoryUnavailable
	}
	definition := securityagent.SecurityAgent{ID: body.ID, OrganizationID: wire.OrganizationID, Name: body.Name, Trigger: securityagent.Trigger{Kind: body.TriggerKind, Source: body.TriggerSource}, Scope: securityagent.Scope{OrganizationID: wire.OrganizationID, EnvironmentIDs: body.EnvironmentIDs}, Autonomy: securityagent.Autonomy(body.Autonomy), Limits: securityagent.RunLimits{MaxSteps: body.MaxSteps, MaxDuration: time.Duration(body.MaxDurationSeconds) * time.Second, TemporaryPolicyTTL: time.Duration(body.TemporaryPolicySeconds) * time.Second, MaxAITokens: body.AITokenBudget, MaxConcurrent: body.ConcurrencyLimit}, AllowedActions: body.AllowedActions, Verification: securityagent.Verification{Kind: body.VerificationKind}, DefinitionVersion: body.DefinitionVersion, Enabled: body.Enabled}
	if securityagent.ValidateAgent(definition) != nil || !exactWorkflowEnvironment(body.EnvironmentIDs, wire.EnvironmentID) || !servedWorkflowActions(body.AllowedActions) {
		return SecurityAgentActivationState{}, ErrRepositoryUnavailable
	}
	return SecurityAgentActivationState{ID: wire.DefinitionID, Activation: wire.Activation, Enabled: body.Enabled, Version: wire.Version}, nil
}

func (repository *PostgresRepository) SimulateSecurityAgent(ctx context.Context, identity RequestIdentity, input SecurityAgentSimulationRequest) (SecurityAgentSimulationResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(input.DefinitionID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validProductID(input.RunID) || !validSecurityAgentText(input.Goal, 1024) || len(input.EvidenceIDs) < 1 || len(input.EvidenceIDs) > 100 || !validUniqueProductIDs(input.EvidenceIDs) || input.ExpiresAt.IsZero() || input.ExpiresAt.Location() != time.UTC || !input.ExpiresAt.After(time.Now().UTC()) || input.ExpiresAt.After(time.Now().UTC().Add(16*time.Minute)) || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) {
		return SecurityAgentSimulationResult{}, ErrRepositoryOperation
	}
	evidence, err := json.Marshal(input.EvidenceIDs)
	if err != nil {
		return SecurityAgentSimulationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentSimulateSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.DefinitionID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.Goal, json.RawMessage(evidence), input.ExpiresAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentSimulationResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentSimulationResult
	if !exactJSONFields(payload, "audit_id", "catalog_version", "correlation_id", "definition_id", "definition_version", "expires_at", "matched_evidence_ids", "plan_hash", "receipt_id", "replayed", "run_id", "side_effects", "steps", "summary", "version") || json.Unmarshal(payload, &result) != nil || !validSecurityAgentSimulation(result, input.DefinitionID, input.ExpectedVersion, input.EvidenceIDs, input.ExpiresAt) || !result.Replayed && (result.RunID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentSimulationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ActivateSecurityAgent(ctx context.Context, identity RequestIdentity, input SecurityAgentActivation) (SecurityAgentActivationResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || identity.FreshAuthExpiresAt.Location() != time.UTC || input.FreshAuthExpiresAt != identity.FreshAuthExpiresAt || !validProductID(input.DefinitionID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !stringIn(input.TargetActivation, "validated", "supervised", "autonomous") || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || input.AuditID == input.CorrelationID || input.AuditID == input.ReceiptID || input.CorrelationID == input.ReceiptID {
		return SecurityAgentActivationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActivateSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.DefinitionID,
		identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.TargetActivation, input.FreshAuthExpiresAt,
		input.AuditID, input.CorrelationID, input.ReceiptID,
	)
	if err != nil {
		return SecurityAgentActivationResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentActivationResult
	if !exactJSONFields(payload, "activation", "audit_id", "correlation_id", "enabled", "id", "receipt_id", "replayed", "version") || decodeStrictDiscovery(payload, &result) != nil || result.ID != input.DefinitionID || result.Activation != input.TargetActivation || result.Enabled != (input.TargetActivation == "supervised" || input.TargetActivation == "autonomous") || result.Version != input.ExpectedVersion+1 || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentActivationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) RunSecurityAgent(ctx context.Context, identity RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(input.DefinitionID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validProductID(input.RunID) || input.TriggerKind != "finding" || !validProductID(input.TriggerID) || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentRunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.DefinitionID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.TriggerKind, input.TriggerID, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentRunResult
	if !exactJSONFields(payload, "agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version") || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentRunResult(result, input) || !result.Replayed && (result.ID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ListSecurityAgentRuns(ctx context.Context, identity RequestIdentity, input SecurityAgentRunPageRequest) (SecurityAgentRunPage, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || input.DefinitionID != "" && !validProductID(input.DefinitionID) || input.State != "" && !validSecurityAgentRunState(input.State) || input.Limit < 1 || input.Limit > 100 || input.BeforeCreatedAt.IsZero() != (input.BeforeID == "") || !input.BeforeCreatedAt.IsZero() && (input.BeforeCreatedAt.Location() != time.UTC || !validProductID(input.BeforeID)) {
		return SecurityAgentRunPage{}, ErrRepositoryOperation
	}
	var before any
	if !input.BeforeCreatedAt.IsZero() {
		before = input.BeforeCreatedAt
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentRunPageSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.DefinitionID, input.State, before, input.BeforeID, input.Limit)
	if err != nil {
		return SecurityAgentRunPage{}, discoveryProviderError(err)
	}
	var wire struct {
		Items         []SecurityAgentRun `json:"items"`
		NextCreatedAt *time.Time         `json:"next_created_at"`
		NextID        *string            `json:"next_id"`
	}
	if !exactJSONFields(payload, "items", "next_created_at", "next_id") || decodeStrictDiscovery(payload, &wire) != nil || len(wire.Items) > input.Limit || (wire.NextCreatedAt == nil) != (wire.NextID == nil) {
		return SecurityAgentRunPage{}, ErrRepositoryUnavailable
	}
	for _, item := range wire.Items {
		if !validSecurityAgentRun(item) {
			return SecurityAgentRunPage{}, ErrRepositoryUnavailable
		}
	}
	page := SecurityAgentRunPage{Items: append([]SecurityAgentRun{}, wire.Items...), NextCreatedAt: wire.NextCreatedAt}
	if wire.NextID != nil {
		if wire.NextCreatedAt.IsZero() || wire.NextCreatedAt.Location() != time.UTC || !validProductID(*wire.NextID) {
			return SecurityAgentRunPage{}, ErrRepositoryUnavailable
		}
		page.NextID = *wire.NextID
	}
	return page, nil
}

func (repository *PostgresRepository) GetSecurityAgentRun(ctx context.Context, identity RequestIdentity, runID string) (SecurityAgentRunDetail, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(runID) {
		return SecurityAgentRunDetail{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentRunDetailSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), runID)
	if err != nil {
		return SecurityAgentRunDetail{}, discoveryProviderError(err)
	}
	var result SecurityAgentRunDetail
	if !exactJSONFields(payload, "approvals", "authorization", "evidence_ids", "execution", "plan", "run", "verification") || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentRunDetail(result, runID) {
		return SecurityAgentRunDetail{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) CancelSecurityAgentRun(ctx context.Context, identity RequestIdentity, input SecurityAgentCancelRequest) (SecurityAgentRunResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(input.RunID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentCancelRunSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.RunID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentRunResult
	read := SecurityAgentRun{ID: result.ID, AgentID: result.AgentID, State: result.State, EvidenceIDs: result.EvidenceIDs, DefinitionVersion: result.DefinitionVersion, Version: result.Version}
	if !exactJSONFields(payload, "agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version") || decodeStrictDiscovery(payload, &result) != nil {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	read = SecurityAgentRun{ID: result.ID, AgentID: result.AgentID, State: result.State, EvidenceIDs: result.EvidenceIDs, DefinitionVersion: result.DefinitionVersion, Version: result.Version}
	if result.ID != input.RunID || result.State != "cancelled" || result.Version != input.ExpectedVersion+1 || !validSecurityAgentRun(read) || !validProductID(result.AuditID) || !validProductID(result.CorrelationID) || !validProductID(result.ReceiptID) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) ListSecurityAgentApprovals(ctx context.Context, identity RequestIdentity, input SecurityAgentApprovalPageRequest) (SecurityAgentApprovalPage, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || input.State != "" && !validSecurityAgentApprovalState(input.State) || input.RunID != "" && !validProductID(input.RunID) || input.Limit < 1 || input.Limit > 100 || input.BeforeCreatedAt.IsZero() != (input.BeforeID == "") || !input.BeforeCreatedAt.IsZero() && (input.BeforeCreatedAt.Location() != time.UTC || !validProductID(input.BeforeID)) {
		return SecurityAgentApprovalPage{}, ErrRepositoryOperation
	}
	var before any
	if !input.BeforeCreatedAt.IsZero() {
		before = input.BeforeCreatedAt
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentApprovalPageSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.State, input.RunID, before, input.BeforeID, input.Limit)
	if err != nil {
		return SecurityAgentApprovalPage{}, discoveryProviderError(err)
	}
	var wire struct {
		Items         []SecurityAgentApproval `json:"items"`
		NextCreatedAt *time.Time              `json:"next_created_at"`
		NextID        *string                 `json:"next_id"`
	}
	if !exactJSONFields(payload, "items", "next_created_at", "next_id") || decodeStrictDiscovery(payload, &wire) != nil || len(wire.Items) > input.Limit || (wire.NextCreatedAt == nil) != (wire.NextID == nil) {
		return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
	}
	for _, item := range wire.Items {
		if !validSecurityAgentApproval(item) {
			return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
		}
	}
	page := SecurityAgentApprovalPage{Items: append([]SecurityAgentApproval{}, wire.Items...), NextCreatedAt: wire.NextCreatedAt}
	if wire.NextID != nil {
		if wire.NextCreatedAt.IsZero() || wire.NextCreatedAt.Location() != time.UTC || !validProductID(*wire.NextID) {
			return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
		}
		page.NextID = *wire.NextID
	}
	return page, nil
}

func (repository *PostgresRepository) GetSecurityAgentApproval(ctx context.Context, identity RequestIdentity, approvalID string) (SecurityAgentApproval, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(approvalID) {
		return SecurityAgentApproval{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentApprovalDetailSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), approvalID)
	if err != nil {
		return SecurityAgentApproval{}, discoveryProviderError(err)
	}
	var result SecurityAgentApproval
	if !exactJSONFields(payload, "evidence_summary", "expected_effect", "expires_at", "id", "reversible", "run_id", "state", "step_id", "ttl_seconds", "version") || decodeStrictDiscovery(payload, &result) != nil || result.ID != approvalID || !validSecurityAgentApproval(result) {
		return SecurityAgentApproval{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validSecurityAgentRunState(value string) bool {
	return stringIn(value, "queued", "planning", "waiting_approval", "running", "verifying", "contained", "remediated", "needs_human", "failed", "inconclusive", "cancelled")
}

func validSecurityAgentRun(value SecurityAgentRun) bool {
	return validProductID(value.ID) && validProductID(value.AgentID) && validSecurityAgentRunState(value.State) && len(value.EvidenceIDs) >= 1 && len(value.EvidenceIDs) <= 100 && validUniqueProductIDs(value.EvidenceIDs) && value.DefinitionVersion >= 1 && value.DefinitionVersion <= 1000000 && value.Version >= 1 && value.Version <= 1000000
}

func validSecurityAgentApprovalState(value string) bool {
	return stringIn(value, "pending", "approved", "rejected", "cancelled", "expired")
}

func validSecurityAgentApproval(value SecurityAgentApproval) bool {
	return validProductID(value.ID) && validProductID(value.RunID) && validProductID(value.StepID) && validSecurityAgentApprovalState(value.State) && !value.ExpiresAt.IsZero() && value.ExpiresAt.Location() == time.UTC && value.Version >= 1 && value.Version <= 1000000 && value.ExpectedEffect == "Move finding to under review" && value.Reversible && value.TTLSeconds == 0 && len(value.EvidenceSummary) == 1 && validProductID(value.EvidenceSummary[0])
}

func validSecurityAgentRunDetail(value SecurityAgentRunDetail, runID string) bool {
	if value.Run.ID != runID || !validSecurityAgentRun(value.Run) || !reflectStringSlices(value.EvidenceIDs, value.Run.EvidenceIDs) || !stringIn(value.Authorization, "not_planned", "authorized", "approval_required", "approved", "denied", "cancelled") || !stringIn(value.Verification, "not_started", "pending", "verified", "failed", "inconclusive") || len(value.Approvals) > 100 || len(value.Execution) > 100 {
		return false
	}
	for _, approval := range value.Approvals {
		if !validSecurityAgentApproval(approval) || approval.RunID != runID || !reflectStringSlices(approval.EvidenceSummary, value.EvidenceIDs) {
			return false
		}
	}
	if value.Plan == nil {
		return value.Authorization == "not_planned" && len(value.Approvals) == 0 && len(value.Execution) == 0
	}
	if !securityAgentPlanHashPattern.MatchString(value.Plan.PlanHash) || value.Plan.CatalogVersion != "security-agent-actions-v1" || value.Plan.ExpiresAt.IsZero() || value.Plan.ExpiresAt.Location() != time.UTC || len(value.Plan.Steps) < 1 || len(value.Plan.Steps) > 100 || len(value.Execution) != len(value.Plan.Steps) {
		return false
	}
	seenSteps := make(map[string]struct{}, len(value.Plan.Steps))
	for index, step := range value.Plan.Steps {
		if !validProductID(step.ID) || step.Index != index || !validSecurityAgentText(step.Action, 128) || !stringIn(step.Authorization, "allow", "approval_required", "autonomous", "deny") || !stringIn(step.State, "queued", "authorized", "waiting_approval", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled") || step.Version < 1 || step.Version > 1000000 {
			return false
		}
		seenSteps[step.ID] = struct{}{}
	}
	for _, execution := range value.Execution {
		if _, ok := seenSteps[execution.StepID]; !ok || !validSecurityAgentText(execution.Action, 128) || !stringIn(execution.State, "queued", "authorized", "waiting_approval", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled") || execution.OutcomeID != "" && !validProductID(execution.OutcomeID) || execution.ResultDigest != "" && !securityAgentPlanHashPattern.MatchString(execution.ResultDigest) || execution.Version < 1 || execution.Version > 1000000 {
			return false
		}
	}
	return true
}

func (repository *PostgresRepository) DecideSecurityAgentApproval(ctx context.Context, identity RequestIdentity, input SecurityAgentApprovalDecisionRequest) (SecurityAgentApprovalResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || identity.FreshAuthExpiresAt.Location() != time.UTC || !validProductID(input.ApprovalID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !stringIn(input.Decision, "approved", "rejected", "cancelled") || input.FreshAuthAt.IsZero() || input.FreshAuthAt.Location() != time.UTC || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) {
		return SecurityAgentApprovalResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentDecideApprovalSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.ApprovalID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.Decision, input.FreshAuthAt, input.AuditID, input.CorrelationID, input.ReceiptID)
	if err != nil {
		return SecurityAgentApprovalResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentApprovalResult
	if !exactJSONFields(payload, "audit_id", "correlation_id", "evidence_summary", "expected_effect", "expires_at", "id", "receipt_id", "replayed", "reversible", "run_id", "state", "step_id", "ttl_seconds", "version") || decodeStrictDiscovery(payload, &result) != nil || !validSecurityAgentApprovalResult(result, input) || !result.Replayed && (result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentApprovalResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *PostgresRepository) readySecurityAgentAuthority(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	statement := postgresSecurityAgentAuthorityReadySQL
	metadata := migrations.ProductionSecurityAgentExecution()
	fingerprint := migrations.ProductionSecurityAgentExecutionSemanticFingerprint()
	if repository.schema == SecurityAgentAutonomousSchemaVersion {
		statement = postgresSecurityAgentAutonomousReadySQL
		metadata = migrations.ProductionSecurityAgentAutonomousResponse()
		fingerprint = migrations.ProductionSecurityAgentAutonomousResponseSemanticFingerprint()
	} else if repository.schema == SecurityAgentControlsSchemaVersion {
		statement = postgresSecurityAgentControlsReadySQL
		metadata = migrations.ProductionSecurityAgentControls()
		fingerprint = migrations.ProductionSecurityAgentControlsSemanticFingerprint()
	} else if repository.schema == IdentityAdministrationSchemaVersion {
		statement = postgresIdentityAdminSecurityAgentReadySQL
		metadata = migrations.ProductionIdentityAdministration()
		fingerprint = migrations.ProductionIdentityAdministrationSemanticFingerprint()
	}
	payload, err := repository.database.QueryJSON(ctx, statement, metadata.Checksum(), fingerprint)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	var raw map[string]json.RawMessage
	var result struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 2 || raw["release"] == nil || raw["principal"] == nil || json.Unmarshal(payload, &result) != nil || !result.Release || !result.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}
