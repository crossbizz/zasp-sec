package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresSecurityAgentAuthorityReadySQL   = `SELECT jsonb_build_object('release',zasp_security_agent_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_api'))`
	postgresSecurityAgentDefinitionPageSQL   = `SELECT zasp_security_agent_definition_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresSecurityAgentDefinitionValueSQL  = `SELECT zasp_security_agent_definition_value($1,$2,$3,$4)`
	postgresSecurityAgentDefinitionReplaySQL = `SELECT zasp_security_agent_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb)`
	postgresSecurityAgentDefinitionMutateSQL = `SELECT zasp_security_agent_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14)`
	postgresSecurityAgentActivateSQL         = `SELECT zasp_security_agent_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
)

func NewSecurityAgentPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	repository := &PostgresRepository{database: database, schema: SecurityAgentExecutionSchemaVersion, securityAgentExecution: true}
	if repository.readySecurityAgentAuthority(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
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

func (repository *PostgresRepository) readySecurityAgentAuthority(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentAuthorityReadySQL, migrations.ProductionSecurityAgentExecution().Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint())
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
