package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	ReferenceSchemaVersion                    = "reference-authorization-v1"
	postgresReferenceAuthorizationReadySQL    = `SELECT to_jsonb(zasp_reference_authorization_readiness($1,$2))`
	postgresReplayReferenceAuthorizationSQL   = `SELECT zasp_reference_authorization_replay($1,$2,$3,$4,$5,$6,$7)`
	postgresCompleteReferenceAuthorizationSQL = `SELECT zasp_complete_reference_authorization($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15)`
	referenceAuthorizationOperation           = "completeIntegrationReferenceAuthorization"
)

type ReferenceAuthorizationCompletion struct {
	IntegrationID, Provider, ConnectionID, ConnectionReference string
	IdempotencyKey                                             string
	ExpectedVersion                                            int64
	Configuration, Intent                                      json.RawMessage
	AuditID, CorrelationID, ReceiptID                          string
}

type ReferenceAuthorizationReplay struct {
	IntegrationID, IdempotencyKey string
	ExpectedVersion               int64
}

type ReferenceAuthorizationAuthority interface {
	Replay(context.Context, RequestIdentity, ReferenceAuthorizationReplay) (WorkflowMutationResult, bool, error)
	Complete(context.Context, RequestIdentity, ReferenceAuthorizationCompletion) (WorkflowMutationResult, error)
}

type ReferenceAuthorizationRepository struct{ database JSONDatabase }

func NewReferenceAuthorizationRepository(database JSONDatabase) (*ReferenceAuthorizationRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != ReferenceSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	repository := &ReferenceAuthorizationRepository{database: database}
	if err := repository.Ready(context.Background()); err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *ReferenceAuthorizationRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	version, err := repository.database.SchemaVersion(ctx)
	if err != nil || version != ReferenceSchemaVersion {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresReferenceAuthorizationReadySQL, migrations.ReferenceAuthorization().Checksum(), migrations.ReferenceAuthorizationSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *ReferenceAuthorizationRepository) Replay(ctx context.Context, identity RequestIdentity, input ReferenceAuthorizationReplay) (WorkflowMutationResult, bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validProductID(input.IntegrationID) || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 {
		return WorkflowMutationResult{}, false, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresReplayReferenceAuthorizationSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IntegrationID, input.IdempotencyKey, input.ExpectedVersion)
	if err != nil {
		return WorkflowMutationResult{}, false, discoveryProviderError(err)
	}
	var envelope struct {
		Found  bool                   `json:"found"`
		Result WorkflowMutationResult `json:"result"`
	}
	if decodeStrictDiscovery(payload, &envelope) != nil {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	if !envelope.Found {
		return WorkflowMutationResult{}, false, nil
	}
	mutation := WorkflowMutation{Action: "update", Kind: "integration", ID: input.IntegrationID, Operation: referenceAuthorizationOperation, IdempotencyKey: input.IdempotencyKey, ExpectedVersion: input.ExpectedVersion, ReceiptID: envelope.Result.ReceiptID}
	if envelope.Result.Version != input.ExpectedVersion+1 || envelope.Result.SecretGeneration < 0 || !canonicalReferenceAuthorizationResult(&envelope.Result, input.IntegrationID, "") || !validMutationResultIDs(envelope.Result, mutation) || !validMutationReceiptIdentity(identity, envelope.Result.ReceiptID) || !envelope.Result.Replayed {
		return WorkflowMutationResult{}, false, ErrRepositoryUnavailable
	}
	return envelope.Result, true, nil
}

func (repository *ReferenceAuthorizationRepository) Complete(ctx context.Context, identity RequestIdentity, input ReferenceAuthorizationCompletion) (WorkflowMutationResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validReferenceAuthorizationCompletion(input) {
		return WorkflowMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresCompleteReferenceAuthorizationSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.IntegrationID, input.Provider, input.ConnectionID, input.ConnectionReference, input.IdempotencyKey, input.ExpectedVersion,
		input.Configuration, input.Intent, input.AuditID, input.CorrelationID, input.ReceiptID,
	)
	if err != nil {
		return WorkflowMutationResult{}, discoveryProviderError(err)
	}
	var result WorkflowMutationResult
	mutation := WorkflowMutation{Action: "update", Kind: "integration", ID: input.IntegrationID, Operation: referenceAuthorizationOperation, IdempotencyKey: input.IdempotencyKey, ExpectedVersion: input.ExpectedVersion, Intent: input.Intent, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}
	if decodeStrictDiscovery(payload, &result) != nil || result.Version != input.ExpectedVersion+1 || result.SecretGeneration < 0 || !canonicalReferenceAuthorizationResult(&result, input.IntegrationID, input.Provider) || !validMutationResultIDs(result, mutation) {
		return WorkflowMutationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

type referenceAuthorizedIntegration struct {
	ID            string          `json:"id"`
	ConnectorKey  string          `json:"connector_key"`
	Name          string          `json:"name"`
	Configuration json.RawMessage `json:"configuration"`
	Status        string          `json:"status"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
}

func canonicalReferenceAuthorizationResult(result *WorkflowMutationResult, integrationID, expectedProvider string) bool {
	if result == nil {
		return false
	}
	if len(result.Body) < 2 || len(result.Body) > 16<<10 || !validJSONObjectBody(result.Body) {
		return false
	}
	var value referenceAuthorizedIntegration
	if decodeStrictDiscovery(result.Body, &value) != nil || value.ID != integrationID || !validProductID(value.ID) || !stringIn(value.ConnectorKey, "aws", "kubernetes") || expectedProvider != "" && value.ConnectorKey != expectedProvider || value.Status != "active" || len(value.Name) < 1 || len(value.Name) > 128 || strings.TrimSpace(value.Name) != value.Name {
		return false
	}
	configuration, _, valid := parseReferenceAuthorizationConfiguration(value.ConnectorKey, value.Configuration)
	createdAt, createdErr := time.Parse(time.RFC3339Nano, value.CreatedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, value.UpdatedAt)
	if !valid || createdErr != nil || updatedErr != nil || createdAt.Location() != time.UTC || updatedAt.Location() != time.UTC || updatedAt.Before(createdAt) {
		return false
	}
	value.Configuration = configuration
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > 16<<10 {
		return false
	}
	result.Body = canonical
	return true
}

func referenceAuthorizationIntent(identity RequestIdentity, integrationID, provider, idempotencyKey string, expectedVersion int64, configuration json.RawMessage) json.RawMessage {
	intent, _ := json.Marshal(map[string]any{
		"configuration":    json.RawMessage(configuration),
		"expected_version": expectedVersion,
		"idempotency_key":  idempotencyKey,
		"integration_id":   integrationID,
		"provider":         provider,
		"scope": map[string]string{
			"environment_id":  identity.Scope.EnvironmentID().String(),
			"organization_id": identity.Scope.OrganizationID().String(),
			"workspace_id":    identity.Scope.WorkspaceID().String(),
		},
	})
	return intent
}

func validReferenceAuthorizationCompletion(input ReferenceAuthorizationCompletion) bool {
	if !validProductID(input.IntegrationID) || !validProductID(input.ConnectionID) || !stringIn(input.Provider, "aws", "kubernetes") || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 || !workflowKeyPattern.MatchString(input.IdempotencyKey) || input.ExpectedVersion < 1 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) || !validJSONObjectBody(input.Configuration) || !validJSONObjectBody(input.Intent) {
		return false
	}
	configuration, reference, valid := parseReferenceAuthorizationConfiguration(input.Provider, input.Configuration)
	return valid && reference == input.ConnectionReference && json.Valid(configuration)
}

func parseReferenceAuthorizationConfiguration(provider string, raw json.RawMessage) (json.RawMessage, string, bool) {
	if !validJSONObjectBody(raw) || len(raw) > 4096 {
		return nil, "", false
	}
	switch provider {
	case "aws":
		var value struct {
			RoleARN             string `json:"role_arn"`
			ExternalIDReference string `json:"external_id_reference"`
			Region              string `json:"region"`
		}
		if decodeStrictDiscovery(raw, &value) != nil || !validAWSReferenceConfiguration(value.RoleARN, value.ExternalIDReference, value.Region) {
			return nil, "", false
		}
		canonical, _ := json.Marshal(value)
		return canonical, value.ExternalIDReference, true
	case "kubernetes":
		var value struct {
			ConnectionReference string `json:"connection_reference"`
		}
		if decodeStrictDiscovery(raw, &value) != nil || !validKubernetesConnectionReference(value.ConnectionReference) {
			return nil, "", false
		}
		canonical, _ := json.Marshal(value)
		return canonical, value.ConnectionReference, true
	default:
		return nil, "", false
	}
}

func referenceConnectionID(scope domain.Scope, integrationID, provider string) string {
	return connectorDeterministicID(scope, integrationID, "reference-connection:"+provider)
}
