package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const CoreSchemaVersion = "production-core-v1"

const (
	postgresAuthenticateSessionSQL = `SELECT jsonb_build_object('principal_id', principal_id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'csrf_token', csrf_token) FROM zasp_product_sessions WHERE token_digest = digest($1, 'sha256') AND revoked_at IS NULL AND expires_at > now()`
	postgresBootstrapSQL           = `SELECT zasp_session_bootstrap($1, $2, $3, $4)`
	postgresCoreReadSQL            = `SELECT zasp_core_read($1, $2, $3, $4, $5)`
	postgresCoreWriteSQL           = `SELECT zasp_core_write($1, $2, $3, $4, $5, $6::jsonb)`
	postgresRevokeSessionSQL       = `UPDATE zasp_product_sessions SET revoked_at = now() WHERE token_digest = digest($1, 'sha256') AND organization_id = $2 AND principal_id = $3`
)

var (
	ErrRepositoryConfiguration  = errors.New("production repository configuration rejected")
	ErrRepositoryAuthentication = errors.New("repository authentication rejected")
	ErrRepositoryNotFound       = errors.New("repository record not found")
	ErrRepositoryOperation      = errors.New("repository operation rejected")
)

type JSONDatabase interface {
	SchemaVersion(context.Context) (string, error)
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
	Exec(context.Context, string, ...any) error
}

type PostgresRepository struct{ database JSONDatabase }

func NewPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != CoreSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresRepository{database: database}, nil
}

func (repository *PostgresRepository) Authenticate(ctx context.Context, credential Credential) (RequestIdentity, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || credential.Value == "" || credential.Kind != CredentialBrowserSession && credential.Kind != CredentialBearerToken {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	payload, err := repository.database.QueryJSON(ctx, postgresAuthenticateSessionSQL, credential.Value)
	if err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	var value struct {
		PrincipalID, OrganizationID, WorkspaceID, EnvironmentID string
		CSRFToken                                               string
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	principal, principalErr := domain.ParseProductID(value.PrincipalID)
	organization, organizationErr := domain.ParseProductID(value.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(value.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(value.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, CSRFToken: value.CSRFToken}
	if principalErr != nil || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || !validRequestIdentity(identity, credential.Kind == CredentialBrowserSession) {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	return identity, nil
}

func (repository *PostgresRepository) Bootstrap(ctx context.Context, identity RequestIdentity) (json.RawMessage, error) {
	if !validRequestIdentity(identity, true) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresBootstrapSQL, identity.PrincipalID.String(), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	return validJSONObject(payload, err)
}

func (repository *PostgresRepository) Read(ctx context.Context, scope domain.Scope, operation string) (json.RawMessage, error) {
	if scope.Validate() != nil || operation == "" {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresCoreReadSQL, operation, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	return validJSONObject(payload, err)
}

func (repository *PostgresRepository) Write(ctx context.Context, scope domain.Scope, operation string, input json.RawMessage) (json.RawMessage, error) {
	if scope.Validate() != nil || operation == "" || !json.Valid(input) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresCoreWriteSQL, operation, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), input)
	return validJSONObject(payload, err)
}

func (repository *PostgresRepository) Revoke(ctx context.Context, identity RequestIdentity, token string) error {
	if !validRequestIdentity(identity, true) || token == "" || repository.database.Exec(ctx, postgresRevokeSessionSQL, token, identity.Scope.OrganizationID().String(), identity.PrincipalID.String()) != nil {
		return ErrRepositoryOperation
	}
	return nil
}

func validJSONObject(payload json.RawMessage, err error) (json.RawMessage, error) {
	if err != nil {
		if errors.Is(err, ErrRepositoryNotFound) {
			return nil, ErrRepositoryNotFound
		}
		return nil, ErrRepositoryOperation
	}
	if len(payload) == 0 || !json.Valid(payload) || payload[0] != '{' {
		return nil, ErrRepositoryOperation
	}
	return append(json.RawMessage(nil), payload...), nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func scopeKey(scope domain.Scope) string {
	return scope.OrganizationID().String() + "/" + scope.WorkspaceID().String() + "/" + scope.EnvironmentID().String()
}

func identityJSON(identity RequestIdentity) map[string]any {
	return map[string]any{"PrincipalID": identity.PrincipalID.String(), "OrganizationID": identity.Scope.OrganizationID().String(), "WorkspaceID": identity.Scope.WorkspaceID().String(), "EnvironmentID": identity.Scope.EnvironmentID().String(), "CSRFToken": identity.CSRFToken}
}

func bootstrapJSON(identity RequestIdentity) map[string]any {
	return map[string]any{
		"principal":       map[string]any{"id": identity.PrincipalID.String(), "organization_id": identity.Scope.OrganizationID().String(), "organization_reference": "organization-live", "member_reference": "member-live", "role": "security_admin", "active": true},
		"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(),
		"permissions": []string{"view", "manage_findings"}, "capabilities": []string{"inventory.read", "findings.read", "findings.manage", "attack_paths.read"},
		"csrf_token": identity.CSRFToken, "correlation_id": fallbackCorrelationID,
	}
}
