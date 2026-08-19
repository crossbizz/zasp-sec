package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const CoreSchemaVersion = "production-core-v1"

const (
	postgresAuthenticateSessionSQL = `SELECT jsonb_build_object('principal_id', principal_id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'permissions', permissions, 'csrf_token', csrf_token) FROM zasp_product_sessions WHERE token_digest = digest($1, 'sha256') AND revoked_at IS NULL AND expires_at > now()`
	postgresAuthenticatePATSQL     = `SELECT jsonb_build_object('principal_id', principal_id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'permissions', permissions) FROM zasp_product_api_tokens WHERE token_digest = digest($1, 'sha256') AND revoked_at IS NULL AND expires_at > now()`
	postgresCreateSessionSQL       = `SELECT zasp_create_product_session($1, $2, $3, $4, $5, $6, $7::jsonb, $8)`
	postgresBootstrapSQL           = `SELECT zasp_session_bootstrap($1, $2, $3, $4)`
	postgresCoreReadSQL            = `SELECT zasp_core_read($1, $2, $3, $4)`
	postgresRevokeSessionSQL       = `UPDATE zasp_product_sessions SET revoked_at = now() WHERE token_digest = digest($1, 'sha256') AND organization_id = $2 AND principal_id = $3`
)

var (
	ErrRepositoryConfiguration  = errors.New("production repository configuration rejected")
	ErrRepositoryAuthentication = errors.New("repository authentication rejected")
	ErrRepositoryNotFound       = errors.New("repository record not found")
	ErrRepositoryOperation      = errors.New("repository operation rejected")
	ErrRepositoryUnavailable    = errors.New("repository provider unavailable")
	ErrRepositoryConflict       = errors.New("repository operation conflict")
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

func (repository *PostgresRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	version, err := repository.database.SchemaVersion(ctx)
	if err != nil || version != CoreSchemaVersion {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *PostgresRepository) Authenticate(ctx context.Context, credential Credential) (RequestIdentity, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || credential.Value == "" || credential.Kind != CredentialBrowserSession && credential.Kind != CredentialBearerToken {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	statement := postgresAuthenticateSessionSQL
	if credential.Kind == CredentialBearerToken {
		statement = postgresAuthenticatePATSQL
	}
	payload, err := repository.database.QueryJSON(ctx, statement, credential.Value)
	if err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	identity, err := identityFromJSON(payload, credential.Kind == CredentialBrowserSession)
	if err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	return identity, nil
}

func identityFromJSON(payload json.RawMessage, requireCSRF bool) (RequestIdentity, error) {
	var value struct {
		PrincipalID    string   `json:"principal_id"`
		OrganizationID string   `json:"organization_id"`
		WorkspaceID    string   `json:"workspace_id"`
		EnvironmentID  string   `json:"environment_id"`
		Permissions    []string `json:"permissions"`
		CSRFToken      string   `json:"csrf_token"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return RequestIdentity{}, err
	}
	principal, principalErr := domain.ParseProductID(value.PrincipalID)
	organization, organizationErr := domain.ParseProductID(value.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(value.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(value.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: append([]string(nil), value.Permissions...), CSRFToken: value.CSRFToken}
	if principalErr != nil || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || !validRequestIdentity(identity, requireCSRF) {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	return identity, nil
}

func (repository *PostgresRepository) CreateSession(ctx context.Context, grant SessionGrant) (string, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validSessionGrant(grant) {
		return "", ErrRepositoryOperation
	}
	token, tokenErr := randomCredential()
	csrf, csrfErr := randomCredential()
	permissions, permissionsErr := json.Marshal(grant.Permissions)
	if tokenErr != nil || csrfErr != nil || permissionsErr != nil {
		return "", ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresCreateSessionSQL,
		token, csrf, grant.PrincipalID.String(), grant.Scope.OrganizationID().String(), grant.Scope.WorkspaceID().String(), grant.Scope.EnvironmentID().String(), json.RawMessage(permissions), grant.ExpiresAt)
	if err != nil {
		return "", ErrRepositoryUnavailable
	}
	identity, err := identityFromJSON(payload, true)
	if err != nil || identity.PrincipalID != grant.PrincipalID || identity.Scope != grant.Scope || identity.CSRFToken != csrf || !equalPermissionSets(identity.Permissions, grant.Permissions) {
		return "", ErrRepositoryUnavailable
	}
	return token, nil
}

func validSessionGrant(grant SessionGrant) bool {
	identity := RequestIdentity{PrincipalID: grant.PrincipalID, Scope: grant.Scope, Permissions: grant.Permissions}
	now := time.Now().UTC()
	return validRequestIdentity(identity, false) && grant.ExpiresAt.Location() == time.UTC && grant.ExpiresAt.After(now) && !grant.ExpiresAt.After(now.Add(24*time.Hour))
}

func randomCredential() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func equalPermissionSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
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
		if errors.Is(err, ErrRepositoryUnavailable) {
			return nil, ErrRepositoryUnavailable
		}
		if errors.Is(err, ErrRepositoryConflict) {
			return nil, ErrRepositoryConflict
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
	return map[string]any{"principal_id": identity.PrincipalID.String(), "organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "permissions": identity.Permissions, "csrf_token": identity.CSRFToken}
}

func bootstrapJSON(identity RequestIdentity) map[string]any {
	return map[string]any{
		"principal":       map[string]any{"id": identity.PrincipalID.String(), "organization_id": identity.Scope.OrganizationID().String(), "organization_reference": "organization-live", "member_reference": "member-live", "role": "security_admin", "active": true},
		"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(),
		"permissions": []string{"view"}, "capabilities": []string{"inventory.read"},
		"csrf_token": identity.CSRFToken, "correlation_id": fallbackCorrelationID,
	}
}
