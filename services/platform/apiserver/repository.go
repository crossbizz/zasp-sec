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
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

const CoreSchemaVersion = "production-risk-projection-v1"
const DiscoverySchemaVersion = "production-discovery-v1"
const ConnectorSchemaVersion = "connector-authorization-v1"

const (
	postgresAuthenticateSessionSQL = `SELECT jsonb_build_object('principal_id', session.principal_id, 'organization_id', session.organization_id, 'workspace_id', session.workspace_id, 'environment_id', session.environment_id, 'permissions', zasp_effective_scope_permissions(scope.permissions, membership.role), 'csrf_token', session.csrf_token, 'fresh_authenticated', session.authenticated_at > now() - interval '5 minutes', 'fresh_auth_expires_at', session.authenticated_at + interval '5 minutes') FROM zasp_product_sessions AS session JOIN zasp_identity_memberships AS membership ON membership.principal_id = session.principal_id AND membership.organization_id = session.organization_id AND membership.active JOIN zasp_authorized_scopes AS scope ON scope.principal_id = session.principal_id AND scope.organization_id = session.organization_id AND scope.workspace_id = session.workspace_id AND scope.environment_id = session.environment_id WHERE session.token_digest = digest($1, 'sha256') AND session.revoked_at IS NULL AND session.expires_at > now()`
	postgresAuthenticatePATSQL     = `WITH used AS (UPDATE zasp_product_api_tokens SET last_used_at=transaction_timestamp() WHERE token_digest=digest($1,'sha256') AND revoked_at IS NULL AND expires_at>now() RETURNING *) SELECT jsonb_build_object('principal_id', token.principal_id, 'organization_id', token.organization_id, 'workspace_id', token.workspace_id, 'environment_id', token.environment_id, 'permissions', (SELECT COALESCE(jsonb_agg(permission ORDER BY permission), '[]'::jsonb) FROM jsonb_array_elements_text(token.permissions) AS permission WHERE zasp_effective_scope_permissions(scope.permissions, membership.role) ? permission)) FROM used AS token JOIN zasp_identity_memberships AS membership ON membership.principal_id = token.principal_id AND membership.organization_id = token.organization_id AND membership.active JOIN zasp_authorized_scopes AS scope ON scope.principal_id = token.principal_id AND scope.organization_id = token.organization_id AND scope.workspace_id = token.workspace_id AND scope.environment_id = token.environment_id`
	postgresCreateSessionSQL       = `WITH created AS (SELECT zasp_create_product_session($1, $2, $3, $4, $5, $6, $7::jsonb, $8) AS value) SELECT value || jsonb_build_object('fresh_authenticated', true, 'fresh_auth_expires_at', transaction_timestamp() + interval '5 minutes') FROM created`
	postgresBootstrapSQL           = `SELECT payload || jsonb_build_object('principal', jsonb_build_object('id', membership.principal_id, 'organization_id', membership.organization_id, 'organization_reference', membership.organization_reference, 'member_reference', membership.member_reference, 'role', membership.role, 'active', membership.active)) FROM zasp_core_payloads AS payloads JOIN zasp_identity_memberships AS membership ON membership.principal_id = $1 AND membership.organization_id = $2 AND membership.active WHERE payloads.organization_id = $2 AND payloads.workspace_id = $3 AND payloads.environment_id = $4 AND payloads.operation = 'session_bootstrap:' || $1`
	postgresCoreReadSQL            = `SELECT zasp_core_read($1, $2, $3, $4)`
	postgresRevokeSessionSQL       = `UPDATE zasp_product_sessions SET revoked_at = now() WHERE token_digest = digest($1, 'sha256') AND organization_id = $2 AND principal_id = $3`
	postgresListScopesSQL          = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(jsonb_build_object('organization_id', organization_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'label', label) ORDER BY label, workspace_id, environment_id), '[]'::jsonb)) FROM zasp_authorized_scopes WHERE principal_id = $1 AND organization_id = $2`
	postgresSwitchScopeSQL         = `WITH authorized AS (SELECT scope.workspace_id, scope.environment_id, zasp_effective_scope_permissions(scope.permissions, membership.role) AS permissions FROM zasp_authorized_scopes AS scope JOIN zasp_identity_memberships AS membership ON membership.principal_id = scope.principal_id AND membership.organization_id = scope.organization_id AND membership.active WHERE scope.principal_id = $3 AND scope.organization_id = $4 AND scope.workspace_id = $5 AND scope.environment_id = $6), updated AS (UPDATE zasp_product_sessions AS session SET workspace_id = authorized.workspace_id, environment_id = authorized.environment_id, permissions = authorized.permissions, csrf_token = $2 FROM authorized WHERE session.token_digest = digest($1, 'sha256') AND session.principal_id = $3 AND session.organization_id = $4 AND session.revoked_at IS NULL AND session.expires_at > now() RETURNING session.principal_id, session.organization_id, session.workspace_id, session.environment_id, session.permissions, session.csrf_token, session.authenticated_at) SELECT jsonb_build_object('principal_id', principal_id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'permissions', permissions, 'csrf_token', csrf_token, 'fresh_authenticated', authenticated_at > now() - interval '5 minutes', 'fresh_auth_expires_at', authenticated_at + interval '5 minutes') FROM updated`
	postgresResolveIdentitySQL     = `SELECT jsonb_build_object('principal_id', membership.principal_id, 'organization_id', membership.organization_id, 'organization_reference', membership.organization_reference, 'member_reference', membership.member_reference, 'role', membership.role, 'active', membership.active, 'workspace_id', scope.workspace_id, 'environment_id', scope.environment_id, 'permissions', zasp_effective_scope_permissions(scope.permissions, membership.role)) FROM zasp_identity_memberships AS membership JOIN zasp_authorized_scopes AS scope ON scope.principal_id = membership.principal_id AND scope.organization_id = membership.organization_id AND scope.is_default WHERE membership.organization_reference = $1 AND membership.member_reference = $2`
	postgresBeginIdentitySQL       = `INSERT INTO zasp_identity_states (state_digest, return_path, expires_at) VALUES (digest($1, 'sha256'), $2, now() + interval '10 minutes')`
	postgresConsumeIdentitySQL     = `WITH consumed AS (UPDATE zasp_identity_states SET consumed_at = now() WHERE state_digest = digest($1, 'sha256') AND consumed_at IS NULL AND expires_at > now() RETURNING return_path) SELECT jsonb_build_object('return_path', return_path) FROM consumed`
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

type PostgresRepository struct {
	database           JSONDatabase
	connectorWorkflows bool
}

func NewPostgresRepository(database JSONDatabase) (*PostgresRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != CoreSchemaVersion && version != DiscoverySchemaVersion && version != ConnectorSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresRepository{database: database, connectorWorkflows: version == ConnectorSchemaVersion}, nil
}

func (repository *PostgresRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	version, err := repository.database.SchemaVersion(ctx)
	if err != nil || version != CoreSchemaVersion && version != DiscoverySchemaVersion && version != ConnectorSchemaVersion {
		return ErrRepositoryUnavailable
	}
	if _, err := repository.CleanupExpiredWorkflowMutationReceipts(ctx, 1000); err != nil {
		return ErrRepositoryUnavailable
	}
	if _, err := repository.CleanupExpiredAPITokenRevealGrants(ctx, 1000); err != nil {
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
	identity.CredentialKind = credential.Kind
	return identity, nil
}

func identityFromJSON(payload json.RawMessage, requireCSRF bool) (RequestIdentity, error) {
	var value struct {
		PrincipalID        string   `json:"principal_id"`
		OrganizationID     string   `json:"organization_id"`
		WorkspaceID        string   `json:"workspace_id"`
		EnvironmentID      string   `json:"environment_id"`
		Permissions        []string `json:"permissions"`
		CSRFToken          string   `json:"csrf_token"`
		FreshAuthenticated bool     `json:"fresh_authenticated"`
		FreshAuthExpiresAt string   `json:"fresh_auth_expires_at"`
	}
	if err := json.Unmarshal(payload, &value); err != nil {
		return RequestIdentity{}, err
	}
	principal, principalErr := domain.ParseProductID(value.PrincipalID)
	organization, organizationErr := domain.ParseProductID(value.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(value.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(value.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	var freshAuthExpiresAt time.Time
	if value.FreshAuthExpiresAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, value.FreshAuthExpiresAt)
		if parseErr != nil {
			return RequestIdentity{}, ErrRepositoryAuthentication
		}
		freshAuthExpiresAt = parsed.UTC()
	}
	identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: append([]string(nil), value.Permissions...), CSRFToken: value.CSRFToken, FreshAuthenticated: value.FreshAuthenticated, FreshAuthExpiresAt: freshAuthExpiresAt}
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
	if !validRequestIdentity(identity, false) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresBootstrapSQL, identity.PrincipalID.String(), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	payload, err = validJSONObject(payload, err)
	if err != nil || validateBootstrapMembership(payload, identity) != nil {
		return nil, ErrRepositoryOperation
	}
	return payload, nil
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

func (repository *PostgresRepository) ListScopes(ctx context.Context, identity RequestIdentity) (json.RawMessage, error) {
	if !validRequestIdentity(identity, true) {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresListScopesSQL, identity.PrincipalID.String(), identity.Scope.OrganizationID().String())
	return validJSONObject(payload, err)
}

func (repository *PostgresRepository) SwitchScope(ctx context.Context, identity RequestIdentity, token string, scope domain.Scope) (RequestIdentity, error) {
	if !validRequestIdentity(identity, true) || token == "" || scope.Validate() != nil || scope.OrganizationID() != identity.Scope.OrganizationID() {
		return RequestIdentity{}, ErrRepositoryNotFound
	}
	csrf := identity.CSRFToken
	payload, err := repository.database.QueryJSON(ctx, postgresSwitchScopeSQL, token, csrf, identity.PrincipalID.String(), identity.Scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		if errors.Is(err, ErrRepositoryNotFound) {
			return RequestIdentity{}, ErrRepositoryNotFound
		}
		return RequestIdentity{}, ErrRepositoryUnavailable
	}
	updated, err := identityFromJSON(payload, true)
	if err != nil || updated.Scope != scope || updated.PrincipalID != identity.PrincipalID {
		return RequestIdentity{}, ErrRepositoryUnavailable
	}
	return updated, nil
}

func (repository *PostgresRepository) ResolveIdentity(ctx context.Context, external platformidentity.ExternalPrincipal) (SessionGrant, error) {
	if repository == nil || external.OrganizationReference() == "" || external.MemberReference() == "" {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	payload, err := repository.database.QueryJSON(ctx, postgresResolveIdentitySQL, external.OrganizationReference(), external.MemberReference())
	if err != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	identity, role, active, err := membershipIdentityFromJSON(payload)
	grant := SessionGrant{PrincipalID: identity.PrincipalID, Scope: identity.Scope, Permissions: identity.Permissions, ExpiresAt: external.ExpiresAt()}
	if err != nil || !active || !validMembershipRole(role) || !validSessionGrant(grant) {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	return grant, nil
}

func membershipIdentityFromJSON(payload json.RawMessage) (RequestIdentity, string, bool, error) {
	var value struct {
		PrincipalID           string   `json:"principal_id"`
		OrganizationID        string   `json:"organization_id"`
		OrganizationReference string   `json:"organization_reference"`
		MemberReference       string   `json:"member_reference"`
		Role                  string   `json:"role"`
		Active                bool     `json:"active"`
		WorkspaceID           string   `json:"workspace_id"`
		EnvironmentID         string   `json:"environment_id"`
		Permissions           []string `json:"permissions"`
	}
	if json.Unmarshal(payload, &value) != nil || !validStytchReference(value.OrganizationReference, "organization-") || !validStytchReference(value.MemberReference, "member-") || !validMembershipRole(value.Role) {
		return RequestIdentity{}, "", false, ErrRepositoryAuthentication
	}
	identityPayload, err := json.Marshal(map[string]any{
		"principal_id": value.PrincipalID, "organization_id": value.OrganizationID, "workspace_id": value.WorkspaceID,
		"environment_id": value.EnvironmentID, "permissions": value.Permissions,
	})
	if err != nil {
		return RequestIdentity{}, "", false, ErrRepositoryAuthentication
	}
	identity, err := identityFromJSON(identityPayload, false)
	return identity, value.Role, value.Active, err
}

func validateBootstrapMembership(payload json.RawMessage, identity RequestIdentity) error {
	var value struct {
		Principal struct {
			ID                    string `json:"id"`
			OrganizationID        string `json:"organization_id"`
			OrganizationReference string `json:"organization_reference"`
			MemberReference       string `json:"member_reference"`
			Role                  string `json:"role"`
			Active                bool   `json:"active"`
		} `json:"principal"`
	}
	if json.Unmarshal(payload, &value) != nil || value.Principal.ID != identity.PrincipalID.String() || value.Principal.OrganizationID != identity.Scope.OrganizationID().String() || !validStytchReference(value.Principal.OrganizationReference, "organization-") || !validStytchReference(value.Principal.MemberReference, "member-") || !validMembershipRole(value.Principal.Role) || !value.Principal.Active {
		return ErrRepositoryOperation
	}
	return nil
}

func validMembershipRole(value string) bool {
	_, ok := platformidentity.BuiltInRoles()[platformidentity.Role(value)]
	return ok
}

func (repository *PostgresRepository) BeginIdentity(ctx context.Context, returnTo string) (string, error) {
	if repository == nil || !validReturnPath(returnTo) {
		return "", ErrRepositoryOperation
	}
	state, err := randomCredential()
	if err != nil {
		return "", ErrRepositoryUnavailable
	}
	if err := repository.database.Exec(ctx, postgresBeginIdentitySQL, state, returnTo); err != nil {
		return "", ErrRepositoryUnavailable
	}
	return state, nil
}

func (repository *PostgresRepository) ConsumeIdentity(ctx context.Context, state string) (string, error) {
	if repository == nil || len(state) < 32 || len(state) > 512 {
		return "", ErrRepositoryAuthentication
	}
	payload, err := repository.database.QueryJSON(ctx, postgresConsumeIdentitySQL, state)
	if err != nil {
		return "", ErrRepositoryAuthentication
	}
	var value struct {
		ReturnPath string `json:"return_path"`
	}
	if json.Unmarshal(payload, &value) != nil || !validReturnPath(value.ReturnPath) {
		return "", ErrRepositoryAuthentication
	}
	return value.ReturnPath, nil
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
	value := map[string]any{"principal_id": identity.PrincipalID.String(), "organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(), "permissions": identity.Permissions, "csrf_token": identity.CSRFToken, "fresh_authenticated": identity.FreshAuthenticated}
	if !identity.FreshAuthExpiresAt.IsZero() {
		value["fresh_auth_expires_at"] = identity.FreshAuthExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return value
}

func bootstrapJSON(identity RequestIdentity) map[string]any {
	return map[string]any{
		"principal":       map[string]any{"id": identity.PrincipalID.String(), "organization_id": identity.Scope.OrganizationID().String(), "organization_reference": "organization-live", "member_reference": "member-live", "role": "security_admin", "active": true},
		"organization_id": identity.Scope.OrganizationID().String(), "workspace_id": identity.Scope.WorkspaceID().String(), "environment_id": identity.Scope.EnvironmentID().String(),
		"permissions": identity.Permissions, "capabilities": capabilitiesForPermissions(identity.Permissions),
		"csrf_token": identity.CSRFToken, "correlation_id": fallbackCorrelationID,
	}
}
