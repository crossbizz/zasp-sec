package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// AuthorizationTransactionDriver is additive to the existing JSONDatabase and
// PostgresDriver contracts. Production activation requires this capability.
type AuthorizationTransactionDriver interface {
	Begin(context.Context) (pgx.Tx, error)
}

func (database *PostgresJSONDatabase) RequireCurrentAuthorization() error {
	if database == nil {
		return ErrRepositoryConfiguration
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	if _, ok := database.driver.(AuthorizationTransactionDriver); !ok || database.closed {
		return ErrRepositoryConfiguration
	}
	// Prepare immutable compiled pins before enabling bounded runtime probes.
	// Database readiness and authorization decisions remain live per request.
	_, _ = authorizationRuntimeChecksums()
	database.currentAuthorization = true
	return nil
}

func authorizationProofJSON(grant RequestAuthorization) ([]byte, error) {
	body, err := authorizationDecisionJSON(grant)
	if err != nil {
		return nil, err
	}
	if len(grant.attestation) == 0 || sha256.Sum256(body) != grant.decisionDigest {
		return nil, ErrAuthorizationDenied
	}
	return append([]byte(nil), grant.attestation...), nil
}

func authorizationDecisionJSON(grant RequestAuthorization) ([]byte, error) {
	policy, err := authorization.LookupOperation(grant.OperationID)
	if err != nil || policy.Permission == "" || !validRequestIdentity(grant.Identity, false) || grant.Credential.Kind != grant.Identity.CredentialKind || grant.Credential.ID == "" || grant.Credential.Digest == ([32]byte{}) {
		return nil, ErrAuthorizationDenied
	}
	targets := func(values []AuthorizationTarget) []map[string]any {
		result := make([]map[string]any, 0, len(values))
		for _, value := range values {
			result = append(result, map[string]any{"organization_id": value.Scope.OrganizationID().String(), "workspace_id": value.Scope.WorkspaceID().String(), "environment_id": value.Scope.EnvironmentID().String(), "kind": value.Kind, "id": value.ID, "version": value.Version, "source_id": value.SourceID})
		}
		return result
	}
	csrfDigest := sha256.Sum256([]byte(grant.Identity.CSRFToken))
	return json.Marshal(map[string]any{"operation_id": grant.OperationID, "workspace_selector": grant.WorkspaceSelector, "path_parameters": grant.PathParameters, "permission": policy.Permission, "fresh_auth": policy.FreshAuth, "principal_id": grant.Identity.PrincipalID.String(), "organization_id": grant.Identity.Scope.OrganizationID().String(), "workspace_id": grant.Identity.Scope.WorkspaceID().String(), "environment_id": grant.Identity.Scope.EnvironmentID().String(), "credential_kind": grant.Credential.Kind, "credential_id": grant.Credential.ID, "credential_digest": hex.EncodeToString(grant.Credential.Digest[:]), "csrf_digest": hex.EncodeToString(csrfDigest[:]), "pat_ceiling": grant.Credential.PATCeiling, "revision": grant.Revision, "collection": grant.Collection, "environment_view": grant.EnvironmentView, "targets": targets(grant.Targets), "allowed": targets(grant.Allowed)})
}

func (database *PostgresJSONDatabase) authorizedQueryJSON(ctx context.Context, grant RequestAuthorization, statement string, arguments ...any) (json.RawMessage, error) {
	if !authorizationStatementAllowed(grant, statement, arguments) {
		return nil, ErrAuthorizationDenied
	}
	driver, ok := database.driver.(AuthorizationTransactionDriver)
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		return nil, err
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return nil, classifyPostgresError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
		return nil, classifyPostgresError(err)
	}
	var payload []byte
	if err = tx.QueryRow(ctx, statement, arguments...).Scan(&payload); err != nil {
		return nil, classifyPostgresError(err)
	}
	if len(payload) == 0 {
		return nil, ErrRepositoryNotFound
	}
	if !json.Valid(payload) {
		return nil, ErrRepositoryUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, classifyPostgresError(err)
	}
	return append(json.RawMessage(nil), payload...), nil
}

// Only exact identity authentication statements bypass product authorization.
// Startup readiness executes before enforcement activation. Other credential
// lifecycle calls receive separate explicit classification at their call sites.
func authorizationIdentityStatement(statement string) bool {
	return statement == postgresAuthorizationSessionSQL
}
