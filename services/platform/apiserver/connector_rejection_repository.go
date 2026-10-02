package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
)

// IntegrationRejection deliberately cannot carry a submitted body, configuration,
// URL, name, idempotency key or credential value.
type IntegrationRejection struct {
	CredentialDigest []byte
	Operation        string
	TargetID         string
	AuditID          string
	CorrelationID    string
}

type integrationRejectionAuditor interface {
	AuditIntegrationRejection(context.Context, RequestIdentity, IntegrationRejection) error
}

func validIntegrationRejection(identity RequestIdentity, command IntegrationRejection) bool {
	return validIntegrationRejectionShape(identity, command) && stringIn("manage_workflows", identity.Permissions...)
}

func validIntegrationRejectionShape(identity RequestIdentity, command IntegrationRejection) bool {
	return validRequestIdentity(identity, false) &&
		(identity.CredentialKind == CredentialBrowserSession || identity.CredentialKind == CredentialBearerToken) &&
		len(command.CredentialDigest) == sha256.Size && !bytes.Equal(command.CredentialDigest, make([]byte, sha256.Size)) &&
		stringIn(command.Operation, "createIntegration", "updateIntegration") &&
		validProductID(command.TargetID) && validProductID(command.AuditID) && validProductID(command.CorrelationID) &&
		(command.Operation != "createIntegration" || command.TargetID == identity.Scope.EnvironmentID().String())
}

func validCurrentIntegrationRejection(grant RequestAuthorization, identity RequestIdentity, command IntegrationRejection) bool {
	if !validIntegrationRejectionShape(identity, command) || grant.OperationID != command.Operation || grant.Identity.PrincipalID != identity.PrincipalID || grant.Identity.Scope != identity.Scope || grant.Credential.Kind != identity.CredentialKind || !bytes.Equal(command.CredentialDigest, grant.Credential.Digest[:]) {
		return false
	}
	if _, err := authorizationProofJSON(grant); err != nil {
		return false
	}
	kind := "environment"
	if command.Operation == "updateIntegration" {
		kind = "integration"
		if grant.PathParameters["id"] != command.TargetID {
			return false
		}
	}
	return authorizationNativeTargetAllowed(grant, kind, command.TargetID)
}

func (repository *PostgresRepository) AuditIntegrationRejection(ctx context.Context, identity RequestIdentity, command IntegrationRejection) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil {
		return ErrRepositoryOperation
	}
	if grant, checked := requestAuthorizationFromContext(ctx); checked {
		if !validCurrentIntegrationRejection(grant, identity, command) {
			return ErrAuthorizationDenied
		}
	} else if repository.currentAuthorization {
		return ErrAuthorizationDenied
	} else if !validIntegrationRejection(identity, command) {
		return ErrRepositoryOperation
	}
	auditor, ok := repository.database.(integrationRejectionAuditor)
	if !ok {
		return ErrRepositoryUnavailable
	}
	return auditor.AuditIntegrationRejection(ctx, identity, command)
}
