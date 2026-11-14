package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The remediation role of an integration (completion.sql, section V6): the
// separate IAM role, named by ARN only, that provider remediations use. The
// role discovery reads with is never used to make changes, so an integration
// without a remediation role cannot be remediated.
//
//	GET /api/v1/integrations/{id}/remediation-role   getIntegrationRemediationRole
//	PUT /api/v1/integrations/{id}/remediation-role   putIntegrationRemediationRole

const (
	currentIntegrationRemediationRoleSQL    = `SELECT zasp_authorization80.integration_remediation_role($1,$2,$3,$4)`
	currentIntegrationSetRemediationRoleSQL = `SELECT zasp_authorization80.integration_set_remediation_role($1,$2,$3,$4,$5,$6,$7,$8,$9)`
)

// IntegrationRemediationRole is the remediation setting of an integration.
// Supported is false for a provider that has no remediation actions.
type IntegrationRemediationRole struct {
	IntegrationID string     `json:"integration_id"`
	Supported     bool       `json:"supported"`
	Configured    bool       `json:"configured"`
	RoleARN       *string    `json:"role_arn"`
	Version       int64      `json:"version"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

// IntegrationRemediationRolePut is a change of the remediation role. An
// empty RoleARN removes the setting.
type IntegrationRemediationRolePut struct {
	IntegrationID, RoleARN, AuditID, CorrelationID string
	ExpectedVersion                                int64
}

// IntegrationRemediationRoleAuthority is implemented by the discovery
// repository of the current catalog.
type IntegrationRemediationRoleAuthority interface {
	GetIntegrationRemediationRole(context.Context, domain.Scope, string) (IntegrationRemediationRole, error)
	PutIntegrationRemediationRole(context.Context, RequestIdentity, IntegrationRemediationRolePut) (IntegrationRemediationRole, string, error)
}

func validIntegrationRemediationRole(value IntegrationRemediationRole, integrationID string) bool {
	if value.IntegrationID != integrationID || value.Version < 0 || value.Version > 1000000 || value.Configured != (value.RoleARN != nil) || value.Configured != (value.UpdatedAt != nil) || value.Configured != (value.Version > 0) {
		return false
	}
	if !value.Configured {
		return true
	}
	return value.Supported && awsRoleARNPattern.MatchString(*value.RoleARN) && !value.UpdatedAt.IsZero() && value.UpdatedAt.Location() == time.UTC
}

func (repository *DiscoveryRepository) GetIntegrationRemediationRole(ctx context.Context, scope domain.Scope, integrationID string) (IntegrationRemediationRole, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || scope == (domain.Scope{}) || !validProductID(integrationID) {
		return IntegrationRemediationRole{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, currentIntegrationRemediationRoleSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID)
	if err != nil {
		return IntegrationRemediationRole{}, discoveryProviderError(err)
	}
	var result IntegrationRemediationRole
	if !exactJSONFields(payload, "configured", "integration_id", "role_arn", "supported", "updated_at", "version") || decodeStrictDiscovery(payload, &result) != nil || !validIntegrationRemediationRole(result, integrationID) {
		return IntegrationRemediationRole{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *DiscoveryRepository) PutIntegrationRemediationRole(ctx context.Context, identity RequestIdentity, input IntegrationRemediationRolePut) (IntegrationRemediationRole, string, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) ||
		!validProductID(input.IntegrationID) || input.RoleARN != "" && !awsRoleARNPattern.MatchString(input.RoleARN) || input.ExpectedVersion < 0 || input.ExpectedVersion > 1000000 || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || input.AuditID == input.CorrelationID {
		return IntegrationRemediationRole{}, "", ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, currentIntegrationSetRemediationRoleSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.IntegrationID, input.RoleARN, input.ExpectedVersion, input.AuditID, input.CorrelationID)
	if err != nil {
		return IntegrationRemediationRole{}, "", discoveryProviderError(err)
	}
	var wire struct {
		IntegrationRemediationRole
		AuditID       string `json:"audit_id"`
		CorrelationID string `json:"correlation_id"`
	}
	if !exactJSONFields(payload, "audit_id", "configured", "correlation_id", "integration_id", "role_arn", "supported", "updated_at", "version") || decodeStrictDiscovery(payload, &wire) != nil || !validIntegrationRemediationRole(wire.IntegrationRemediationRole, input.IntegrationID) ||
		wire.AuditID != input.AuditID || wire.CorrelationID != input.CorrelationID || wire.Configured != (input.RoleARN != "") || wire.Configured && (*wire.RoleARN != input.RoleARN || wire.Version != input.ExpectedVersion+1) {
		return IntegrationRemediationRole{}, "", ErrRepositoryUnavailable
	}
	return wire.IntegrationRemediationRole, wire.AuditID, nil
}

func (handler *discoveryPublicHTTPHandler) getRemediationRole(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	repository, ok := handler.repository.(IntegrationRemediationRoleAuthority)
	if !ok || request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := repository.GetIntegrationRemediationRole(request.Context(), identity.Scope, integrationID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

func (handler *discoveryPublicHTTPHandler) putRemediationRole(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	repository, ok := handler.repository.(IntegrationRemediationRoleAuthority)
	// The optimistic version makes a repeated request safe: the second one
	// names a version that is no longer current and is refused.
	_, expectedVersion, valid := discoveryMutationHeaders(request, true)
	var input struct {
		RoleARN *string `json:"role_arn"`
	}
	if !ok || request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || decodeProductionJSON(request, &input) != nil || input.RoleARN == nil || *input.RoleARN != "" && !awsRoleARNPattern.MatchString(*input.RoleARN) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	ids, ok := handler.newProductIDs(1)
	correlationID := correlationIDFromContext(request.Context())
	if !ok || !validProductID(correlationID) || ids[0] == correlationID {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, auditID, err := repository.PutIntegrationRemediationRole(request.Context(), identity, IntegrationRemediationRolePut{IntegrationID: integrationID, RoleARN: *input.RoleARN, ExpectedVersion: expectedVersion, AuditID: ids[0], CorrelationID: correlationID})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeDiscoveryMutationHeaders(writer, result.Version, auditID, "")
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

// integrationRemediationRoleStatementAllowed admits the two remediation role
// statements for the checked request they belong to.
func integrationRemediationRoleStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	var operation string
	var expected []string
	o, w, e := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()
	switch q {
	case currentIntegrationRemediationRoleSQL:
		operation, expected = "getIntegrationRemediationRole", []string{o, w, e, g.PathParameters["id"]}
		if len(args) != 4 {
			return true, false
		}
	case currentIntegrationSetRemediationRoleSQL:
		operation, expected = "putIntegrationRemediationRole", []string{o, w, e, g.Identity.PrincipalID.String(), g.PathParameters["id"]}
		if len(args) != 9 {
			return true, false
		}
	default:
		return false, false
	}
	if g.OperationID != operation || g.Collection || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) {
		return true, false
	}
	for index, want := range expected {
		value, ok := args[index].(string)
		if !ok || value == "" || value != want {
			return true, false
		}
	}
	return true, authorizationNativeTargetAllowed(g, "integration", g.PathParameters["id"])
}
