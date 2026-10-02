package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type SecurityAgentResourceKind string
type SecurityAgentFamily string

const (
	SecurityAgentResourceDefinition     SecurityAgentResourceKind = "definition"
	SecurityAgentResourceRun            SecurityAgentResourceKind = "run"
	SecurityAgentResourceApproval       SecurityAgentResourceKind = "approval"
	SecurityAgentFamilyOrderedRelease61 SecurityAgentFamily       = "ordered_release61"
	SecurityAgentFamilyLegacyOrMissing  SecurityAgentFamily       = "legacy_or_missing"
)

// SecurityAgentOwnershipResolver classifies authenticated resources, but cannot
// perform lifecycle operations. An error never establishes legacy ownership.
type SecurityAgentOwnershipResolver struct{ database JSONDatabase }

func NewSecurityAgentOwnershipResolver(database JSONDatabase) (*SecurityAgentOwnershipResolver, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryOperation
	}
	return &SecurityAgentOwnershipResolver{database: database}, nil
}

// Resolve permits product API tokens only for classification. Callers must
// reject ordered bearer requests, not dispatch them to the legacy repository.
func (r *SecurityAgentOwnershipResolver) Resolve(ctx context.Context, id RequestIdentity, kind SecurityAgentResourceKind, resource string) (SecurityAgentFamily, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || (id.CredentialKind != CredentialBrowserSession && id.CredentialKind != CredentialBearerToken) || !validRequestIdentity(id, id.CredentialKind == CredentialBrowserSession) || !public62ID(resource) || (kind != SecurityAgentResourceDefinition && kind != SecurityAgentResourceRun && kind != SecurityAgentResourceApproval) {
		return "", ErrRepositoryOperation
	}
	q := map[string]any{"operation": "classify", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "resource_kind": kind, "resource_id": resource}
	raw, err := json.Marshal(q)
	if err != nil {
		return "", ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(raw))
	if err != nil {
		return "", public62ProviderError(err, "classify")
	}
	var v struct {
		ContractVersion int                       `json:"contract_version"`
		Kind            SecurityAgentResourceKind `json:"resource_kind"`
		ID              string                    `json:"resource_id"`
		Family          SecurityAgentFamily       `json:"family"`
	}
	if bounded.Err() != nil || len(response) > 1024 || public62Decode(response, &v) != nil || v.ContractVersion != 62 || v.Kind != kind || v.ID != resource || (v.Family != SecurityAgentFamilyOrderedRelease61 && v.Family != SecurityAgentFamilyLegacyOrMissing) {
		return "", ErrRepositoryUnavailable
	}
	return v.Family, nil
}
