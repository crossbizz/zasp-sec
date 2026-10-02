package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// resolveTriggerKey is classification only. A legacy HTTP body cannot supply
// the trigger version required by ResolveMutation; only retained SQL intent may.
func (r *SecurityAgentOwnershipResolver) resolveTriggerKey(ctx context.Context, id RequestIdentity, definition, key string) (SecurityAgentFamily, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil || (id.CredentialKind != CredentialBrowserSession && id.CredentialKind != CredentialBearerToken) || !validRequestIdentity(id, id.CredentialKind == CredentialBrowserSession) || !public62ID(definition) || !securityAgentPublicIdempotency.MatchString(key) {
		return "", ErrRepositoryOperation
	}
	raw, err := json.Marshal(map[string]any{"operation": "classify_trigger_key", "organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "definition_id": definition, "idempotency_key": key})
	if err != nil {
		return "", ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(raw))
	if err != nil {
		return "", public62ProviderError(err, "classify_trigger_key")
	}
	var v struct {
		ContractVersion int                 `json:"contract_version"`
		DefinitionID    string              `json:"definition_id"`
		IdempotencyKey  string              `json:"idempotency_key"`
		Family          SecurityAgentFamily `json:"family"`
	}
	if bounded.Err() != nil || len(response) > 1024 || public62Decode(response, &v) != nil || v.ContractVersion != 62 || v.DefinitionID != definition || v.IdempotencyKey != key || (v.Family != SecurityAgentFamilyOrderedRelease61 && v.Family != SecurityAgentFamilyLegacyOrMissing) {
		return "", ErrRepositoryUnavailable
	}
	return v.Family, nil
}

func (a *SecurityAgentOrderedResourceAuthority) ownTriggerKey(ctx context.Context, id RequestIdentity, definition, key string) error {
	if a == nil || a.resolver == nil || a.repository == nil {
		return ErrRepositoryOperation
	}
	family, err := a.resolver.resolveTriggerKey(ctx, id, definition, key)
	if err != nil {
		return err
	}
	if family == SecurityAgentFamilyLegacyOrMissing {
		return ErrSecurityAgentNotOwned
	}
	if id.CredentialKind != CredentialBrowserSession {
		return ErrRepositoryOperation
	}
	return nil
}
