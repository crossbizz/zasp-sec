package apiserver

import (
	"crypto/sha256"
	"encoding/json"
)

// Authentication establishes current identity and the original PAT ceiling.
// It does not compute product permissions from a role or credential snapshot.
const postgresAuthorizationSessionSQL = `SELECT jsonb_build_object('credential_id',s.session_id,'principal_id',s.principal_id,'organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id,'permissions','[]'::jsonb,'csrf_token',s.csrf_token,'fresh_authenticated',s.authenticated_at>clock_timestamp()-interval '5 minutes','fresh_auth_expires_at',s.authenticated_at+interval '5 minutes') FROM zasp_product_sessions s JOIN zasp_identity_memberships m ON(m.principal_id,m.organization_id)=(s.principal_id,s.organization_id) AND m.active WHERE s.token_digest=digest($1,'sha256') AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(s.principal_id,s.organization_id) x WHERE(x.workspace_id,x.environment_id)=(s.workspace_id,s.environment_id))`
const postgresAuthorizationPATSQL = `WITH used AS(UPDATE zasp_product_api_tokens SET last_used_at=clock_timestamp() WHERE token_digest=digest($1,'sha256') AND revoked_at IS NULL AND expires_at>clock_timestamp() RETURNING *) SELECT jsonb_build_object('credential_id',t.id,'principal_id',t.principal_id,'organization_id',t.organization_id,'workspace_id',t.workspace_id,'environment_id',t.environment_id,'permissions','[]'::jsonb,'pat_ceiling',t.permissions) FROM used t JOIN zasp_identity_memberships m ON(m.principal_id,m.organization_id)=(t.principal_id,t.organization_id) AND m.active WHERE EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(t.principal_id,t.organization_id) x WHERE(x.workspace_id,x.environment_id)=(t.workspace_id,t.environment_id))`

func bindAuthorizationCredential(identity *RequestIdentity, credential Credential, payload json.RawMessage) error {
	var value struct {
		ID      string   `json:"credential_id"`
		Ceiling []string `json:"pat_ceiling"`
	}
	if json.Unmarshal(payload, &value) != nil || value.ID == "" || !validPermissions(value.Ceiling) {
		return ErrRepositoryAuthentication
	}
	identity.credentialBinding = CredentialBinding{Kind: credential.Kind, ID: value.ID, Digest: sha256.Sum256([]byte(credential.Value)), PATCeiling: append([]string(nil), value.Ceiling...)}
	return nil
}
