package apiserver

import (
	"crypto/sha256"
	"encoding/json"
)

// Authentication establishes current identity and the original PAT ceiling.
// It does not compute product permissions from a role or credential snapshot.
// The browser session lookup precedes every proof. It is one function that
// takes the presented token and returns that one live session: the API role
// holds no privilege on the session or membership tables (completion.sql X6).
const postgresAuthorizationSessionSQL = `SELECT zasp_authorization80_identity.authenticate_session($1)`
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
