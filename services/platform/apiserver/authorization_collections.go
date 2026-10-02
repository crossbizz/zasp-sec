package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

func authorizationReadStatement(ctx context.Context, legacy, current string) string {
	if _, ok := requestAuthorizationFromContext(ctx); ok {
		return current
	}
	return legacy
}

// Derive a per-authorization-view cursor key from the existing server secret.
// The handler is copied per request, so concurrent users never share mutable
// signing state. Both encode and decode use the same current-revision binding.
func authorizationCursorKey(ctx context.Context, key []byte) []byte {
	grant, ok := requestAuthorizationFromContext(ctx)
	if !ok {
		return key
	}
	binding, _ := json.Marshal(struct {
		Principal, Scope, Operation, Credential string
		Revision                                any
		Ceiling                                 []string
	}{grant.Identity.PrincipalID.String(), expectedScopeValue(grant.Identity.Scope), grant.OperationID, grant.Credential.ID, grant.Revision, grant.Credential.PATCeiling})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("zasp-authorization-cursor-v1\x00"))
	_, _ = mac.Write(binding)
	return mac.Sum(nil)
}
