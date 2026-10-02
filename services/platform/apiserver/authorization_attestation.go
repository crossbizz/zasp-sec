package apiserver

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func attestAuthorization(grant RequestAuthorization, key *authorization.AttestationKey, now time.Time) (RequestAuthorization, error) {
	if key == nil {
		return RequestAuthorization{}, authorization.ErrUnavailable
	}
	body, err := authorizationDecisionJSON(grant)
	if err != nil {
		return RequestAuthorization{}, err
	}
	grant.decisionDigest = sha256.Sum256(body)
	var claims map[string]json.RawMessage
	if json.Unmarshal(body, &claims) != nil {
		return RequestAuthorization{}, authorization.ErrInvalid
	}
	claims["attestation_domain"], _ = json.Marshal("zasp-authorization-attestation-v1")
	claims["key_version"], _ = json.Marshal(key.Version())
	claims["issued_at"], _ = json.Marshal(now.UnixMilli())
	claims["expires_at"], _ = json.Marshal(now.Add(time.Minute).UnixMilli())
	payload, err := json.Marshal(claims)
	if err != nil {
		return RequestAuthorization{}, err
	}
	grant.attestation, err = key.Sign(payload)
	return grant, err
}
