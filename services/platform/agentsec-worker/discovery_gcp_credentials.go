package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
)

// Google Cloud is reference-authorized like AWS. The integration
// configuration names the organization, folder or project to read and how
// the customer's read-only service account is reached:
//
//   - workload identity federation: identity_reference is
//     ref:gcp/workload-identity/<project>/<service account name> and audience
//     the customer's workload identity pool provider. The worker's own AWS
//     role is exchanged for a token of that service account. Nothing is
//     stored anywhere.
//   - a service account key: identity_reference is
//     ref:gcp/service-account-key/<id> and the key file lives in Secrets
//     Manager under the discovery secret root at
//     <root>/gcp/service-account-key/<id>. The key never leaves the resolver.
//
// Either way the collector receives a token that lives at most an hour.

type discoveryGCPTokenAPI interface {
	FederatedToken(ctx context.Context, audience, serviceAccount string) (gcpdiscovery.AccessToken, error)
	KeyToken(ctx context.Context, keyFile []byte) (gcpdiscovery.AccessToken, error)
}

func (resolver *productionDiscoveryCredentialResolver) resolveGCP(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	// The members are in the order the stored configuration holds them.
	var config struct {
		Audience          string `json:"audience,omitempty"`
		IdentityReference string `json:"identity_reference"`
		Scope             string `json:"scope"`
	}
	// A refused document may still have filled some members: nothing of it
	// is used unless the whole document was accepted.
	canonical := decodeCanonicalDiscoveryCredentialJSON(bound.configuration(), &config, 4096)
	serviceAccount, federated := gcpdiscovery.FederationServiceAccount(config.IdentityReference)
	if !canonical || nilDiscoveryCredentialDependency(resolver.config.GCP) || !gcpdiscovery.ValidScope(config.Scope) || config.Scope != bound.Credential.ExpectedSubject.ID || config.IdentityReference != bound.Credential.Reference ||
		federated != (config.Audience != "") || federated && !gcpdiscovery.ValidAudience(config.Audience) || !federated && !gcpdiscovery.ValidKeyReference(config.IdentityReference) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	if err := bound.checkCurrent(ctx); err != nil {
		return discoveryCredentialEnvelope{}, err
	}
	var token gcpdiscovery.AccessToken
	var tokenErr error
	if federated {
		token, tokenErr = resolver.config.GCP.FederatedToken(ctx, config.Audience, serviceAccount)
	} else {
		keyFile, secretErr := resolver.resolveCurrentSecret(ctx, bound, config.IdentityReference)
		if secretErr != nil || len(keyFile) < 64 {
			clear(keyFile)
			return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, secretErr)
		}
		if err := bound.checkCurrent(ctx); err != nil {
			clear(keyFile)
			return discoveryCredentialEnvelope{}, err
		}
		token, tokenErr = resolver.config.GCP.KeyToken(ctx, keyFile)
		clear(keyFile)
	}
	defer token.Destroy()
	if tokenErr != nil || ctx.Err() != nil {
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, tokenErr)
	}
	expiresAt := providerDiscoveryCredentialExpiry(now, token.ExpiresAt)
	credential, ok := gcpdiscovery.EncodeCredential(token.Token)
	if !ok || !expiresAt.After(now) {
		clear(credential)
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) { value.BearerToken = credential }), nil
}

var _ discoveryGCPTokenAPI = (*gcpdiscovery.TokenExchanger)(nil)
