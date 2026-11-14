package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
)

// Google Cloud is reference-authorized: the integration names the
// organization, folder or project to read and how the customer's read-only
// service account is reached (workload identity federation from the API's
// own AWS role, or a service account key stored outside the product
// database). The probe obtains a token the same way a collection does and
// reads the named scope with it, so an authorization that succeeds here
// proves the service account exists, may be used by this deployment, and can
// see what the integration says it will read. The token is not kept.

type gcpReferenceTokens interface {
	FederatedToken(ctx context.Context, audience, serviceAccount string) (gcpdiscovery.AccessToken, error)
	KeyToken(ctx context.Context, keyFile []byte) (gcpdiscovery.AccessToken, error)
}

type gcpReferenceScopeReader interface {
	ProbeScope(ctx context.Context, credential []byte, scope string) error
}

type gcpReferenceProbe struct {
	resolver *referenceSecretResolver
	tokens   gcpReferenceTokens
	scopes   gcpReferenceScopeReader
}

func (probe *gcpReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) (apiserver.ReferenceAuthorizationSubject, error) {
	var config struct {
		Audience          string `json:"audience,omitempty"`
		IdentityReference string `json:"identity_reference"`
		Scope             string `json:"scope"`
	}
	if probe == nil || probe.tokens == nil || probe.scopes == nil || !decodeStrictReferenceJSON(target.Configuration, &config, 4096) || config.IdentityReference != target.ConnectionReference || !gcpdiscovery.ValidScope(config.Scope) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	serviceAccount, federated := gcpdiscovery.FederationServiceAccount(config.IdentityReference)
	if federated != (config.Audience != "") || federated && !gcpdiscovery.ValidAudience(config.Audience) || !federated && !gcpdiscovery.ValidKeyReference(config.IdentityReference) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	var token gcpdiscovery.AccessToken
	var err error
	if federated {
		token, err = probe.tokens.FederatedToken(ctx, config.Audience, serviceAccount)
	} else {
		if probe.resolver == nil {
			return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
		}
		keyFile, secretErr := probe.resolver.Resolve(ctx, config.IdentityReference)
		if secretErr != nil {
			clear(keyFile)
			return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
		}
		token, err = probe.tokens.KeyToken(ctx, keyFile)
		clear(keyFile)
	}
	defer token.Destroy()
	if err != nil {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	credential, ok := gcpdiscovery.EncodeCredential(token.Token)
	defer clear(credential)
	if !ok || probe.scopes.ProbeScope(ctx, credential, config.Scope) != nil {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	return apiserver.ReferenceAuthorizationSubject{Kind: "gcp_scope", ID: config.Scope}, nil
}

var _ apiserver.ReferenceAuthorizationProbe = (*gcpReferenceProbe)(nil)
var _ gcpReferenceTokens = (*gcpdiscovery.TokenExchanger)(nil)
var _ gcpReferenceScopeReader = (*gcpdiscovery.GCPCollectionAPI)(nil)
