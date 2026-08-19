package apiserver

import (
	"context"
	"net"
	"net/url"
	"strings"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type ExternalIdentityAuthenticator interface {
	Authenticate(context.Context, string) (platformidentity.ExternalPrincipal, error)
	Ready(context.Context) error
}

type IdentityGrantResolver interface {
	ResolveIdentity(context.Context, platformidentity.ExternalPrincipal) (SessionGrant, error)
}

type IdentityStateRepository interface {
	BeginIdentity(context.Context, string) (string, error)
	ConsumeIdentity(context.Context, string) (string, error)
}

type IdentityStarter interface {
	Start(context.Context, string) (string, error)
}

type RepositoryIdentityProvider struct {
	authenticator         ExternalIdentityAuthenticator
	resolver              IdentityGrantResolver
	states                IdentityStateRepository
	authorizeURL          string
	publicToken           string
	organizationReference string
	redirectURI           string
}

func NewRepositoryIdentityProviderWithStart(authenticator ExternalIdentityAuthenticator, resolver IdentityGrantResolver, states IdentityStateRepository, authorizeURL, publicToken, organizationReference, redirectURI string) (*RepositoryIdentityProvider, error) {
	provider, err := NewRepositoryIdentityProvider(authenticator, resolver)
	if err != nil || nilInterface(states) || !boundedSecret(publicToken) || !validStytchReference(organizationReference, "organization-") {
		return nil, ErrRepositoryConfiguration
	}
	authorize, authorizeErr := url.Parse(authorizeURL)
	redirect, redirectErr := url.Parse(redirectURI)
	if authorizeErr != nil || redirectErr != nil || !validIdentityURL(authorize, "") || !validStytchAuthorizePath(authorize.Path) || !validIdentityURL(redirect, "/auth/callback") {
		return nil, ErrRepositoryConfiguration
	}
	provider.states = states
	provider.authorizeURL = authorizeURL
	provider.publicToken = publicToken
	provider.organizationReference = organizationReference
	provider.redirectURI = redirectURI
	return provider, nil
}

func (provider *RepositoryIdentityProvider) Start(ctx context.Context, returnTo string) (string, error) {
	if provider == nil || nilInterface(provider.states) || ctx == nil || ctx.Err() != nil || !validReturnPath(returnTo) {
		return "", ErrRepositoryOperation
	}
	state, err := provider.states.BeginIdentity(ctx, returnTo)
	if err != nil || len(state) < 32 || len(state) > 512 {
		return "", ErrRepositoryUnavailable
	}
	target, _ := url.Parse(provider.authorizeURL)
	query := target.Query()
	callback, _ := url.Parse(provider.redirectURI)
	callbackQuery := callback.Query()
	callbackQuery.Set("state", state)
	callback.RawQuery = callbackQuery.Encode()
	query.Set("public_token", provider.publicToken)
	query.Set("organization_id", provider.organizationReference)
	query.Set("login_redirect_url", callback.String())
	query.Set("signup_redirect_url", callback.String())
	target.RawQuery = query.Encode()
	return target.String(), nil
}

func NewRepositoryIdentityProvider(authenticator ExternalIdentityAuthenticator, resolver IdentityGrantResolver) (*RepositoryIdentityProvider, error) {
	if nilInterface(authenticator) || nilInterface(resolver) {
		return nil, ErrRepositoryConfiguration
	}
	return &RepositoryIdentityProvider{authenticator: authenticator, resolver: resolver}, nil
}

func (provider *RepositoryIdentityProvider) Complete(ctx context.Context, code, state string) (SessionGrant, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || code == "" || len(code) > 4096 || len(state) < 32 || len(state) > 512 {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	returnTo := "/"
	if provider.states != nil {
		var consumeErr error
		returnTo, consumeErr = provider.states.ConsumeIdentity(ctx, state)
		if consumeErr != nil || !validReturnPath(returnTo) {
			return SessionGrant{}, ErrRepositoryAuthentication
		}
	}
	external, err := provider.authenticator.Authenticate(ctx, code)
	if err != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	grant, err := provider.resolver.ResolveIdentity(ctx, external)
	if err != nil || !validSessionGrant(grant) || grant.ExpiresAt.After(external.ExpiresAt()) {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	grant.ReturnTo = returnTo
	return grant, nil
}

func validReturnPath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.ContainsAny(value, "\\\r\n") && len(value) <= 2048
}

func validIdentityURL(value *url.URL, exactPath string) bool {
	if value == nil || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || value.Path == "" || exactPath != "" && value.Path != exactPath {
		return false
	}
	loopback := net.ParseIP(value.Hostname()) != nil && net.ParseIP(value.Hostname()).IsLoopback()
	return value.Scheme == "https" || value.Scheme == "http" && loopback
}

func validStytchReference(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) <= 128 && strings.TrimSpace(value) == value
}

func validStytchAuthorizePath(value string) bool {
	for _, provider := range []string{"google", "microsoft", "github", "slack", "hubspot"} {
		if value == "/v1/b2b/public/oauth/"+provider+"/start" {
			return true
		}
	}
	return false
}

func (provider *RepositoryIdentityProvider) Ready(ctx context.Context) error {
	if provider == nil || provider.authenticator.Ready(ctx) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
