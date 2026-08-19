package apiserver

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"
)

type ExternalIdentity struct {
	OrganizationReference string
	MemberReference       string
	ExpiresAt             time.Time
}

type IdentityExchanger interface {
	Exchange(context.Context, string, string) (ExternalIdentity, error)
	Ready(context.Context) error
}

type IdentityGrantResolver interface {
	ResolveIdentity(context.Context, ExternalIdentity) (SessionGrant, error)
}

type IdentityStateRepository interface {
	BeginIdentity(context.Context, string) (string, error)
	ConsumeIdentity(context.Context, string) (string, error)
}

type IdentityStarter interface {
	Start(context.Context, string) (string, error)
}

type RepositoryIdentityProvider struct {
	exchanger    IdentityExchanger
	resolver     IdentityGrantResolver
	states       IdentityStateRepository
	authorizeURL string
	clientID     string
	redirectURI  string
}

func NewRepositoryIdentityProviderWithStart(exchanger IdentityExchanger, resolver IdentityGrantResolver, states IdentityStateRepository, authorizeURL, clientID, redirectURI string) (*RepositoryIdentityProvider, error) {
	provider, err := NewRepositoryIdentityProvider(exchanger, resolver)
	if err != nil || nilInterface(states) || !boundedSecret(clientID) {
		return nil, ErrRepositoryConfiguration
	}
	authorize, authorizeErr := url.Parse(authorizeURL)
	redirect, redirectErr := url.Parse(redirectURI)
	if authorizeErr != nil || redirectErr != nil || !validIdentityURL(authorize, "") || !validIdentityURL(redirect, "/auth/callback") {
		return nil, ErrRepositoryConfiguration
	}
	provider.states = states
	provider.authorizeURL = authorizeURL
	provider.clientID = clientID
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
	query.Set("response_type", "code")
	query.Set("client_id", provider.clientID)
	query.Set("redirect_uri", provider.redirectURI)
	query.Set("state", state)
	target.RawQuery = query.Encode()
	return target.String(), nil
}

func NewRepositoryIdentityProvider(exchanger IdentityExchanger, resolver IdentityGrantResolver) (*RepositoryIdentityProvider, error) {
	if nilInterface(exchanger) || nilInterface(resolver) {
		return nil, ErrRepositoryConfiguration
	}
	return &RepositoryIdentityProvider{exchanger: exchanger, resolver: resolver}, nil
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
	external, err := provider.exchanger.Exchange(ctx, code, state)
	if err != nil || !validExternalIdentity(external) {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	grant, err := provider.resolver.ResolveIdentity(ctx, external)
	if err != nil || !validSessionGrant(grant) || grant.ExpiresAt.After(external.ExpiresAt) {
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

func (provider *RepositoryIdentityProvider) Ready(ctx context.Context) error {
	if provider == nil || provider.exchanger.Ready(ctx) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validExternalIdentity(value ExternalIdentity) bool {
	return strings.HasPrefix(value.OrganizationReference, "organization-") && len(value.OrganizationReference) <= 128 && strings.HasPrefix(value.MemberReference, "member-") && len(value.MemberReference) <= 128 && value.ExpiresAt.Location() == time.UTC && value.ExpiresAt.After(time.Now().UTC()) && !value.ExpiresAt.After(time.Now().UTC().Add(24*time.Hour))
}
