package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var nangoServiceReferencePattern = regexp.MustCompile(`^ref:nango/service-key-([a-z0-9][a-z0-9_-]{3,127})$`)
var nangoKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var slackWorkspaceIDPattern = regexp.MustCompile(`^T[A-Z0-9]{8,20}$`)

type nangoConnectionAPI interface {
	StartOAuth(context.Context, nango.OAuthStartRequest) (nango.OAuthAuthorization, error)
	CompleteOAuth(context.Context, nango.OAuthCompleteRequest) (nango.Connection, error)
	RecoverOAuth(context.Context, nango.OAuthCompleteRequest) (nango.Connection, error)
	RevokeConnection(context.Context, nango.ConnectionRevocationRequest) error
}

type nangoProxyAPI interface {
	Proxy(context.Context, string, string, string, string, []byte) (nango.ProxyResponse, error)
}

type nangoOAuthProviderConfig struct {
	Client                                       nangoConnectionAPI
	Proxy                                        nangoProxyAPI
	BaseURL, ServiceSecretReference, Environment string
	ConnectorKey, Provider, AuthorizationHost    string
	AuthorizationPath, CallbackURL               string
}

type nangoOAuthProvider struct{ config nangoOAuthProviderConfig }

type cachedNangoCapabilityCheck struct {
	mu          sync.Mutex
	check       apiserver.ConnectorCapabilityCheck
	ttl         time.Duration
	lastSuccess time.Time
	now         func() time.Time
}

func newNangoOAuthProvider(config nangoOAuthProviderConfig) (*nangoOAuthProvider, error) {
	base, baseErr := url.Parse(config.BaseURL)
	callback, callbackErr := url.Parse(config.CallbackURL)
	if config.Client == nil || config.Proxy == nil || baseErr != nil || callbackErr != nil || base.Scheme != "http" && base.Scheme != "https" || base.User != nil || base.Port() == "" || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || !strings.HasSuffix(strings.ToLower(base.Hostname()), ".svc.cluster.local") || net.ParseIP(base.Hostname()) != nil ||
		!nangoServiceReferencePattern.MatchString(config.ServiceSecretReference) || !nangoKeyPattern.MatchString(config.Environment) || !nangoKeyPattern.MatchString(config.ConnectorKey) || config.Provider != config.ConnectorKey ||
		strings.ToLower(config.AuthorizationHost) != config.AuthorizationHost || net.ParseIP(config.AuthorizationHost) != nil || strings.ContainsAny(config.AuthorizationHost, "/:@?#\\\x00\r\n\t ") || config.AuthorizationPath == "" || config.AuthorizationPath[0] != '/' || strings.ContainsAny(config.AuthorizationPath, "?#\\\r\n") ||
		callback.Scheme != "https" || callback.Host == "" || callback.Port() != "" || callback.User != nil || callback.Path != "/api/v1/integrations/oauth/callback" || callback.RawQuery != "" || callback.Fragment != "" {
		return nil, errRuntimeUnavailable
	}
	return &nangoOAuthProvider{config: config}, nil
}

func (*nangoOAuthProvider) AuthorizationURL(string, string) (string, error) {
	return "", errRuntimeUnavailable
}

func (*nangoOAuthProvider) Complete(context.Context, string, string, []byte) (apiserver.ConnectorOAuthGrant, error) {
	return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
}

func (*nangoOAuthProvider) Recover(context.Context, string) (apiserver.ConnectorOAuthGrant, error) {
	return apiserver.ConnectorOAuthGrant{}, apiserver.ErrConnectorOutcomeNotFound
}

func (*nangoOAuthProvider) Discard(context.Context, string, bool) error { return nil }

func (*nangoOAuthProvider) Revoke(context.Context, string) error { return errRuntimeUnavailable }

func (provider *nangoOAuthProvider) StartAuthorization(ctx context.Context, input apiserver.ConnectorAuthorizationStart) (apiserver.ConnectorAuthorizationTarget, error) {
	if !provider.validStart(input) {
		return apiserver.ConnectorAuthorizationTarget{}, errRuntimeUnavailable
	}
	result, err := provider.config.Client.StartOAuth(ctx, nango.OAuthStartRequest{
		NangoBaseURL: provider.config.BaseURL, ServiceSecretReference: provider.config.ServiceSecretReference, Environment: provider.config.Environment,
		ConnectorKey: provider.config.ConnectorKey, Provider: provider.config.Provider, AuthorizationHost: provider.config.AuthorizationHost,
		AuthorizationPath: provider.config.AuthorizationPath, CallbackURL: provider.config.CallbackURL, Binding: nangoConnectionBinding(input.Scope, input.IntegrationID, input.AttemptID),
	})
	if err != nil {
		return apiserver.ConnectorAuthorizationTarget{}, errRuntimeUnavailable
	}
	return apiserver.ConnectorAuthorizationTarget{URL: result.URL, State: result.State, ExpiresAt: result.ExpiresAt}, nil
}

func (provider *nangoOAuthProvider) CompleteAuthorization(ctx context.Context, input apiserver.ConnectorAuthorizationCompletion) (apiserver.ConnectorOAuthGrant, error) {
	if !provider.validCompletion(input) {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	result, err := provider.config.Client.CompleteOAuth(ctx, nango.OAuthCompleteRequest{
		NangoBaseURL: provider.config.BaseURL, ServiceSecretReference: provider.config.ServiceSecretReference, Environment: provider.config.Environment,
		ConnectorKey: provider.config.ConnectorKey, Provider: provider.config.Provider, State: input.State, Code: input.Code, Binding: nangoConnectionBinding(input.Scope, input.IntegrationID, input.AttemptID),
	})
	return provider.grant(ctx, result, err)
}

func (provider *nangoOAuthProvider) RecoverAuthorization(ctx context.Context, input apiserver.ConnectorAuthorizationRecovery) (apiserver.ConnectorOAuthGrant, error) {
	if !provider.validRecovery(input) {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	result, err := provider.config.Client.RecoverOAuth(ctx, nango.OAuthCompleteRequest{
		NangoBaseURL: provider.config.BaseURL, ServiceSecretReference: provider.config.ServiceSecretReference, Environment: provider.config.Environment,
		ConnectorKey: provider.config.ConnectorKey, Provider: provider.config.Provider, Binding: nangoConnectionBinding(input.Scope, input.IntegrationID, input.AttemptID),
	})
	return provider.grant(ctx, result, err)
}

func (provider *nangoOAuthProvider) DiscardAuthorization(ctx context.Context, input apiserver.ConnectorAuthorizationDiscard) error {
	if provider == nil || !input.Revoke {
		return nil
	}
	recovery := apiserver.ConnectorAuthorizationRecovery{
		Scope: input.Scope, PrincipalID: input.PrincipalID, IntegrationID: input.IntegrationID, AttemptID: input.AttemptID,
		EffectID: input.EffectID, ConnectorKey: input.ConnectorKey, AuthorityProvider: input.AuthorityProvider,
	}
	if !provider.validRecovery(recovery) {
		return errRuntimeUnavailable
	}
	connection, err := provider.config.Client.RecoverOAuth(ctx, nango.OAuthCompleteRequest{
		NangoBaseURL: provider.config.BaseURL, ServiceSecretReference: provider.config.ServiceSecretReference, Environment: provider.config.Environment,
		ConnectorKey: provider.config.ConnectorKey, Provider: provider.config.Provider, Binding: nangoConnectionBinding(input.Scope, input.IntegrationID, input.AttemptID),
	})
	if errors.Is(err, nango.ErrConnectionNotFound) {
		return nil
	}
	if err != nil || connection.ConnectorKey != provider.config.ConnectorKey {
		return errRuntimeUnavailable
	}
	return provider.RevokeAuthorization(ctx, apiserver.ConnectorAuthorizationRevocation{
		Scope: input.Scope, IntegrationID: input.IntegrationID, EffectID: input.EffectID, ConnectorKey: input.ConnectorKey,
		AuthorityProvider: input.AuthorityProvider, ConnectionReference: connection.Reference,
	})
}

func (provider *nangoOAuthProvider) RevokeAuthorization(ctx context.Context, input apiserver.ConnectorAuthorizationRevocation) error {
	if provider == nil || ctx == nil || ctx.Err() != nil || input.Scope.Validate() != nil || !validNangoProductID(input.IntegrationID) || !validNangoProductID(input.EffectID) || input.ConnectorKey != provider.config.ConnectorKey || input.AuthorityProvider != "nango:"+provider.config.ConnectorKey {
		return errRuntimeUnavailable
	}
	err := provider.config.Client.RevokeConnection(ctx, nango.ConnectionRevocationRequest{
		NangoBaseURL: provider.config.BaseURL, ServiceSecretReference: provider.config.ServiceSecretReference, Environment: provider.config.Environment,
		ConnectorKey: provider.config.ConnectorKey, Provider: provider.config.Provider, ConnectionReference: input.ConnectionReference,
		Binding: nango.RevocationBinding{OrganizationID: input.Scope.OrganizationID().String(), WorkspaceID: input.Scope.WorkspaceID().String(), EnvironmentID: input.Scope.EnvironmentID().String(), IntegrationID: input.IntegrationID},
	})
	if err != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (provider *nangoOAuthProvider) validStart(input apiserver.ConnectorAuthorizationStart) bool {
	return provider != nil && input.Scope.Validate() == nil && validNangoProductID(input.PrincipalID) && validNangoProductID(input.IntegrationID) && validNangoProductID(input.AttemptID) && input.ConnectorKey == provider.config.ConnectorKey && input.AuthorityProvider == "nango:"+provider.config.ConnectorKey && !input.ExpiresAt.IsZero()
}

func (provider *nangoOAuthProvider) validCompletion(input apiserver.ConnectorAuthorizationCompletion) bool {
	return provider != nil && input.Scope.Validate() == nil && validNangoProductID(input.PrincipalID) && validNangoProductID(input.IntegrationID) && validNangoProductID(input.AttemptID) && input.ConnectorKey == provider.config.ConnectorKey && input.AuthorityProvider == "nango:"+provider.config.ConnectorKey && len(input.State) >= 8 && len(input.State) <= 512 && len(input.Code) >= 8 && len(input.Code) <= 512 && len(input.Verifier) >= 43 && len(input.Verifier) <= 128
}

func (provider *nangoOAuthProvider) validRecovery(input apiserver.ConnectorAuthorizationRecovery) bool {
	return provider != nil && input.Scope.Validate() == nil && validNangoProductID(input.PrincipalID) && validNangoProductID(input.IntegrationID) && validNangoProductID(input.AttemptID) && validNangoProductID(input.EffectID) && input.ConnectorKey == provider.config.ConnectorKey && input.AuthorityProvider == "nango:"+provider.config.ConnectorKey
}

func (provider *nangoOAuthProvider) grant(ctx context.Context, connection nango.Connection, err error) (apiserver.ConnectorOAuthGrant, error) {
	if errors.Is(err, nango.ErrConnectionNotFound) {
		return apiserver.ConnectorOAuthGrant{}, apiserver.ErrConnectorOutcomeNotFound
	}
	if err != nil || connection.ConnectorKey != provider.config.ConnectorKey {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	response, err := provider.config.Proxy.Proxy(ctx, provider.config.ConnectorKey, connection.Reference, http.MethodGet, "/api/team.info", nil)
	workspaceID, workspaceOK := exactSlackWorkspaceID(response, err)
	if !workspaceOK {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]string{"connector_key": provider.config.ConnectorKey, "source": "managed_auth_proxy"})
	if err != nil {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	return apiserver.ConnectorOAuthGrant{ConnectionReference: connection.Reference, ProviderSubject: workspaceID, CredentialClass: "nango_connection_reference", Metadata: metadata}, nil
}

func exactSlackWorkspaceID(response nango.ProxyResponse, proxyErr error) (string, bool) {
	if proxyErr != nil || response.StatusCode != http.StatusOK || response.Location != "" || len(response.Body) < 2 || len(response.Body) > 64<<10 || containsNangoSensitivePayload(response.Body) {
		return "", false
	}
	var payload struct {
		OK   bool `json:"ok"`
		Team struct {
			ID             string          `json:"id"`
			Name           string          `json:"name"`
			Domain         string          `json:"domain"`
			EmailDomain    string          `json:"email_domain"`
			EnterpriseID   *string         `json:"enterprise_id"`
			EnterpriseName *string         `json:"enterprise_name"`
			Icon           json.RawMessage `json:"icon"`
		} `json:"team"`
		Warning          string `json:"warning"`
		ResponseMetadata struct {
			Warnings []string `json:"warnings"`
		} `json:"response_metadata"`
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return "", false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || !payload.OK || !slackWorkspaceIDPattern.MatchString(payload.Team.ID) {
		return "", false
	}
	return payload.Team.ID, true
}

func containsNangoSensitivePayload(value []byte) bool {
	lower := bytes.ToLower(value)
	for _, marker := range [][]byte{[]byte("access_token"), []byte("refresh_token"), []byte("client_secret"), []byte("private_key"), []byte("password")} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func nangoConnectionBinding(scope domain.Scope, integrationID, attemptID string) nango.ConnectionBinding {
	return nango.ConnectionBinding{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), IntegrationID: integrationID, AttemptID: attemptID}
}

func validNangoProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

type nangoServiceSecretResolver struct {
	path string
}

type nangoProviderDNSResolver struct{}

func (nangoProviderDNSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

type nangoConnectorResources struct {
	connection io.Closer
	proxy      io.Closer
}

func (resources *nangoConnectorResources) Close() error {
	if resources == nil {
		return nil
	}
	return errors.Join(resources.proxy.Close(), resources.connection.Close())
}

func addProductionNangoProvider(config RuntimeConfig, resolver nango.ServiceSecretResolver, providers map[string]apiserver.ConnectorOAuthProviderDefinition, checks map[string]apiserver.ConnectorCapabilityCheck) (io.Closer, error) {
	if config.NangoBaseURL == "" && config.NangoServiceSecretReference == "" && config.NangoEnvironment == "" {
		return nil, nil
	}
	if !validOptionalNangoConfig(config) || resolver == nil || providers == nil || checks == nil {
		return nil, errRuntimeUnavailable
	}
	if _, exists := providers["slack"]; exists {
		return nil, errRuntimeUnavailable
	}
	client, err := nango.NewProductionConnectionClient(resolver, config.ProviderTimeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	proxyClient, err := nango.NewProductionProxyClient(resolver, config.ProviderTimeout)
	if err != nil {
		_ = client.Close()
		return nil, errRuntimeUnavailable
	}
	proxy, err := nango.NewAdapter(nango.Config{
		BaseURL: config.NangoBaseURL, ServiceSecretReference: config.NangoServiceSecretReference, Environment: config.NangoEnvironment,
		Entries: []nango.Entry{{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []nango.Rule{{Method: http.MethodGet, PathPrefix: "/api/team.info"}}}},
	}, nangoProviderDNSResolver{}, proxyClient, config.ProviderTimeout)
	if err != nil {
		_ = proxyClient.Close()
		_ = client.Close()
		return nil, errRuntimeUnavailable
	}
	provider, err := newNangoOAuthProvider(nangoOAuthProviderConfig{
		Client: client, Proxy: proxy, BaseURL: config.NangoBaseURL, ServiceSecretReference: config.NangoServiceSecretReference, Environment: config.NangoEnvironment,
		ConnectorKey: "slack", Provider: "slack", AuthorizationHost: "slack.com", AuthorizationPath: "/oauth/v2/authorize", CallbackURL: config.PublicOrigin + "/api/v1/integrations/oauth/callback",
	})
	if err != nil {
		_ = proxyClient.Close()
		_ = client.Close()
		return nil, errRuntimeUnavailable
	}
	providers["slack"] = apiserver.ConnectorOAuthProviderDefinition{Provider: provider, RequestedScopes: []string{"nango:auth", "nango:proxy"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack"}
	liveCheck := func(ctx context.Context) error {
		secret, resolveErr := resolver.Resolve(ctx, config.NangoServiceSecretReference)
		validSecret := validResolvedNangoServiceSecret(secret)
		clear(secret)
		if resolveErr != nil || !validSecret {
			return errRuntimeUnavailable
		}
		if err := client.CheckReadiness(ctx, nango.ReadinessRequest{NangoBaseURL: config.NangoBaseURL, ServiceSecretReference: config.NangoServiceSecretReference, Environment: config.NangoEnvironment, ConnectorKey: "slack", Provider: "slack"}); err != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	checks["slack"], err = newCachedNangoCapabilityCheck(liveCheck, 30*time.Second, func() time.Time { return time.Now().UTC() })
	if err != nil {
		_ = proxyClient.Close()
		_ = client.Close()
		delete(providers, "slack")
		return nil, errRuntimeUnavailable
	}
	return &nangoConnectorResources{connection: client, proxy: proxyClient}, nil
}

func newCachedNangoCapabilityCheck(check apiserver.ConnectorCapabilityCheck, ttl time.Duration, now func() time.Time) (apiserver.ConnectorCapabilityCheck, error) {
	if check == nil || ttl < time.Second || ttl > time.Minute || now == nil || now().IsZero() {
		return nil, errRuntimeUnavailable
	}
	readiness := &cachedNangoCapabilityCheck{check: check, ttl: ttl, now: now}
	return readiness.Ready, nil
}

func (readiness *cachedNangoCapabilityCheck) Ready(ctx context.Context) error {
	if readiness == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	now := readiness.now().UTC()
	if !readiness.lastSuccess.IsZero() {
		elapsed := now.Sub(readiness.lastSuccess)
		if elapsed >= 0 && elapsed < readiness.ttl {
			return nil
		}
	}
	if err := readiness.check(ctx); err != nil {
		return errRuntimeUnavailable
	}
	readiness.lastSuccess = now
	return nil
}

func validResolvedNangoServiceSecret(value []byte) bool {
	if len(value) < 16 || len(value) > 4096 || string(value) != strings.TrimSpace(string(value)) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func newNangoServiceSecretResolver(path string) (*nangoServiceSecretResolver, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "service-key" || strings.Contains(path, "..") {
		return nil, errRuntimeUnavailable
	}
	return &nangoServiceSecretResolver{path: path}, nil
}

func (resolver *nangoServiceSecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	match := nangoServiceReferencePattern.FindStringSubmatch(reference)
	if resolver == nil || resolver.path == "" || ctx == nil || ctx.Err() != nil || len(match) != 2 || match[1] != "0001" {
		return nil, errRuntimeUnavailable
	}
	file, err := os.Open(resolver.path)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 16 || info.Size() > 4096 || info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o440 {
		return nil, errRuntimeUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) > 4096 || ctx.Err() != nil {
		clear(value)
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

var _ apiserver.ConnectorOAuthProvider = (*nangoOAuthProvider)(nil)
var _ apiserver.ConnectorAuthorizationStarter = (*nangoOAuthProvider)(nil)
var _ apiserver.ConnectorAuthorizationCompleter = (*nangoOAuthProvider)(nil)
var _ apiserver.ConnectorAuthorizationRecoverer = (*nangoOAuthProvider)(nil)
var _ apiserver.ConnectorAuthorizationDiscarder = (*nangoOAuthProvider)(nil)
var _ apiserver.ConnectorAuthorizationRevoker = (*nangoOAuthProvider)(nil)
var _ nango.ServiceSecretResolver = (*nangoServiceSecretResolver)(nil)
