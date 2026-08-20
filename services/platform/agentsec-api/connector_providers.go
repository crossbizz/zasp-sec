package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
)

type connectorProviderSecrets struct {
	driver *connectorSecretsDriver
	root   string
	kmsKey string
}

func (store *connectorProviderSecrets) resolve(ctx context.Context, reference string) ([]byte, error) {
	name, ok := store.name(reference)
	if !ok {
		return nil, errRuntimeUnavailable
	}
	value, err := store.driver.Read(ctx, name)
	if err != nil || len(value) < 8 || len(value) > 2048 {
		return nil, errRuntimeUnavailable
	}
	return value, nil
}

func (store *connectorProviderSecrets) put(ctx context.Context, reference string, value []byte) error {
	name, ok := store.name(reference)
	if !ok || len(value) < 16 || len(value) > 2048 {
		return errRuntimeUnavailable
	}
	if err := store.driver.Create(ctx, name, store.kmsKey, value); err == nil {
		return nil
	}
	existing, err := store.driver.Read(ctx, name)
	if err != nil || !bytes.Equal(existing, value) {
		return errRuntimeUnavailable
	}
	return nil
}

func (store *connectorProviderSecrets) ready(ctx context.Context, reference string) error {
	value, err := store.resolve(ctx, reference)
	clear(value)
	return err
}

func (store *connectorProviderSecrets) name(reference string) (string, bool) {
	if store == nil || store.driver == nil || !connectorReferencePattern.MatchString(reference) || strings.Contains(reference, "..") {
		return "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(reference, "ref:"), "/", 2)
	if len(parts) != 2 {
		return "", false
	}
	return store.root + "/" + parts[0] + "/" + parts[1], true
}

type githubExchangeClient struct {
	http    *http.Client
	secrets *connectorProviderSecrets
}

func (client *githubExchangeClient) Exchange(ctx context.Context, request githubdiscovery.ExchangeRequest) (githubdiscovery.Connection, error) {
	secret, err := client.secrets.resolve(ctx, request.ClientSecretReference)
	if err != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	form := url.Values{"client_id": {request.ClientID}, "client_secret": {string(secret)}, "code": {request.Code}, "redirect_uri": {request.CallbackURL}, "code_verifier": {string(request.PKCEVerifier)}}
	clear(secret)
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	tokenRequest.Header.Set("Accept", "application/json")
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if performConnectorJSON(client.http, tokenRequest, &token, 32<<10) != nil || len(token.AccessToken) < 20 || len(token.AccessToken) > 4096 || !strings.EqualFold(token.TokenType, "bearer") {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	installationsRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/installations?per_page=2", nil)
	installationsRequest.Header.Set("Accept", "application/vnd.github+json")
	installationsRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	installationsRequest.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var page struct {
		TotalCount    int `json:"total_count"`
		Installations []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
			RepositorySelection string            `json:"repository_selection"`
			Permissions         map[string]string `json:"permissions"`
		} `json:"installations"`
	}
	if performConnectorJSON(client.http, installationsRequest, &page, 128<<10) != nil || page.TotalCount != 1 || len(page.Installations) != 1 {
		return githubdiscovery.Connection{}, errRuntimeUnavailable
	}
	installation := page.Installations[0]
	return githubdiscovery.Connection{Reference: "ref:github/install/" + strconv.FormatInt(installation.ID, 10), InstallationID: installation.ID, AccountLogin: installation.Account.Login, RepositorySelection: installation.RepositorySelection, Permissions: installation.Permissions}, nil
}

type oktaExchangeClient struct {
	http    *http.Client
	secrets *connectorProviderSecrets
}

func (client *oktaExchangeClient) Exchange(ctx context.Context, request idpdiscovery.ExchangeRequest) (idpdiscovery.Connection, error) {
	secret, err := client.secrets.resolve(ctx, request.ClientSecretReference)
	if err != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {request.Code}, "redirect_uri": {request.CallbackURL}, "code_verifier": {string(request.PKCEVerifier)}}
	tokenRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, request.Issuer+"/oauth2/v1/token", strings.NewReader(form.Encode()))
	tokenRequest.SetBasicAuth(request.ClientID, string(secret))
	clear(secret)
	tokenRequest.Header.Set("Accept", "application/json")
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if performConnectorJSON(client.http, tokenRequest, &token, 64<<10) != nil || len(token.AccessToken) < 20 || len(token.AccessToken) > 4096 || len(token.RefreshToken) < 20 || len(token.RefreshToken) > 4096 || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn < 1 || token.ExpiresIn > 3600 {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	profileRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, request.Issuer+"/oauth2/v1/userinfo", nil)
	profileRequest.Header.Set("Accept", "application/json")
	profileRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	var profile struct {
		Subject string `json:"sub"`
	}
	if performConnectorJSON(client.http, profileRequest, &profile, 32<<10) != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	digest := sha256.Sum256([]byte(token.RefreshToken))
	reference := "ref:okta/refresh/" + hex.EncodeToString(digest[:16])
	if err := client.secrets.put(ctx, reference, []byte(token.RefreshToken)); err != nil {
		return idpdiscovery.Connection{}, errRuntimeUnavailable
	}
	issuer, _ := url.Parse(request.Issuer)
	scopes := strings.Fields(token.Scope)
	sort.Strings(scopes)
	return idpdiscovery.Connection{Reference: reference, Subject: profile.Subject, Tenant: issuer.Hostname(), Scopes: scopes}, nil
}

func performConnectorJSON(client *http.Client, request *http.Request, target any, maximum int64) error {
	if client == nil || request == nil || maximum < 1 || maximum > 1<<20 {
		return errRuntimeUnavailable
	}
	response, err := client.Do(request)
	if err != nil {
		return errRuntimeUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode < 200 || response.StatusCode > 299 || response.Header.Get("Location") != "" || mediaErr != nil || strings.ToLower(mediaType) != "application/json" || len(parameters) > 1 || len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8") {
		return errRuntimeUnavailable
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return errRuntimeUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errRuntimeUnavailable
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errRuntimeUnavailable
	}
	return nil
}

type githubOAuthProvider struct{ adapter *githubdiscovery.Adapter }

func (provider *githubOAuthProvider) AuthorizationURL(state, challenge string) (string, error) {
	return provider.adapter.AuthorizationURL(state, challenge)
}
func (provider *githubOAuthProvider) Complete(ctx context.Context, code string, verifier []byte) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Complete(ctx, code, verifier)
	if err != nil {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"account_login": value.AccountLogin, "installation_id": value.InstallationID, "permissions": value.Permissions, "repository_selection": value.RepositorySelection})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: "installation:" + strconv.FormatInt(value.InstallationID, 10), CredentialClass: "github_installation_reference", Metadata: metadata}, err
}

type oktaOAuthProvider struct{ adapter *idpdiscovery.OktaAdapter }

func (provider *oktaOAuthProvider) AuthorizationURL(state, challenge string) (string, error) {
	return provider.adapter.AuthorizationURL(state, challenge)
}
func (provider *oktaOAuthProvider) Complete(ctx context.Context, code string, verifier []byte) (apiserver.ConnectorOAuthGrant, error) {
	value, err := provider.adapter.Complete(ctx, code, verifier)
	if err != nil {
		return apiserver.ConnectorOAuthGrant{}, errRuntimeUnavailable
	}
	metadata, err := json.Marshal(map[string]any{"scopes": value.Scopes, "subject": value.Subject, "tenant": value.Tenant})
	return apiserver.ConnectorOAuthGrant{ConnectionReference: value.Reference, ProviderSubject: value.Subject, CredentialClass: "okta_refresh_reference", Metadata: metadata}, err
}

type oktaOAuthFactory struct {
	clientID, secretReference, callback string
	exchange                            idpdiscovery.ExchangeClient
	timeout                             time.Duration
}

func (factory *oktaOAuthFactory) Provider(configuration map[string]string) (apiserver.ConnectorOAuthProvider, error) {
	if factory == nil || len(configuration) != 1 {
		return nil, errRuntimeUnavailable
	}
	adapter, err := idpdiscovery.NewOktaAdapter(idpdiscovery.Config{Issuer: configuration["issuer"], ClientID: factory.clientID, ClientSecretReference: factory.secretReference, CallbackURL: factory.callback}, factory.exchange, factory.timeout)
	if err != nil {
		return nil, errRuntimeUnavailable
	}
	return &oktaOAuthProvider{adapter: adapter}, nil
}

func newConnectorHTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 1 << 20}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

var _ githubdiscovery.ExchangeClient = (*githubExchangeClient)(nil)
var _ idpdiscovery.ExchangeClient = (*oktaExchangeClient)(nil)
var _ apiserver.ConnectorOAuthProvider = (*githubOAuthProvider)(nil)
var _ apiserver.ConnectorOAuthProviderFactory = (*oktaOAuthFactory)(nil)
