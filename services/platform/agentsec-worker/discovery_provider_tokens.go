package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type productionDiscoveryGitHubTokenClient struct {
	http  *http.Client
	clock func() time.Time
}

func newProductionDiscoveryGitHubTokenClient(client *http.Client, clock func() time.Time) (*productionDiscoveryGitHubTokenClient, error) {
	if client == nil || client.Transport == nil || clock == nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &productionDiscoveryGitHubTokenClient{http: client, clock: clock}, nil
}

func (client *productionDiscoveryGitHubTokenClient) MintDiscoveryInstallationToken(ctx context.Context, appID string, privateKey []byte, installationID int64) (discoveryGitHubInstallationToken, error) {
	if client == nil || client.http == nil || ctx == nil || ctx.Err() != nil || !discoveryGitHubAppIDPattern.MatchString(appID) || installationID < 1 || len(privateKey) < 256 || len(privateKey) > 16_384 {
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	block, rest := pem.Decode(privateKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 {
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	now := client.clock()
	if now.IsZero() || now.Location() != time.UTC {
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{IssuedAt: now.Add(-30 * time.Second).Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Issuer: appID})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	clear(payloadBytes)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, signErr := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if signErr != nil {
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	jwt := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	clear(signature)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/app/installations/"+strconv.FormatInt(installationID, 10)+"/access_tokens", strings.NewReader(`{"permissions":{"actions":"read","contents":"read","metadata":"read"}}`))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	jwt = ""
	var response struct {
		Token               string                           `json:"token"`
		ExpiresAt           time.Time                        `json:"expires_at"`
		Permissions         map[string]string                `json:"permissions"`
		RepositorySelection string                           `json:"repository_selection"`
		Repositories        discardedGitHubTokenRepositories `json:"repositories,omitempty"`
	}
	if performDiscoveryProviderJSON(client.http, request, http.StatusCreated, &response, 8<<20) != nil || !validDiscoveryOpaqueSecret([]byte(response.Token), 16, 8192) || !response.ExpiresAt.After(now.Add(time.Minute)) || response.ExpiresAt.After(now.Add(65*time.Minute)) || !validDiscoveryGitHubPermissions(response.Permissions) || response.RepositorySelection != "all" && response.RepositorySelection != "selected" || response.RepositorySelection == "all" && response.Repositories.Count != 0 {
		response.Token = ""
		return discoveryGitHubInstallationToken{}, errDiscoveryCredentialUnavailable
	}
	result := discoveryGitHubInstallationToken{Token: []byte(response.Token), InstallationID: installationID, ExpiresAt: response.ExpiresAt.UTC()}
	response.Token = ""
	return result, nil
}

type discardedGitHubTokenRepositories struct {
	Count int
}

func (repositories *discardedGitHubTokenRepositories) UnmarshalJSON(value []byte) error {
	if repositories == nil || len(value) < 2 || len(value) > 8<<20 {
		return errDiscoveryCredentialUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') {
		return errDiscoveryCredentialUnavailable
	}
	count := 0
	for decoder.More() {
		var repository map[string]json.RawMessage
		if decoder.Decode(&repository) != nil || len(repository) == 0 {
			return errDiscoveryCredentialUnavailable
		}
		count++
		if count > 500 {
			return errDiscoveryCredentialUnavailable
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') || decoder.Decode(new(any)) != io.EOF {
		return errDiscoveryCredentialUnavailable
	}
	repositories.Count = count
	return nil
}

type productionDiscoveryOktaTokenClient struct {
	http  *http.Client
	clock func() time.Time
}

func newProductionDiscoveryOktaTokenClient(client *http.Client, clock func() time.Time) (*productionDiscoveryOktaTokenClient, error) {
	if client == nil || client.Transport == nil || clock == nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &productionDiscoveryOktaTokenClient{http: client, clock: clock}, nil
}

func (client *productionDiscoveryOktaTokenClient) ExchangeDiscoveryRefreshToken(ctx context.Context, issuer, clientID string, clientSecret, refreshToken []byte) (discoveryOktaAccessToken, error) {
	issuerMatch := discoveryOktaIssuerPattern.FindStringSubmatch(issuer)
	if client == nil || client.http == nil || ctx == nil || ctx.Err() != nil || len(issuerMatch) != 2 || !discoveryOktaClientIDPattern.MatchString(clientID) || !validDiscoveryOpaqueSecret(clientSecret, 8, 16_384) || !validDiscoveryOpaqueSecret(refreshToken, 16, 8192) {
		return discoveryOktaAccessToken{}, errDiscoveryCredentialUnavailable
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {string(refreshToken)}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth2/v1/token", strings.NewReader(form.Encode()))
	request.SetBasicAuth(clientID, string(clientSecret))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	if performDiscoveryProviderJSON(client.http, request, http.StatusOK, &response, 64<<10) != nil || response.RefreshToken != "" || !strings.EqualFold(response.TokenType, "bearer") || response.ExpiresIn < 60 || response.ExpiresIn > 3600 || !validDiscoveryOpaqueSecret([]byte(response.AccessToken), 16, 8192) {
		response.AccessToken, response.RefreshToken = "", ""
		return discoveryOktaAccessToken{}, errDiscoveryCredentialUnavailable
	}
	scopes := strings.Fields(response.Scope)
	sort.Strings(scopes)
	if len(scopes) < 1 || len(scopes) > 32 || hasDuplicateDiscoveryStrings(scopes) {
		response.AccessToken = ""
		return discoveryOktaAccessToken{}, errDiscoveryCredentialUnavailable
	}
	now := client.clock()
	if now.IsZero() || now.Location() != time.UTC {
		response.AccessToken = ""
		return discoveryOktaAccessToken{}, errDiscoveryCredentialUnavailable
	}
	result := discoveryOktaAccessToken{Token: []byte(response.AccessToken), Tenant: issuerMatch[1], Scopes: scopes, ExpiresAt: now.Add(time.Duration(response.ExpiresIn) * time.Second)}
	response.AccessToken = ""
	return result, nil
}

func newDiscoveryProviderHTTPClient(timeout time.Duration) (*http.Client, *http.Transport, error) {
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, nil, errDiscoveryCredentialUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: -1}).DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: rejectDiscoveryProviderRedirect}, transport, nil
}

func rejectDiscoveryProviderRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func performDiscoveryProviderJSON(client *http.Client, request *http.Request, expectedStatus int, destination any, maximum int64) error {
	if client == nil || request == nil || destination == nil || maximum < 1 || maximum > 8<<20 {
		return errDiscoveryCredentialUnavailable
	}
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return errDiscoveryCredentialUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != expectedStatus || response.Header.Get("Location") != "" || mediaErr != nil || strings.ToLower(mediaType) != "application/json" || len(parameters) > 1 || len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8") {
		return errDiscoveryCredentialUnavailable
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if readErr != nil || int64(len(payload)) < 2 || int64(len(payload)) > maximum {
		clear(payload)
		return errDiscoveryCredentialUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(destination)
	var extra any
	extraErr := decoder.Decode(&extra)
	clear(payload)
	if decodeErr != nil || extraErr != io.EOF {
		return errDiscoveryCredentialUnavailable
	}
	return nil
}

func validDiscoveryGitHubPermissions(values map[string]string) bool {
	return len(values) == 3 && values["actions"] == "read" && values["contents"] == "read" && values["metadata"] == "read"
}

func hasDuplicateDiscoveryStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

var _ discoveryGitHubTokenAPI = (*productionDiscoveryGitHubTokenClient)(nil)
var _ discoveryOktaTokenAPI = (*productionDiscoveryOktaTokenClient)(nil)
