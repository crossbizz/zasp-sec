package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The Microsoft and Salesforce token clients run the OAuth 2.0
// client-credentials grant. They share the bounded provider HTTP client of the
// GitHub and Okta clients (no proxy, no redirects, TLS 1.2 or later, one
// timeout) and return one constant error: a provider's error body is read
// only to bound it and is never returned or logged.

type productionDiscoveryMicrosoftTokenClient struct {
	http  *http.Client
	clock func() time.Time
}

func newProductionDiscoveryMicrosoftTokenClient(client *http.Client, clock func() time.Time) (*productionDiscoveryMicrosoftTokenClient, error) {
	if client == nil || client.Transport == nil || clock == nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &productionDiscoveryMicrosoftTokenClient{http: client, clock: clock}, nil
}

// ExchangeDiscoveryMicrosoftClientCredentials asks the tenant's own token
// endpoint for an application token. The scope is Microsoft Graph or one
// Dataverse environment; nothing else is requested.
func (client *productionDiscoveryMicrosoftTokenClient) ExchangeDiscoveryMicrosoftClientCredentials(ctx context.Context, tenantID, clientID string, clientSecret []byte, scope string) (discoverySaaSAccessToken, error) {
	dataverseURL, dataverseScope := strings.CutSuffix(scope, "/.default")
	if client == nil || client.http == nil || ctx == nil || ctx.Err() != nil || !discoveryMicrosoftGUIDPattern.MatchString(tenantID) || !discoveryMicrosoftGUIDPattern.MatchString(clientID) || !validDiscoveryOpaqueSecret(clientSecret, 8, 4096) ||
		scope != discoveryMicrosoftGraphScope && scope != discoveryMicrosoftARMScope && (!dataverseScope || !discoveryMicrosoftDataverseURLPattern.MatchString(dataverseURL)) {
		return discoverySaaSAccessToken{}, errDiscoveryCredentialUnavailable
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {string(clientSecret)}, "grant_type": {"client_credentials"}, "scope": {scope}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.microsoftonline.com/"+tenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	if performDiscoveryProviderTokenJSON(client.http, request, &response, 64<<10) != nil || response.RefreshToken != "" || !strings.EqualFold(response.TokenType, "bearer") || response.ExpiresIn < 60 || response.ExpiresIn > 86_400 || !validDiscoverySaaSAccessToken([]byte(response.AccessToken)) {
		response.AccessToken, response.RefreshToken = "", ""
		return discoverySaaSAccessToken{}, errDiscoveryCredentialUnavailable
	}
	now := client.clock()
	if now.IsZero() || now.Location() != time.UTC {
		response.AccessToken = ""
		return discoverySaaSAccessToken{}, errDiscoveryCredentialUnavailable
	}
	result := discoverySaaSAccessToken{Token: []byte(response.AccessToken), ExpiresAt: now.Add(time.Duration(response.ExpiresIn) * time.Second)}
	response.AccessToken = ""
	return result, nil
}

type productionDiscoverySalesforceTokenClient struct {
	http *http.Client
}

func newProductionDiscoverySalesforceTokenClient(client *http.Client) (*productionDiscoverySalesforceTokenClient, error) {
	if client == nil || client.Transport == nil {
		return nil, errDiscoveryCredentialUnavailable
	}
	return &productionDiscoverySalesforceTokenClient{http: client}, nil
}

// ExchangeDiscoverySalesforceClientCredentials asks the org's My Domain token
// endpoint for a token of the connected app's run-as user. The result reports
// the instance and the org the response names; the caller compares both with
// the connection.
func (client *productionDiscoverySalesforceTokenClient) ExchangeDiscoverySalesforceClientCredentials(ctx context.Context, instanceURL, clientID string, clientSecret []byte) (discoverySaaSAccessToken, error) {
	if client == nil || client.http == nil || ctx == nil || ctx.Err() != nil || !discoverySalesforceInstanceURLPattern.MatchString(instanceURL) || !discoverySalesforceClientIDPattern.MatchString(clientID) || !validDiscoveryOpaqueSecret(clientSecret, 8, 4096) {
		return discoverySaaSAccessToken{}, errDiscoveryCredentialUnavailable
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {string(clientSecret)}, "grant_type": {"client_credentials"}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, instanceURL+"/services/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		InstanceURL  string `json:"instance_url"`
		Identity     string `json:"id,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	organizationID, identityOK := "", false
	if performDiscoveryProviderTokenJSON(client.http, request, &response, 64<<10) == nil {
		organizationID, identityOK = discoverySalesforceIdentityOrganization(response.Identity)
	}
	if !identityOK || response.RefreshToken != "" || !strings.EqualFold(response.TokenType, "bearer") || !discoverySalesforceInstanceURLPattern.MatchString(response.InstanceURL) || !validDiscoverySaaSAccessToken([]byte(response.AccessToken)) {
		response.AccessToken, response.RefreshToken = "", ""
		return discoverySaaSAccessToken{}, errDiscoveryCredentialUnavailable
	}
	result := discoverySaaSAccessToken{Token: []byte(response.AccessToken), InstanceURL: response.InstanceURL, OrganizationID: organizationID}
	response.AccessToken = ""
	return result, nil
}

var _ discoveryMicrosoftTokenAPI = (*productionDiscoveryMicrosoftTokenClient)(nil)
var _ discoverySalesforceTokenAPI = (*productionDiscoverySalesforceTokenClient)(nil)
