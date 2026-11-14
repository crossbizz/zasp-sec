package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// Microsoft and Salesforce are reference-authorized: the integration names an
// OAuth client secret by reference and the secret is read from Secrets
// Manager at <root>/<provider>/client-secret/<id>. A probe proves the
// reference resolves and that the provider issues a token for it, by running
// the same client-credentials exchange the discovery worker runs. It keeps
// nothing: the secret and the token are cleared before it returns, and a
// provider's error body is never read into an error.

var (
	saasGUIDPattern                   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	saasDataverseURLPattern           = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	saasSalesforceInstancePattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$`)
	saasSalesforceOrganizationPattern = regexp.MustCompile(`^00D[A-Za-z0-9]{15}$`)
	saasSalesforceClientIDPattern     = regexp.MustCompile(`^[!-~]{16,256}$`)
	saasSalesforceIdentityPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9.-]{0,251}\.salesforce\.com/id/(00D[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?)/005[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?$`)
)

type saasTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	InstanceURL  string `json:"instance_url,omitempty"`
	Identity     string `json:"id,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// exchangeSaaSClientCredentials posts one client-credentials form and reads
// the token response: exact status, JSON media type, one document of at most
// 64 KiB. Members the probe does not read are ignored, as RFC 6749 requires.
func exchangeSaaSClientCredentials(ctx context.Context, client *http.Client, endpoint string, form url.Values) (saasTokenResponse, bool) {
	if client == nil || ctx == nil || ctx.Err() != nil {
		return saasTokenResponse{}, false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return saasTokenResponse{}, false
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return saasTokenResponse{}, false
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != "" || mediaErr != nil || strings.ToLower(mediaType) != "application/json" {
		return saasTokenResponse{}, false
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	defer clear(payload)
	if readErr != nil || len(payload) < 2 || len(payload) > 64<<10 {
		return saasTokenResponse{}, false
	}
	var value saasTokenResponse
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var trailing any
	if decoder.Decode(&value) != nil || decoder.Decode(&trailing) != io.EOF || !strings.EqualFold(value.TokenType, "bearer") || value.RefreshToken != "" || !validSaaSAccessToken(value.AccessToken) {
		return saasTokenResponse{}, false
	}
	// Only the fact that a token was issued is kept.
	value.AccessToken = ""
	return value, true
}

func validSaaSAccessToken(value string) bool {
	if len(value) < 16 || len(value) > 8192 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '"' || value[index] == '\\' {
			return false
		}
	}
	return true
}

func validSaaSClientSecret(value []byte) bool {
	if len(value) < 8 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

type microsoftReferenceProbe struct {
	resolver *referenceSecretResolver
	http     *http.Client
}

func (probe *microsoftReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) (apiserver.ReferenceAuthorizationSubject, error) {
	var config struct {
		ClientID              string `json:"client_id"`
		ClientSecretReference string `json:"client_secret_reference"`
		DataverseURL          string `json:"dataverse_url,omitempty"`
		TenantID              string `json:"tenant_id"`
	}
	if probe == nil || probe.resolver == nil || probe.http == nil || !decodeStrictReferenceJSON(target.Configuration, &config, 4096) || config.ClientSecretReference != target.ConnectionReference ||
		!saasGUIDPattern.MatchString(config.TenantID) || !saasGUIDPattern.MatchString(config.ClientID) || config.DataverseURL != "" && !saasDataverseURLPattern.MatchString(config.DataverseURL) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	secret, err := probe.resolver.Resolve(ctx, config.ClientSecretReference)
	defer clear(secret)
	if err != nil || !validSaaSClientSecret(secret) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	// The tenant's own token endpoint issues the token, so a token proves the
	// application is registered in this tenant with this secret.
	scopes := []string{"https://graph.microsoft.com/.default"}
	if config.DataverseURL != "" {
		scopes = append(scopes, config.DataverseURL+"/.default")
	}
	for _, scope := range scopes {
		form := url.Values{"client_id": {config.ClientID}, "client_secret": {string(secret)}, "grant_type": {"client_credentials"}, "scope": {scope}}
		if _, ok := exchangeSaaSClientCredentials(ctx, probe.http, "https://login.microsoftonline.com/"+config.TenantID+"/oauth2/v2.0/token", form); !ok {
			return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
		}
	}
	return apiserver.ReferenceAuthorizationSubject{Kind: "microsoft_tenant", ID: config.TenantID}, nil
}

type salesforceReferenceProbe struct {
	resolver *referenceSecretResolver
	http     *http.Client
}

func (probe *salesforceReferenceProbe) ProbeReferenceAuthorization(ctx context.Context, target apiserver.ReferenceAuthorizationTarget) (apiserver.ReferenceAuthorizationSubject, error) {
	var config struct {
		ClientID              string `json:"client_id"`
		ClientSecretReference string `json:"client_secret_reference"`
		InstanceURL           string `json:"instance_url"`
		OrganizationID        string `json:"organization_id"`
	}
	if probe == nil || probe.resolver == nil || probe.http == nil || !decodeStrictReferenceJSON(target.Configuration, &config, 4096) || config.ClientSecretReference != target.ConnectionReference ||
		!saasSalesforceInstancePattern.MatchString(config.InstanceURL) || !saasSalesforceOrganizationPattern.MatchString(config.OrganizationID) || !saasSalesforceClientIDPattern.MatchString(config.ClientID) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	secret, err := probe.resolver.Resolve(ctx, config.ClientSecretReference)
	defer clear(secret)
	if err != nil || !validSaaSClientSecret(secret) {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	form := url.Values{"client_id": {config.ClientID}, "client_secret": {string(secret)}, "grant_type": {"client_credentials"}}
	response, ok := exchangeSaaSClientCredentials(ctx, probe.http, config.InstanceURL+"/services/oauth2/token", form)
	if !ok || response.InstanceURL != config.InstanceURL {
		return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
	}
	// The identity URL of a token response names the org by its 15- or
	// 18-character id. When the response carries one it must be the
	// configured org; the collector attests the org again on its first page.
	if response.Identity != "" {
		match := saasSalesforceIdentityPattern.FindStringSubmatch(response.Identity)
		if len(match) != 2 || match[1] != config.OrganizationID && match[1] != config.OrganizationID[:15] {
			return apiserver.ReferenceAuthorizationSubject{}, errRuntimeUnavailable
		}
	}
	return apiserver.ReferenceAuthorizationSubject{Kind: "salesforce_org", ID: config.OrganizationID}, nil
}

var _ apiserver.ReferenceAuthorizationProbe = (*microsoftReferenceProbe)(nil)
var _ apiserver.ReferenceAuthorizationProbe = (*salesforceReferenceProbe)(nil)
