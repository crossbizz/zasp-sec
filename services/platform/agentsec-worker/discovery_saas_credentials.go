package main

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// Microsoft and Salesforce are reference-authorized like AWS: the integration
// configuration names one customer-supplied secret (an OAuth client secret) by
// reference, the reference is the connection's credential reference, and the
// value lives in Secrets Manager under the discovery secret root at
// <root>/<provider>/client-secret/<id>. The worker exchanges it for a
// short-lived access token on every collection; the secret never leaves the
// resolver and the token never leaves the credential material.

const (
	discoveryMicrosoftGraphScope = "https://graph.microsoft.com/.default"
	// The scope of an Azure Resource Manager token for the same application.
	discoveryMicrosoftARMScope      = "https://management.azure.com/.default"
	discoveryMicrosoftSecretPrefix  = "ref:microsoft/client-secret/"
	discoverySalesforceSecretPrefix = "ref:salesforce/client-secret/"
)

var (
	discoveryMicrosoftGUIDPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	discoveryMicrosoftDataverseURLPattern  = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	discoverySalesforceInstanceURLPattern  = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$`)
	discoverySalesforceOrganizationPattern = regexp.MustCompile(`^00D[A-Za-z0-9]{15}$`)
	discoverySalesforceClientIDPattern     = regexp.MustCompile(`^[!-~]{16,256}$`)
	discoverySaaSSecretReferencePattern    = regexp.MustCompile(`^ref:(microsoft|salesforce)/client-secret/[a-z0-9][a-z0-9._-]{7,127}$`)
)

// discoverySaaSAccessToken is one client-credentials access token.
type discoverySaaSAccessToken struct {
	Token []byte
	// InstanceURL and OrganizationID are what a Salesforce token response
	// says about itself. OrganizationID is empty when the response carried no
	// identity URL.
	InstanceURL    string
	OrganizationID string
	// ExpiresAt is zero when the provider reports no lifetime (Salesforce).
	ExpiresAt time.Time
}

func (value *discoverySaaSAccessToken) Destroy() {
	if value == nil {
		return
	}
	clear(value.Token)
	*value = discoverySaaSAccessToken{}
}

type discoveryMicrosoftTokenAPI interface {
	ExchangeDiscoveryMicrosoftClientCredentials(ctx context.Context, tenantID, clientID string, clientSecret []byte, scope string) (discoverySaaSAccessToken, error)
}

type discoverySalesforceTokenAPI interface {
	ExchangeDiscoverySalesforceClientCredentials(ctx context.Context, instanceURL, clientID string, clientSecret []byte) (discoverySaaSAccessToken, error)
}

func validDiscoverySaaSSecretReference(value, prefix string) bool {
	return discoverySaaSSecretReferencePattern.MatchString(value) && validDiscoveryCredentialReference(value, prefix)
}

func (resolver *productionDiscoveryCredentialResolver) resolveMicrosoft(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		ClientID              string `json:"client_id"`
		ClientSecretReference string `json:"client_secret_reference"`
		DataverseURL          string `json:"dataverse_url,omitempty"`
		TenantID              string `json:"tenant_id"`
	}
	if nilDiscoveryCredentialDependency(resolver.config.Microsoft) || !decodeCanonicalDiscoveryCredentialJSON(bound.configuration(), &config, 4096) ||
		!discoveryMicrosoftGUIDPattern.MatchString(config.TenantID) || config.TenantID != bound.Credential.ExpectedSubject.ID || !discoveryMicrosoftGUIDPattern.MatchString(config.ClientID) ||
		config.ClientSecretReference != bound.Credential.Reference || !validDiscoverySaaSSecretReference(config.ClientSecretReference, discoveryMicrosoftSecretPrefix) ||
		config.DataverseURL != "" && !discoveryMicrosoftDataverseURLPattern.MatchString(config.DataverseURL) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	clientSecret, secretErr := resolver.resolveCurrentSecret(ctx, bound, config.ClientSecretReference)
	if secretErr != nil || !validDiscoveryOpaqueSecret(clientSecret, 8, 4096) {
		clear(clientSecret)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, secretErr)
	}
	defer clear(clientSecret)
	if err := bound.checkCurrent(ctx); err != nil {
		return discoveryCredentialEnvelope{}, err
	}
	graph, graphErr := resolver.config.Microsoft.ExchangeDiscoveryMicrosoftClientCredentials(ctx, config.TenantID, config.ClientID, clientSecret, discoveryMicrosoftGraphScope)
	if graphErr != nil || ctx.Err() != nil {
		graph.Destroy()
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, graphErr)
	}
	defer graph.Destroy()
	expiresAt := providerDiscoveryCredentialExpiry(now, graph.ExpiresAt)
	var dataverse discoverySaaSAccessToken
	defer dataverse.Destroy()
	if config.DataverseURL != "" {
		if err := bound.checkCurrent(ctx); err != nil {
			return discoveryCredentialEnvelope{}, err
		}
		var dataverseErr error
		dataverse, dataverseErr = resolver.config.Microsoft.ExchangeDiscoveryMicrosoftClientCredentials(ctx, config.TenantID, config.ClientID, clientSecret, config.DataverseURL+"/.default")
		if dataverseErr != nil || ctx.Err() != nil {
			return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, dataverseErr)
		}
		// The credential is good only while both tokens are.
		if dataverseExpiry := providerDiscoveryCredentialExpiry(now, dataverse.ExpiresAt); dataverseExpiry.Before(expiresAt) {
			expiresAt = dataverseExpiry
		}
	}
	// A Resource Manager token for the same application, when the deployment
	// reads Azure. The token is issued whether or not the application has a
	// role in Azure; what it may read there is decided by Azure.
	var arm discoverySaaSAccessToken
	defer arm.Destroy()
	if resolver.config.MicrosoftAzure {
		if err := bound.checkCurrent(ctx); err != nil {
			return discoveryCredentialEnvelope{}, err
		}
		var armErr error
		arm, armErr = resolver.config.Microsoft.ExchangeDiscoveryMicrosoftClientCredentials(ctx, config.TenantID, config.ClientID, clientSecret, discoveryMicrosoftARMScope)
		if armErr != nil || ctx.Err() != nil {
			return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, armErr)
		}
		if armExpiry := providerDiscoveryCredentialExpiry(now, arm.ExpiresAt); armExpiry.Before(expiresAt) {
			expiresAt = armExpiry
		}
	}
	credential, ok := encodeDiscoveryMicrosoftCollectorCredentialWithARM(arm.Token, graph.Token, dataverse.Token, config.DataverseURL)
	if !ok || !expiresAt.After(now) {
		clear(credential)
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) { value.BearerToken = credential }), nil
}

func (resolver *productionDiscoveryCredentialResolver) resolveSalesforce(ctx context.Context, bound discoveryCredentialMaterialRequest, now time.Time) (discoveryCredentialEnvelope, error) {
	var config struct {
		ClientID              string `json:"client_id"`
		ClientSecretReference string `json:"client_secret_reference"`
		InstanceURL           string `json:"instance_url"`
		OrganizationID        string `json:"organization_id"`
	}
	if nilDiscoveryCredentialDependency(resolver.config.Salesforce) || !decodeCanonicalDiscoveryCredentialJSON(bound.configuration(), &config, 4096) ||
		!discoverySalesforceInstanceURLPattern.MatchString(config.InstanceURL) || !discoverySalesforceOrganizationPattern.MatchString(config.OrganizationID) || config.OrganizationID != bound.Credential.ExpectedSubject.ID ||
		!discoverySalesforceClientIDPattern.MatchString(config.ClientID) ||
		config.ClientSecretReference != bound.Credential.Reference || !validDiscoverySaaSSecretReference(config.ClientSecretReference, discoverySalesforceSecretPrefix) {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureMalformed)
	}
	clientSecret, secretErr := resolver.resolveCurrentSecret(ctx, bound, config.ClientSecretReference)
	if secretErr != nil || !validDiscoveryOpaqueSecret(clientSecret, 8, 4096) {
		clear(clientSecret)
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, secretErr)
	}
	if err := bound.checkCurrent(ctx); err != nil {
		clear(clientSecret)
		return discoveryCredentialEnvelope{}, err
	}
	result, exchangeErr := resolver.config.Salesforce.ExchangeDiscoverySalesforceClientCredentials(ctx, config.InstanceURL, config.ClientID, clientSecret)
	clear(clientSecret)
	if exchangeErr != nil || ctx.Err() != nil {
		result.Destroy()
		return discoveryCredentialEnvelope{}, mapDiscoveryCredentialDependency(ctx, exchangeErr)
	}
	defer result.Destroy()
	// A token for another instance or another org is not this connection's
	// credential. The identity URL of a response carries the org as its
	// 15- or 18-character id; a response without one names no org.
	if result.InstanceURL != config.InstanceURL || result.OrganizationID != "" && result.OrganizationID != config.OrganizationID && result.OrganizationID != config.OrganizationID[:15] {
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	// Salesforce reports no token lifetime; a session lasts at least 15
	// minutes, the bound of one collection.
	expiresAt := now.Add(discoveryStaticCredentialTTL).UTC()
	credential, ok := encodeDiscoverySalesforceCollectorCredential(result.Token, config.InstanceURL)
	if !ok || !expiresAt.After(now) {
		clear(credential)
		return discoveryCredentialEnvelope{}, discoveryCredentialFailure(ctx, collection.FailureDenied)
	}
	return newDiscoveryCredentialEnvelope(bound, expiresAt, func(value *discoveryCredentialEnvelope) { value.BearerToken = credential }), nil
}

// validDiscoverySaaSAccessToken admits a token of 16 to 8192 visible ASCII
// bytes without a quote or a backslash, so it is written into the collector's
// JSON credential without escaping and cannot change its structure.
func validDiscoverySaaSAccessToken(value []byte) bool {
	if len(value) < 16 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

// encodeDiscoveryMicrosoftCollectorCredential writes the credential the
// Microsoft collector reads: compact JSON with sorted members,
// {"graph_token":"…"} or
// {"dataverse_token":"…","dataverse_url":"https://…","graph_token":"…"}.
func encodeDiscoveryMicrosoftCollectorCredential(graphToken, dataverseToken []byte, dataverseURL string) ([]byte, bool) {
	if !validDiscoverySaaSAccessToken(graphToken) || (dataverseURL == "") != (len(dataverseToken) == 0) {
		return nil, false
	}
	if dataverseURL == "" {
		encoded := make([]byte, 0, len(graphToken)+32)
		encoded = append(encoded, `{"graph_token":"`...)
		encoded = append(encoded, graphToken...)
		return append(encoded, `"}`...), true
	}
	if !validDiscoverySaaSAccessToken(dataverseToken) || !discoveryMicrosoftDataverseURLPattern.MatchString(dataverseURL) {
		return nil, false
	}
	encoded := make([]byte, 0, len(graphToken)+len(dataverseToken)+len(dataverseURL)+64)
	encoded = append(encoded, `{"dataverse_token":"`...)
	encoded = append(encoded, dataverseToken...)
	encoded = append(encoded, `","dataverse_url":"`...)
	encoded = append(encoded, dataverseURL...)
	encoded = append(encoded, `","graph_token":"`...)
	encoded = append(encoded, graphToken...)
	return append(encoded, `"}`...), true
}

// encodeDiscoveryMicrosoftCollectorCredentialWithARM writes the same
// credential with a leading arm_token member when a Resource Manager token
// is given: {"arm_token":"…","graph_token":"…"} or
// {"arm_token":"…","dataverse_token":"…","dataverse_url":"…","graph_token":"…"}.
func encodeDiscoveryMicrosoftCollectorCredentialWithARM(armToken, graphToken, dataverseToken []byte, dataverseURL string) ([]byte, bool) {
	base, ok := encodeDiscoveryMicrosoftCollectorCredential(graphToken, dataverseToken, dataverseURL)
	if !ok || len(armToken) == 0 {
		return base, ok
	}
	defer clear(base)
	if !validDiscoverySaaSAccessToken(armToken) {
		return nil, false
	}
	encoded := make([]byte, 0, len(base)+len(armToken)+24)
	encoded = append(encoded, `{"arm_token":"`...)
	encoded = append(encoded, armToken...)
	encoded = append(encoded, `",`...)
	return append(encoded, base[1:]...), true
}

// encodeDiscoverySalesforceCollectorCredential writes
// {"access_token":"…","instance_url":"https://….my.salesforce.com"}.
func encodeDiscoverySalesforceCollectorCredential(accessToken []byte, instanceURL string) ([]byte, bool) {
	if !validDiscoverySaaSAccessToken(accessToken) || !discoverySalesforceInstanceURLPattern.MatchString(instanceURL) {
		return nil, false
	}
	encoded := make([]byte, 0, len(accessToken)+len(instanceURL)+48)
	encoded = append(encoded, `{"access_token":"`...)
	encoded = append(encoded, accessToken...)
	encoded = append(encoded, `","instance_url":"`...)
	encoded = append(encoded, instanceURL...)
	return append(encoded, `"}`...), true
}

// The validators accept exactly what the encoders write: the members are cut
// out on the fixed separators and written again, and the bytes must agree.
func validDiscoveryMicrosoftCollectorCredential(value []byte) bool {
	if len(value) < 32 || len(value) > 3*8192+512 {
		return false
	}
	// A leading Resource Manager token is cut off and checked; the rest is
	// one of the two shapes without it.
	const armPrefix = `{"arm_token":"`
	if bytes.HasPrefix(value, []byte(armPrefix)) {
		armToken, rest, found := bytes.Cut(value[len(armPrefix):], []byte(`",`))
		if !found || !validDiscoverySaaSAccessToken(armToken) || bytes.HasPrefix(rest, []byte(`"arm_token"`)) {
			return false
		}
		remainder := append([]byte{'{'}, rest...)
		defer clear(remainder)
		return validDiscoveryMicrosoftCollectorCredential(remainder)
	}
	const graphPrefix, suffix = `{"graph_token":"`, `"}`
	if bytes.HasPrefix(value, []byte(graphPrefix)) && bytes.HasSuffix(value, []byte(suffix)) {
		encoded, ok := encodeDiscoveryMicrosoftCollectorCredential(value[len(graphPrefix):len(value)-len(suffix)], nil, "")
		defer clear(encoded)
		return ok && bytes.Equal(encoded, value)
	}
	const dataversePrefix, urlSeparator, graphSeparator = `{"dataverse_token":"`, `","dataverse_url":"`, `","graph_token":"`
	if !bytes.HasPrefix(value, []byte(dataversePrefix)) || !bytes.HasSuffix(value, []byte(suffix)) {
		return false
	}
	dataverseToken, rest, found := bytes.Cut(value[len(dataversePrefix):len(value)-len(suffix)], []byte(urlSeparator))
	if !found {
		return false
	}
	dataverseURL, graphToken, found := bytes.Cut(rest, []byte(graphSeparator))
	if !found {
		return false
	}
	encoded, ok := encodeDiscoveryMicrosoftCollectorCredential(graphToken, dataverseToken, string(dataverseURL))
	defer clear(encoded)
	return ok && bytes.Equal(encoded, value)
}

func validDiscoverySalesforceCollectorCredential(value []byte) bool {
	const prefix, separator, suffix = `{"access_token":"`, `","instance_url":"`, `"}`
	if len(value) < 32 || len(value) > 8192+512 || !bytes.HasPrefix(value, []byte(prefix)) || !bytes.HasSuffix(value, []byte(suffix)) || len(value) < len(prefix)+len(separator)+len(suffix) {
		return false
	}
	accessToken, instanceURL, found := bytes.Cut(value[len(prefix):len(value)-len(suffix)], []byte(separator))
	if !found {
		return false
	}
	encoded, ok := encodeDiscoverySalesforceCollectorCredential(accessToken, string(instanceURL))
	defer clear(encoded)
	return ok && bytes.Equal(encoded, value)
}

// discoverySalesforceIdentityOrganization reads the organization id out of a
// token response's identity URL, https://<host>/id/<organization>/<user>.
func discoverySalesforceIdentityOrganization(identity string) (string, bool) {
	if identity == "" {
		return "", true
	}
	rest, found := strings.CutPrefix(identity, "https://")
	if !found || len(identity) > 512 {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 4 || parts[1] != "id" || !discoverySalesforceIdentityHostPattern.MatchString(parts[0]) || !discoverySalesforceIdentityOrganizationPattern.MatchString(parts[2]) || !discoverySalesforceIdentityUserPattern.MatchString(parts[3]) {
		return "", false
	}
	return parts[2], true
}

var (
	discoverySalesforceIdentityHostPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}\.salesforce\.com$`)
	discoverySalesforceIdentityOrganizationPattern = regexp.MustCompile(`^00D[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?$`)
	discoverySalesforceIdentityUserPattern         = regexp.MustCompile(`^005[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?$`)
)
