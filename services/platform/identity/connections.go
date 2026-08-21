package identity

import (
	"context"
	"net/url"
	"strings"
)

const maximumConnectionTokenBytes = 4096

type SSOConfig struct {
	DisplayName      string
	Protocol         string
	IdentityProvider string
}

func (config SSOConfig) valid() bool {
	return validName(config.DisplayName) && validSSOProtocol(config.Protocol) && validSSOProvider(config.IdentityProvider)
}

type SCIMConfig struct {
	DisplayName      string
	IdentityProvider string
}

func (config SCIMConfig) valid() bool {
	return validName(config.DisplayName) && validSCIMProvider(config.IdentityProvider)
}

type SSOConnection struct {
	reference             string
	organizationReference string
	status                string
	displayName           string
	protocol              string
	identityProvider      string
}

func (connection SSOConnection) valid() bool {
	return validSSOReference(connection.reference) && validReference(connection.organizationReference, "organization-") &&
		validConnectionStatus(connection.status) && validName(connection.displayName) && validSSOProtocol(connection.protocol) &&
		validSSOProvider(connection.identityProvider)
}

func (connection SSOConnection) Reference() string        { return connection.reference }
func (connection SSOConnection) Status() string           { return connection.status }
func (connection SSOConnection) DisplayName() string      { return connection.displayName }
func (connection SSOConnection) Protocol() string         { return connection.protocol }
func (connection SSOConnection) IdentityProvider() string { return connection.identityProvider }

type SCIMConnection struct {
	reference             string
	organizationReference string
	status                string
	displayName           string
	identityProvider      string
	baseURL               string
}

func (connection SCIMConnection) valid() bool {
	return validSCIMReference(connection.reference) && validReference(connection.organizationReference, "organization-") &&
		validConnectionStatus(connection.status) && validName(connection.displayName) &&
		validSCIMProvider(connection.identityProvider) && validSCIMBaseURL(connection.baseURL, connection.identityProvider)
}

func (connection SCIMConnection) Reference() string        { return connection.reference }
func (connection SCIMConnection) Status() string           { return connection.status }
func (connection SCIMConnection) DisplayName() string      { return connection.displayName }
func (connection SCIMConnection) IdentityProvider() string { return connection.identityProvider }
func (connection SCIMConnection) BaseURL() string          { return connection.baseURL }

type SCIMCredential struct {
	Connection  SCIMConnection
	bearerToken string
}

func (credential SCIMCredential) BearerToken() string { return credential.bearerToken }

type ConnectionService struct {
	adapter *Adapter
}

func NewConnectionService(adapter *Adapter) (*ConnectionService, error) {
	if adapter == nil || nilInterface(adapter.driver) {
		return nil, ErrConfiguration
	}
	return &ConnectionService{adapter: adapter}, nil
}

func (service *ConnectionService) ListSSO(ctx context.Context, organization string) ([]SSOConnection, error) {
	if service == nil || service.adapter == nil {
		return nil, ErrConfiguration
	}
	raw, err := service.adapter.ListSSOConnections(ctx, organization)
	if err != nil {
		return nil, err
	}
	result := make([]SSOConnection, len(raw))
	for index, value := range raw {
		result[index], err = newSSOConnection(value, organization)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (service *ConnectionService) CreateSSO(ctx context.Context, organization string, config SSOConfig) (SSOConnection, error) {
	if service == nil || service.adapter == nil || !validContext(ctx) || !validReference(organization, "organization-") || !config.valid() {
		return SSOConnection{}, ErrInvalidRecord
	}
	raw, err := createSSODriver(service.adapter.driver, ctx, organization, DriverSSOConfig(config))
	if err != nil {
		return SSOConnection{}, ErrProvider
	}
	return newSSOConnection(raw, organization)
}

func (service *ConnectionService) DeleteSSO(ctx context.Context, organization, reference string) error {
	if service == nil || service.adapter == nil || !validContext(ctx) || !validReference(organization, "organization-") || !validSSOReference(reference) {
		return ErrInvalidRecord
	}
	deleted, err := deleteSSODriver(service.adapter.driver, ctx, organization, reference)
	if err != nil {
		return ErrProvider
	}
	if deleted != reference {
		return ErrInvalidRecord
	}
	return nil
}

func (service *ConnectionService) TestSSO(ctx context.Context, organization, reference string) error {
	if service == nil || service.adapter == nil || !validContext(ctx) || !validReference(organization, "organization-") || !validSSOReference(reference) {
		return ErrInvalidRecord
	}
	if err := testSSODriver(service.adapter.driver, ctx, organization, reference); err != nil {
		return ErrProvider
	}
	return nil
}

func (service *ConnectionService) ListSCIM(ctx context.Context, organization string) ([]SCIMConnection, error) {
	if service == nil || service.adapter == nil {
		return nil, ErrConfiguration
	}
	raw, err := service.adapter.ListSCIMConnections(ctx, organization)
	if err != nil {
		return nil, err
	}
	result := make([]SCIMConnection, len(raw))
	for index, value := range raw {
		result[index], err = newSCIMConnection(value, organization)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (service *ConnectionService) CreateSCIM(ctx context.Context, organization string, config SCIMConfig) (SCIMCredential, error) {
	if service == nil || service.adapter == nil || !validContext(ctx) || !validReference(organization, "organization-") || !config.valid() {
		return SCIMCredential{}, ErrInvalidRecord
	}
	raw, err := createSCIMDriver(service.adapter.driver, ctx, organization, DriverSCIMConfig(config))
	if err != nil {
		return SCIMCredential{}, ErrProvider
	}
	connection, err := newSCIMConnection(raw.Connection, organization)
	if err != nil || !validBearerToken(raw.BearerToken) {
		return SCIMCredential{}, ErrInvalidRecord
	}
	return SCIMCredential{Connection: connection, bearerToken: raw.BearerToken}, nil
}

func (service *ConnectionService) DeleteSCIM(ctx context.Context, organization, reference string) error {
	if service == nil || service.adapter == nil || !validContext(ctx) || !validReference(organization, "organization-") || !validSCIMReference(reference) {
		return ErrInvalidRecord
	}
	deleted, err := deleteSCIMDriver(service.adapter.driver, ctx, organization, reference)
	if err != nil {
		return ErrProvider
	}
	if deleted != reference {
		return ErrInvalidRecord
	}
	return nil
}

func newSSOConnection(value DriverSSOConnection, organization string) (SSOConnection, error) {
	connection := SSOConnection{reference: value.Reference, organizationReference: value.OrganizationReference, status: value.Status,
		displayName: value.DisplayName, protocol: value.Protocol, identityProvider: value.IdentityProvider}
	if !connection.valid() || connection.organizationReference != organization {
		return SSOConnection{}, ErrInvalidRecord
	}
	return connection, nil
}

func newSCIMConnection(value DriverSCIMConnection, organization string) (SCIMConnection, error) {
	connection := SCIMConnection{reference: value.Reference, organizationReference: value.OrganizationReference, status: value.Status,
		displayName: value.DisplayName, identityProvider: value.IdentityProvider, baseURL: value.BaseURL}
	if !connection.valid() || connection.organizationReference != organization {
		return SCIMConnection{}, ErrInvalidRecord
	}
	return connection, nil
}

func validSSOReference(value string) bool {
	return validReference(value, "saml-connection-") || validReference(value, "oidc-connection-") || validReference(value, "external-connection-")
}

func validSCIMReference(value string) bool { return validReference(value, "scim-connection-") }
func validSSOProtocol(value string) bool   { return value == "saml" || value == "oidc" }

func validSSOProvider(value string) bool {
	switch value {
	case "classlink", "cyberark", "duo", "generic", "google-workspace", "jumpcloud", "keycloak", "miniorange",
		"microsoft-entra", "okta", "onelogin", "pingfederate", "rippling", "salesforce", "shibboleth":
		return true
	default:
		return false
	}
}

func validSCIMProvider(value string) bool {
	switch value {
	case "generic", "okta", "microsoft-entra", "cyberark", "jumpcloud", "onelogin", "pingfederate", "rippling":
		return true
	default:
		return false
	}
}

func validSCIMBaseURL(value, provider string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && parsed.String() == value &&
		(parsed.RawQuery == "" || provider == "microsoft-entra" && parsed.RawQuery == "aadOptscim062020")
}

func validBearerToken(value string) bool {
	if len(value) <= len("scim_bearer_token_") || len(value) > maximumConnectionTokenBytes || !strings.HasPrefix(value, "scim_bearer_token_") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func createSSODriver(driver StytchDriver, ctx context.Context, organization string, config DriverSSOConfig) (result DriverSSOConnection, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.CreateSSOConnection(ctx, organization, config)
}

func deleteSSODriver(driver StytchDriver, ctx context.Context, organization, reference string) (result string, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.DeleteSSOConnection(ctx, organization, reference)
}

func testSSODriver(driver StytchDriver, ctx context.Context, organization, reference string) (resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.TestSSOConnection(ctx, organization, reference)
}

func createSCIMDriver(driver StytchDriver, ctx context.Context, organization string, config DriverSCIMConfig) (result DriverSCIMCredential, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.CreateSCIMConnection(ctx, organization, config)
}

func deleteSCIMDriver(driver StytchDriver, ctx context.Context, organization, reference string) (result string, resultErr error) {
	defer providerRecovery(&resultErr)
	return driver.DeleteSCIMConnection(ctx, organization, reference)
}
