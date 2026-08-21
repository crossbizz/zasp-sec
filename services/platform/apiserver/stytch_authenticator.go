package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

const maximumStytchResponseBytes = 64 * 1024

type StytchOAuthAuthenticator struct {
	baseURL *url.URL
	client  *http.Client
	project string
	secret  string
	adapter *platformidentity.Adapter
}

func NewStytchOAuthAuthenticator(baseURL, project, secret string, timeout time.Duration, now func() time.Time) (*StytchOAuthAuthenticator, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !validProviderBaseURL(parsed) || !boundedSecret(project) || !boundedSecret(secret) || timeout <= 0 || timeout > 30*time.Second || now == nil {
		return nil, ErrRepositoryConfiguration
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("identity redirect rejected") }}
	driver := &stytchSessionDriver{baseURL: parsed, client: client, project: project, secret: secret}
	adapter, err := platformidentity.NewAdapter(driver, now)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &StytchOAuthAuthenticator{baseURL: parsed, client: client, project: project, secret: secret, adapter: adapter}, nil
}

func (authenticator *StytchOAuthAuthenticator) Authenticate(ctx context.Context, token string) (platformidentity.ExternalPrincipal, error) {
	if authenticator == nil || authenticator.client == nil || authenticator.adapter == nil || ctx == nil || ctx.Err() != nil || token == "" || len(token) > 4096 || strings.TrimSpace(token) != token {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	requestBody, err := json.Marshal(map[string]any{"oauth_token": token, "session_duration_minutes": 60})
	if err != nil {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	request, err := authenticator.request(ctx, "/v1/b2b/oauth/authenticate", requestBody)
	if err != nil {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	response, err := authenticator.client.Do(request)
	if err != nil {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	defer response.Body.Close()
	var value struct {
		StatusCode int    `json:"status_code"`
		SessionJWT string `json:"session_jwt"`
	}
	if response.StatusCode != http.StatusOK || !jsonResponse(response) || decodeBoundedJSON(response.Body, &value) != nil || value.StatusCode != http.StatusOK {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	principal, err := authenticator.adapter.Authenticate(ctx, value.SessionJWT)
	if err != nil {
		return platformidentity.ExternalPrincipal{}, ErrRepositoryAuthentication
	}
	return principal, nil
}

func (authenticator *StytchOAuthAuthenticator) Ready(ctx context.Context) error {
	if authenticator == nil || authenticator.client == nil || authenticator.adapter == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (authenticator *StytchOAuthAuthenticator) connectionService() (*platformidentity.ConnectionService, error) {
	if authenticator == nil || authenticator.adapter == nil {
		return nil, ErrRepositoryUnavailable
	}
	service, err := platformidentity.NewConnectionService(authenticator.adapter)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return service, nil
}

func (authenticator *StytchOAuthAuthenticator) ListSSO(ctx context.Context, organization string) ([]platformidentity.SSOConnection, error) {
	service, err := authenticator.connectionService()
	if err != nil {
		return nil, err
	}
	return service.ListSSO(ctx, organization)
}

func (authenticator *StytchOAuthAuthenticator) CreateSSO(ctx context.Context, organization string, config platformidentity.SSOConfig) (platformidentity.SSOConnection, error) {
	service, err := authenticator.connectionService()
	if err != nil {
		return platformidentity.SSOConnection{}, err
	}
	return service.CreateSSO(ctx, organization, config)
}

func (authenticator *StytchOAuthAuthenticator) DeleteSSO(ctx context.Context, organization, reference string) error {
	service, err := authenticator.connectionService()
	if err != nil {
		return err
	}
	return service.DeleteSSO(ctx, organization, reference)
}

func (authenticator *StytchOAuthAuthenticator) TestSSO(ctx context.Context, organization, reference string) error {
	service, err := authenticator.connectionService()
	if err != nil {
		return err
	}
	return service.TestSSO(ctx, organization, reference)
}

func (authenticator *StytchOAuthAuthenticator) ListSCIM(ctx context.Context, organization string) ([]platformidentity.SCIMConnection, error) {
	service, err := authenticator.connectionService()
	if err != nil {
		return nil, err
	}
	return service.ListSCIM(ctx, organization)
}

func (authenticator *StytchOAuthAuthenticator) CreateSCIM(ctx context.Context, organization string, config platformidentity.SCIMConfig) (platformidentity.SCIMCredential, error) {
	service, err := authenticator.connectionService()
	if err != nil {
		return platformidentity.SCIMCredential{}, err
	}
	return service.CreateSCIM(ctx, organization, config)
}

func (authenticator *StytchOAuthAuthenticator) DeleteSCIM(ctx context.Context, organization, reference string) error {
	service, err := authenticator.connectionService()
	if err != nil {
		return err
	}
	return service.DeleteSCIM(ctx, organization, reference)
}

func (authenticator *StytchOAuthAuthenticator) request(ctx context.Context, path string, body []byte) (*http.Request, error) {
	target := *authenticator.baseURL
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(authenticator.project, authenticator.secret)
	return request, nil
}

type stytchSessionDriver struct {
	baseURL *url.URL
	client  *http.Client
	project string
	secret  string
}

func (driver *stytchSessionDriver) AuthenticateJWT(ctx context.Context, jwt string) (platformidentity.DriverSession, error) {
	if driver == nil || driver.client == nil || ctx == nil || ctx.Err() != nil {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	payload, err := json.Marshal(map[string]string{"session_jwt": jwt})
	if err != nil {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	target := *driver.baseURL
	target.Path = "/v1/b2b/sessions/authenticate"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(driver.project, driver.secret)
	response, err := driver.client.Do(request)
	if err != nil {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	defer response.Body.Close()
	var value struct {
		StatusCode    int `json:"status_code"`
		MemberSession struct {
			SessionReference      string `json:"member_session_id"`
			MemberReference       string `json:"member_id"`
			OrganizationReference string `json:"organization_id"`
			AuthenticatedAt       string `json:"started_at"`
			ExpiresAt             string `json:"expires_at"`
		} `json:"member_session"`
	}
	if response.StatusCode != http.StatusOK || !jsonResponse(response) || decodeBoundedJSON(response.Body, &value) != nil || value.StatusCode != http.StatusOK {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	authenticated, authenticatedErr := time.Parse(time.RFC3339, value.MemberSession.AuthenticatedAt)
	expires, expiresErr := time.Parse(time.RFC3339, value.MemberSession.ExpiresAt)
	if authenticatedErr != nil || expiresErr != nil {
		return platformidentity.DriverSession{}, platformidentity.ErrProvider
	}
	return platformidentity.DriverSession{
		MemberReference: value.MemberSession.MemberReference, OrganizationReference: value.MemberSession.OrganizationReference,
		SessionReference: value.MemberSession.SessionReference, AuthenticatedAt: authenticated, ExpiresAt: expires, Active: true,
	}, nil
}

func (*stytchSessionDriver) RevalidateSession(context.Context, string) (platformidentity.DriverSession, error) {
	return platformidentity.DriverSession{}, platformidentity.ErrProvider
}
func (*stytchSessionDriver) GetOrganization(context.Context, string) (platformidentity.DriverOrganization, error) {
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}
func (*stytchSessionDriver) EnsureOrganization(context.Context, string, string) (platformidentity.DriverOrganization, error) {
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}
func (*stytchSessionDriver) InviteAdmin(context.Context, string, string) (platformidentity.DriverInvitation, error) {
	return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
}
func (driver *stytchSessionDriver) ListSSOConnections(ctx context.Context, organization string) ([]platformidentity.DriverSSOConnection, error) {
	if !validExactStytchReference(organization, "organization-") {
		return nil, platformidentity.ErrProvider
	}
	var response struct {
		StatusCode      int                   `json:"status_code"`
		SAMLConnections []stytchSSOConnection `json:"saml_connections"`
		OIDCConnections []stytchSSOConnection `json:"oidc_connections"`
	}
	if err := driver.doJSON(ctx, http.MethodGet, "/v1/b2b/sso/"+url.PathEscape(organization), nil, &response); err != nil || response.StatusCode != http.StatusOK {
		return nil, platformidentity.ErrProvider
	}
	result := make([]platformidentity.DriverSSOConnection, 0, len(response.SAMLConnections)+len(response.OIDCConnections))
	for _, connection := range response.SAMLConnections {
		value, err := connection.driverConnection(organization, "saml")
		if err != nil {
			return nil, platformidentity.ErrProvider
		}
		result = append(result, value)
	}
	for _, connection := range response.OIDCConnections {
		value, err := connection.driverConnection(organization, "oidc")
		if err != nil {
			return nil, platformidentity.ErrProvider
		}
		result = append(result, value)
	}
	return result, nil
}

func (driver *stytchSessionDriver) CreateSSOConnection(ctx context.Context, organization string, config platformidentity.DriverSSOConfig) (platformidentity.DriverSSOConnection, error) {
	if !validExactStytchReference(organization, "organization-") || !validStytchName(config.DisplayName) ||
		!validStytchSSOProvider(config.IdentityProvider) || config.Protocol != "saml" && config.Protocol != "oidc" {
		return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
	}
	var response struct {
		StatusCode int                 `json:"status_code"`
		Connection stytchSSOConnection `json:"connection"`
	}
	path := "/v1/b2b/sso/" + config.Protocol + "/" + url.PathEscape(organization)
	body := map[string]string{"display_name": config.DisplayName, "identity_provider": config.IdentityProvider}
	if err := driver.doJSON(ctx, http.MethodPost, path, body, &response); err != nil || response.StatusCode != http.StatusOK {
		return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
	}
	value, err := response.Connection.driverConnection(organization, config.Protocol)
	if err != nil || value.DisplayName != config.DisplayName || value.IdentityProvider != config.IdentityProvider {
		return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
	}
	return value, nil
}

func (driver *stytchSessionDriver) DeleteSSOConnection(ctx context.Context, organization, reference string) (string, error) {
	if !validExactStytchReference(organization, "organization-") || !validStytchSSOReference(reference) {
		return "", platformidentity.ErrProvider
	}
	var response struct {
		StatusCode   int    `json:"status_code"`
		ConnectionID string `json:"connection_id"`
	}
	path := "/v1/b2b/sso/" + url.PathEscape(organization) + "/connections/" + url.PathEscape(reference)
	if err := driver.doJSON(ctx, http.MethodDelete, path, map[string]any{}, &response); err != nil || response.StatusCode != http.StatusOK || response.ConnectionID != reference {
		return "", platformidentity.ErrProvider
	}
	return response.ConnectionID, nil
}

func (driver *stytchSessionDriver) TestSSOConnection(ctx context.Context, organization, reference string) error {
	if !validStytchSSOReference(reference) {
		return platformidentity.ErrProvider
	}
	connections, err := driver.ListSSOConnections(ctx, organization)
	if err != nil {
		return platformidentity.ErrProvider
	}
	for _, connection := range connections {
		if connection.Reference == reference && connection.OrganizationReference == organization && connection.Status == "active" {
			return nil
		}
	}
	return platformidentity.ErrProvider
}

func (driver *stytchSessionDriver) ListSCIMConnections(ctx context.Context, organization string) ([]platformidentity.DriverSCIMConnection, error) {
	if !validExactStytchReference(organization, "organization-") {
		return nil, platformidentity.ErrProvider
	}
	var response struct {
		StatusCode int                   `json:"status_code"`
		Connection *stytchSCIMConnection `json:"connection"`
	}
	path := "/v1/b2b/scim/" + url.PathEscape(organization) + "/connection"
	if err := driver.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil || response.StatusCode != http.StatusOK {
		return nil, platformidentity.ErrProvider
	}
	if response.Connection == nil {
		return []platformidentity.DriverSCIMConnection{}, nil
	}
	value, err := response.Connection.driverConnection(organization)
	if err != nil {
		return nil, platformidentity.ErrProvider
	}
	return []platformidentity.DriverSCIMConnection{value}, nil
}

func (driver *stytchSessionDriver) CreateSCIMConnection(ctx context.Context, organization string, config platformidentity.DriverSCIMConfig) (platformidentity.DriverSCIMCredential, error) {
	if !validExactStytchReference(organization, "organization-") || !validStytchName(config.DisplayName) || !validStytchSCIMProvider(config.IdentityProvider) {
		return platformidentity.DriverSCIMCredential{}, platformidentity.ErrProvider
	}
	var response struct {
		StatusCode int                   `json:"status_code"`
		Connection *stytchSCIMConnection `json:"connection"`
	}
	path := "/v1/b2b/scim/" + url.PathEscape(organization) + "/connection"
	body := map[string]string{"display_name": config.DisplayName, "identity_provider": config.IdentityProvider}
	if err := driver.doJSON(ctx, http.MethodPost, path, body, &response); err != nil || response.StatusCode != http.StatusOK || response.Connection == nil {
		return platformidentity.DriverSCIMCredential{}, platformidentity.ErrProvider
	}
	value, err := response.Connection.driverConnection(organization)
	if err != nil || value.DisplayName != config.DisplayName || value.IdentityProvider != config.IdentityProvider || !validStytchBearerToken(response.Connection.BearerToken) {
		return platformidentity.DriverSCIMCredential{}, platformidentity.ErrProvider
	}
	return platformidentity.DriverSCIMCredential{Connection: value, BearerToken: response.Connection.BearerToken}, nil
}

func (driver *stytchSessionDriver) DeleteSCIMConnection(ctx context.Context, organization, reference string) (string, error) {
	if !validExactStytchReference(organization, "organization-") || !validExactStytchReference(reference, "scim-connection-") {
		return "", platformidentity.ErrProvider
	}
	var response struct {
		StatusCode   int    `json:"status_code"`
		ConnectionID string `json:"connection_id"`
	}
	path := "/v1/b2b/scim/" + url.PathEscape(organization) + "/connection/" + url.PathEscape(reference)
	if err := driver.doJSON(ctx, http.MethodDelete, path, map[string]any{}, &response); err != nil || response.StatusCode != http.StatusOK || response.ConnectionID != reference {
		return "", platformidentity.ErrProvider
	}
	return response.ConnectionID, nil
}

type stytchSSOConnection struct {
	OrganizationID   string `json:"organization_id"`
	ConnectionID     string `json:"connection_id"`
	Status           string `json:"status"`
	DisplayName      string `json:"display_name"`
	IdentityProvider string `json:"identity_provider"`
}

func (connection stytchSSOConnection) driverConnection(organization, protocol string) (platformidentity.DriverSSOConnection, error) {
	prefix := protocol + "-connection-"
	if connection.OrganizationID != organization || !validExactStytchReference(connection.ConnectionID, prefix) ||
		!validStytchConnectionStatus(connection.Status) || !validStytchName(connection.DisplayName) || !validStytchSSOProvider(connection.IdentityProvider) {
		return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
	}
	return platformidentity.DriverSSOConnection{
		Reference: connection.ConnectionID, OrganizationReference: connection.OrganizationID, Status: connection.Status,
		DisplayName: connection.DisplayName, Protocol: protocol, IdentityProvider: connection.IdentityProvider,
	}, nil
}

type stytchSCIMConnection struct {
	OrganizationID   string `json:"organization_id"`
	ConnectionID     string `json:"connection_id"`
	Status           string `json:"status"`
	DisplayName      string `json:"display_name"`
	IdentityProvider string `json:"identity_provider"`
	BaseURL          string `json:"base_url"`
	BearerToken      string `json:"bearer_token"`
}

func (connection stytchSCIMConnection) driverConnection(organization string) (platformidentity.DriverSCIMConnection, error) {
	parsed, err := url.Parse(connection.BaseURL)
	if connection.OrganizationID != organization || !validExactStytchReference(connection.ConnectionID, "scim-connection-") ||
		!validStytchConnectionStatus(connection.Status) || !validStytchName(connection.DisplayName) || !validStytchSCIMProvider(connection.IdentityProvider) ||
		err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.String() != connection.BaseURL ||
		parsed.RawQuery != "" && (connection.IdentityProvider != "microsoft-entra" || parsed.RawQuery != "aadOptscim062020") {
		return platformidentity.DriverSCIMConnection{}, platformidentity.ErrProvider
	}
	return platformidentity.DriverSCIMConnection{
		Reference: connection.ConnectionID, OrganizationReference: connection.OrganizationID, Status: connection.Status,
		DisplayName: connection.DisplayName, IdentityProvider: connection.IdentityProvider, BaseURL: connection.BaseURL,
	}, nil
}

func (driver *stytchSessionDriver) doJSON(ctx context.Context, method, path string, body any, output any) error {
	if driver == nil || driver.baseURL == nil || driver.client == nil || ctx == nil || ctx.Err() != nil ||
		!strings.HasPrefix(path, "/v1/b2b/") || output == nil {
		return platformidentity.ErrProvider
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return platformidentity.ErrProvider
		}
		reader = bytes.NewReader(encoded)
	}
	target := *driver.baseURL
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return platformidentity.ErrProvider
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.SetBasicAuth(driver.project, driver.secret)
	response, err := driver.client.Do(request)
	if err != nil {
		return platformidentity.ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !jsonResponse(response) || decodeBoundedJSON(response.Body, output) != nil {
		return platformidentity.ErrProvider
	}
	return nil
}

func validExactStytchReference(value, prefix string) bool {
	if len(value) <= len(prefix) || len(value) > 128 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validStytchSSOReference(value string) bool {
	return validExactStytchReference(value, "saml-connection-") || validExactStytchReference(value, "oidc-connection-")
}

func validStytchName(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validStytchConnectionStatus(value string) bool {
	return value == "active" || value == "pending" || value == "disabled"
}

func validStytchSSOProvider(value string) bool {
	switch value {
	case "classlink", "cyberark", "duo", "generic", "google-workspace", "jumpcloud", "keycloak", "miniorange",
		"microsoft-entra", "okta", "onelogin", "pingfederate", "rippling", "salesforce", "shibboleth":
		return true
	default:
		return false
	}
}

func validStytchSCIMProvider(value string) bool {
	switch value {
	case "generic", "okta", "microsoft-entra", "cyberark", "jumpcloud", "onelogin", "pingfederate", "rippling":
		return true
	default:
		return false
	}
}

func validStytchBearerToken(value string) bool {
	if len(value) <= len("scim_bearer_token_") || len(value) > 4096 || !strings.HasPrefix(value, "scim_bearer_token_") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validProviderBaseURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" || value.Path != "" {
		return false
	}
	loopback := net.ParseIP(value.Hostname()) != nil && net.ParseIP(value.Hostname()).IsLoopback()
	return value.Scheme == "https" || value.Scheme == "http" && loopback
}

func jsonResponse(response *http.Response) bool {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func decodeBoundedJSON(body io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(body, maximumStytchResponseBytes+1))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrRepositoryAuthentication
	}
	return nil
}

func boundedSecret(value string) bool {
	return len(value) >= 8 && len(value) <= 4096 && strings.TrimSpace(value) == value
}
