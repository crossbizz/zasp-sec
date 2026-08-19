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
func (*stytchSessionDriver) ListSSOConnections(context.Context, string) ([]platformidentity.DriverSSOConnection, error) {
	return nil, platformidentity.ErrProvider
}
func (*stytchSessionDriver) CreateSSOConnection(context.Context, string, platformidentity.DriverSSOConfig) (platformidentity.DriverSSOConnection, error) {
	return platformidentity.DriverSSOConnection{}, platformidentity.ErrProvider
}
func (*stytchSessionDriver) DeleteSSOConnection(context.Context, string, string) (string, error) {
	return "", platformidentity.ErrProvider
}
func (*stytchSessionDriver) TestSSOConnection(context.Context, string, string) error {
	return platformidentity.ErrProvider
}
func (*stytchSessionDriver) ListSCIMConnections(context.Context, string) ([]platformidentity.DriverSCIMConnection, error) {
	return nil, platformidentity.ErrProvider
}
func (*stytchSessionDriver) CreateSCIMConnection(context.Context, string, platformidentity.DriverSCIMConfig) (platformidentity.DriverSCIMCredential, error) {
	return platformidentity.DriverSCIMCredential{}, platformidentity.ErrProvider
}
func (*stytchSessionDriver) DeleteSCIMConnection(context.Context, string, string) (string, error) {
	return "", platformidentity.ErrProvider
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
