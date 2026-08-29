package nango

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrConnection = errors.New("Nango connection rejected")
var ErrConnectionNotFound = errors.New("Nango connection outcome not found")

var productIDPattern = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var connectSessionTokenPattern = regexp.MustCompile(`^nango_connect_session_[0-9a-f]{64}$`)
var oauthValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,512}$`)

type ConnectionBinding struct {
	OrganizationID, WorkspaceID, EnvironmentID, IntegrationID, AttemptID string
}

type RevocationBinding struct {
	OrganizationID, WorkspaceID, EnvironmentID, IntegrationID string
}

type OAuthStartRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, Provider, AuthorizationHost         string
	AuthorizationPath, CallbackURL                    string
	Binding                                           ConnectionBinding
}

type OAuthAuthorization struct {
	URL, State string
	ExpiresAt  time.Time
}

type OAuthCompleteRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, Provider, State, Code               string
	Binding                                           ConnectionBinding
}

type ConnectionRevocationRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, Provider, ConnectionReference       string
	Binding                                           RevocationBinding
}

type ReadinessRequest struct {
	NangoBaseURL, ServiceSecretReference, Environment string
	ConnectorKey, Provider                            string
}

type Connection struct {
	Reference, ProviderSubject, ConnectorKey string
}

type ProductionConnectionClient struct {
	resolver ServiceSecretResolver
	client   *http.Client
	now      func() time.Time
}

func NewProductionConnectionClient(resolver ServiceSecretResolver, timeout time.Duration) (*ProductionConnectionClient, error) {
	proxy, err := NewProductionProxyClient(resolver, timeout)
	if err != nil {
		return nil, err
	}
	return newProductionConnectionClientWithHTTP(resolver, proxy.client, func() time.Time { return time.Now().UTC() })
}

func newProductionConnectionClientWithHTTP(resolver ServiceSecretResolver, client *http.Client, now func() time.Time) (*ProductionConnectionClient, error) {
	if resolver == nil || client == nil || client.Transport == nil || client.Timeout < 100*time.Millisecond || client.Timeout > 10*time.Second || client.CheckRedirect == nil || now == nil || now().IsZero() {
		return nil, ErrInvalid
	}
	return &ProductionConnectionClient{resolver: resolver, client: client, now: now}, nil
}

func (client *ProductionConnectionClient) StartOAuth(ctx context.Context, request OAuthStartRequest) (OAuthAuthorization, error) {
	if client == nil || client.resolver == nil || client.client == nil || ctx == nil || ctx.Err() != nil || !validOAuthStartRequest(request) {
		return OAuthAuthorization{}, ErrInvalid
	}
	secret, err := client.resolver.Resolve(ctx, request.ServiceSecretReference)
	if err != nil || !validServiceSecret(secret) {
		clear(secret)
		return OAuthAuthorization{}, ErrConnection
	}
	body, err := json.Marshal(map[string]any{
		"end_user":             map[string]string{"id": nangoEndUserID(request.Binding)},
		"organization":         map[string]string{"id": nangoOrganizationID(request.Binding)},
		"allowed_integrations": []string{request.ConnectorKey},
	})
	if err != nil {
		clear(secret)
		return OAuthAuthorization{}, ErrConnection
	}
	query := url.Values{"env": []string{request.Environment}}
	var response struct {
		Data struct {
			Token       string `json:"token"`
			ConnectLink string `json:"connect_link"`
			ExpiresAt   string `json:"expires_at"`
		} `json:"data"`
	}
	err = client.doJSON(ctx, http.MethodPost, request.NangoBaseURL+"/api/v1/connect/sessions?"+query.Encode(), secret, body, http.StatusCreated, &response)
	clear(secret)
	clear(body)
	if err != nil || !connectSessionTokenPattern.MatchString(response.Data.Token) {
		return OAuthAuthorization{}, ErrConnection
	}
	providerExpiry, err := time.Parse(time.RFC3339Nano, response.Data.ExpiresAt)
	connectLink, linkErr := url.Parse(response.Data.ConnectLink)
	base, baseErr := url.Parse(request.NangoBaseURL)
	now := client.now().UTC()
	if err != nil || linkErr != nil || baseErr != nil || !providerExpiry.After(now) || providerExpiry.After(now.Add(31*time.Minute)) ||
		connectLink.Scheme != base.Scheme || connectLink.Host != base.Host || connectLink.Path != "/connect" || connectLink.Fragment != "" ||
		len(connectLink.Query()["session_token"]) != 1 || connectLink.Query().Get("session_token") != response.Data.Token {
		return OAuthAuthorization{}, ErrConnection
	}
	connectQuery := url.Values{"connect_session_token": []string{response.Data.Token}}
	connectURL := request.NangoBaseURL + "/oauth/connect/" + url.PathEscape(request.ConnectorKey) + "?" + connectQuery.Encode()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, connectURL, nil)
	if err != nil {
		return OAuthAuthorization{}, ErrConnection
	}
	httpResponse, err := client.client.Do(httpRequest)
	if err != nil || httpResponse == nil {
		return OAuthAuthorization{}, ErrConnection
	}
	defer httpResponse.Body.Close()
	redirectBody, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, 1))
	target, targetErr := url.Parse(httpResponse.Header.Get("Location"))
	if readErr != nil || len(redirectBody) != 0 || httpResponse.StatusCode != http.StatusFound || targetErr != nil || target.Scheme != "https" || strings.ToLower(target.Hostname()) != request.AuthorizationHost || target.Port() != "" || target.User != nil || target.Fragment != "" || target.Path != request.AuthorizationPath || len(target.Query()["state"]) != 1 || !oauthValuePattern.MatchString(target.Query().Get("state")) || len(target.Query()["redirect_uri"]) != 1 || target.Query().Get("redirect_uri") != request.CallbackURL {
		return OAuthAuthorization{}, ErrConnection
	}
	expiresAt := providerExpiry.UTC()
	if expiresAt.After(now.Add(10 * time.Minute)) {
		expiresAt = now.Add(10 * time.Minute)
	}
	return OAuthAuthorization{URL: target.String(), State: target.Query().Get("state"), ExpiresAt: expiresAt}, nil
}

func (client *ProductionConnectionClient) CompleteOAuth(ctx context.Context, request OAuthCompleteRequest) (Connection, error) {
	if client == nil || client.resolver == nil || client.client == nil || ctx == nil || ctx.Err() != nil || !validOAuthCompleteRequest(request) {
		return Connection{}, ErrInvalid
	}
	callbackQuery := url.Values{"code": []string{request.Code}, "state": []string{request.State}}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, request.NangoBaseURL+"/oauth/callback?"+callbackQuery.Encode(), nil)
	if err != nil {
		return Connection{}, ErrConnection
	}
	response, err := client.client.Do(httpRequest)
	if err != nil || response == nil {
		return Connection{}, ErrConnection
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	response.Body.Close()
	if mediaErr != nil || mediaType != "text/html" || readErr != nil || response.StatusCode != http.StatusOK || len(payload) < 1 || len(payload) > 64<<10 {
		clear(payload)
		return Connection{}, ErrConnection
	}
	clear(payload)
	return client.RecoverOAuth(ctx, request)
}

func (client *ProductionConnectionClient) RecoverOAuth(ctx context.Context, request OAuthCompleteRequest) (Connection, error) {
	if client == nil || client.resolver == nil || client.client == nil || ctx == nil || ctx.Err() != nil || !validOAuthRecoveryRequest(request) {
		return Connection{}, ErrInvalid
	}
	secret, err := client.resolver.Resolve(ctx, request.ServiceSecretReference)
	if err != nil || !validServiceSecret(secret) {
		clear(secret)
		return Connection{}, ErrConnection
	}
	query := url.Values{
		"endUserId":     []string{nangoEndUserID(request.Binding)},
		"env":           []string{request.Environment},
		"integrationId": []string{request.ConnectorKey},
		"limit":         []string{"2"},
		"page":          []string{"0"},
	}
	var result struct {
		Connections []nangoPublicConnection `json:"connections"`
	}
	err = client.doJSON(ctx, http.MethodGet, request.NangoBaseURL+"/connection?"+query.Encode(), secret, nil, http.StatusOK, &result)
	clear(secret)
	if err != nil {
		return Connection{}, ErrConnection
	}
	if len(result.Connections) == 0 {
		return Connection{}, ErrConnectionNotFound
	}
	if len(result.Connections) != 1 || !validNangoConnection(result.Connections[0], request, nangoOrganizationID(request.Binding), nangoEndUserID(request.Binding)) {
		return Connection{}, ErrConnection
	}
	value := result.Connections[0]
	return Connection{Reference: "ref:nango/connection/" + value.ConnectionID, ProviderSubject: value.EndUser.ID, ConnectorKey: value.ProviderConfigKey}, nil
}

func (client *ProductionConnectionClient) RevokeConnection(ctx context.Context, request ConnectionRevocationRequest) error {
	connection := connectionReferencePattern.FindStringSubmatch(request.ConnectionReference)
	if client == nil || client.resolver == nil || client.client == nil || ctx == nil || ctx.Err() != nil || len(connection) != 2 || !validNangoRevocationAuthority(request) {
		return ErrInvalid
	}
	secret, err := client.resolver.Resolve(ctx, request.ServiceSecretReference)
	if err != nil || !validServiceSecret(secret) {
		clear(secret)
		return ErrConnection
	}
	query := url.Values{
		"connectionId":          []string{connection[1]},
		"endUserOrganizationId": []string{nangoRevocationOrganizationID(request.Binding)},
		"env":                   []string{request.Environment},
		"integrationId":         []string{request.ConnectorKey},
		"limit":                 []string{"2"},
		"page":                  []string{"0"},
	}
	var result struct {
		Connections []nangoPublicConnection `json:"connections"`
	}
	err = client.doJSON(ctx, http.MethodGet, request.NangoBaseURL+"/connection?"+query.Encode(), secret, nil, http.StatusOK, &result)
	if err != nil || len(result.Connections) > 1 {
		clear(secret)
		return ErrConnection
	}
	if len(result.Connections) == 0 {
		clear(secret)
		return nil
	}
	if !validNangoRevocationConnection(result.Connections[0], request, connection[1]) {
		clear(secret)
		return ErrConnection
	}
	deleteQuery := url.Values{"provider_config_key": []string{request.ConnectorKey}}
	var deleted struct {
		Success bool `json:"success"`
	}
	err = client.doJSON(ctx, http.MethodDelete, request.NangoBaseURL+"/connection/"+url.PathEscape(connection[1])+"?"+deleteQuery.Encode(), secret, nil, http.StatusOK, &deleted)
	clear(secret)
	if err != nil || !deleted.Success {
		return ErrConnection
	}
	return nil
}

func (client *ProductionConnectionClient) CheckReadiness(ctx context.Context, readiness ReadinessRequest) error {
	if client == nil || client.client == nil || client.resolver == nil || ctx == nil || ctx.Err() != nil || !validBaseURL(readiness.NangoBaseURL) || !referencePattern.MatchString(readiness.ServiceSecretReference) || !environmentPattern.MatchString(readiness.Environment) || !keyPattern.MatchString(readiness.ConnectorKey) || readiness.Provider != readiness.ConnectorKey {
		return ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, readiness.NangoBaseURL+"/ready", nil)
	if err != nil {
		return ErrConnection
	}
	response, err := client.client.Do(request)
	if err != nil || response == nil {
		return ErrConnection
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" || readErr != nil || len(payload) < 2 || len(payload) > 1024 {
		clear(payload)
		return ErrConnection
	}
	var result struct {
		Result string `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&result)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	clear(payload)
	if decodeErr != nil || trailingErr != io.EOF || result.Result != "ok" {
		return ErrConnection
	}
	secret, err := client.resolver.Resolve(ctx, readiness.ServiceSecretReference)
	if err != nil || !validServiceSecret(secret) {
		clear(secret)
		return ErrConnection
	}
	query := url.Values{"env": []string{readiness.Environment}}
	var integration struct {
		Data struct {
			UniqueKey       string `json:"unique_key"`
			Provider        string `json:"provider"`
			DisplayName     string `json:"display_name"`
			Logo            string `json:"logo"`
			ForwardWebhooks bool   `json:"forward_webhooks"`
			CreatedAt       string `json:"created_at"`
			UpdatedAt       string `json:"updated_at"`
		} `json:"data"`
	}
	err = client.doJSON(ctx, http.MethodGet, readiness.NangoBaseURL+"/api/v1/integrations/"+url.PathEscape(readiness.ConnectorKey)+"?"+query.Encode(), secret, nil, http.StatusOK, &integration)
	clear(secret)
	created, createdErr := time.Parse(time.RFC3339Nano, integration.Data.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, integration.Data.UpdatedAt)
	logo, logoErr := url.Parse(integration.Data.Logo)
	if err != nil || integration.Data.UniqueKey != readiness.ConnectorKey || integration.Data.Provider != readiness.Provider || len(integration.Data.DisplayName) < 1 || len(integration.Data.DisplayName) > 128 || createdErr != nil || updatedErr != nil || created.Location() != time.UTC || updated.Location() != time.UTC || updated.Before(created) || logoErr != nil || logo.Scheme != "https" || logo.Host == "" || logo.User != nil || logo.RawQuery != "" || logo.Fragment != "" || !strings.HasSuffix(logo.Path, "/images/template-logos/"+readiness.Provider+".svg") {
		return ErrConnection
	}
	return nil
}

func (client *ProductionConnectionClient) doJSON(ctx context.Context, method, target string, secret, body []byte, expectedStatus int, output any) error {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return ErrConnection
	}
	request.Header.Set("Authorization", "Bearer "+string(secret))
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil || response == nil {
		return ErrConnection
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if readErr != nil || response.StatusCode != expectedStatus || len(payload) < 2 || len(payload) > 1<<20 || containsSecret(payload) {
		clear(payload)
		return ErrConnection
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(output)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	clear(payload)
	if decodeErr != nil || trailingErr != io.EOF {
		return ErrConnection
	}
	return nil
}

func (client *ProductionConnectionClient) Close() error {
	if client != nil && client.client != nil {
		client.client.CloseIdleConnections()
	}
	return nil
}

type nangoPublicConnection struct {
	ID                int64             `json:"id"`
	ConnectionID      string            `json:"connection_id"`
	ProviderConfigKey string            `json:"provider_config_key"`
	Provider          string            `json:"provider"`
	Errors            []json.RawMessage `json:"errors"`
	EndUser           struct {
		ID           string            `json:"id"`
		DisplayName  *string           `json:"display_name"`
		Email        *string           `json:"email"`
		Tags         map[string]string `json:"tags"`
		Organization struct {
			ID          string  `json:"id"`
			DisplayName *string `json:"display_name"`
		} `json:"organization"`
	} `json:"end_user"`
	Tags     map[string]string `json:"tags"`
	Metadata json.RawMessage   `json:"metadata"`
	Created  string            `json:"created"`
}

func validNangoConnection(value nangoPublicConnection, request OAuthCompleteRequest, organizationID, endUserID string) bool {
	created, err := time.Parse(time.RFC3339Nano, value.Created)
	return err == nil && created.Location() == time.UTC && value.ID > 0 && connectionReferencePattern.MatchString("ref:nango/connection/"+value.ConnectionID) &&
		value.ProviderConfigKey == request.ConnectorKey && value.Provider == request.Provider && len(value.Errors) == 0 && string(value.Metadata) == "null" &&
		value.EndUser.ID == endUserID && value.EndUser.DisplayName == nil && value.EndUser.Email == nil && len(value.EndUser.Tags) == 1 && value.EndUser.Tags["origin"] == "nango_dashboard" &&
		value.EndUser.Organization.ID == organizationID && value.EndUser.Organization.DisplayName == nil && len(value.Tags) == 3 && value.Tags["end_user_id"] == endUserID && value.Tags["organization_id"] == organizationID && value.Tags["origin"] == "nango_dashboard"
}

func validNangoRevocationConnection(value nangoPublicConnection, request ConnectionRevocationRequest, connectionID string) bool {
	created, err := time.Parse(time.RFC3339Nano, value.Created)
	organizationID := nangoRevocationOrganizationID(request.Binding)
	return err == nil && created.Location() == time.UTC && value.ID > 0 && value.ConnectionID == connectionID &&
		value.ProviderConfigKey == request.ConnectorKey && value.Provider == request.Provider && len(value.Errors) == 0 && string(value.Metadata) == "null" &&
		strings.HasPrefix(value.EndUser.ID, "user_") && len(value.EndUser.ID) == len("user_")+16 && value.EndUser.DisplayName == nil && value.EndUser.Email == nil &&
		len(value.EndUser.Tags) == 1 && value.EndUser.Tags["origin"] == "nango_dashboard" && value.EndUser.Organization.ID == organizationID && value.EndUser.Organization.DisplayName == nil &&
		len(value.Tags) == 3 && value.Tags["end_user_id"] == value.EndUser.ID && value.Tags["organization_id"] == organizationID && value.Tags["origin"] == "nango_dashboard"
}

func validOAuthStartRequest(value OAuthStartRequest) bool {
	return validNangoAuthority(value.NangoBaseURL, value.ServiceSecretReference, value.Environment, value.ConnectorKey, value.Provider, value.Binding) && validAuthorizationHost(value.AuthorizationHost) && validAuthorizationPath(value.AuthorizationPath) && validPublicCallbackURL(value.CallbackURL)
}

func validOAuthCompleteRequest(value OAuthCompleteRequest) bool {
	return validOAuthRecoveryRequest(value) && oauthValuePattern.MatchString(value.State) && oauthValuePattern.MatchString(value.Code)
}

func validOAuthRecoveryRequest(value OAuthCompleteRequest) bool {
	return validNangoAuthority(value.NangoBaseURL, value.ServiceSecretReference, value.Environment, value.ConnectorKey, value.Provider, value.Binding)
}

func validNangoAuthority(baseURL, reference, environment, connectorKey, provider string, binding ConnectionBinding) bool {
	return validBaseURL(baseURL) && referencePattern.MatchString(reference) && environmentPattern.MatchString(environment) && keyPattern.MatchString(connectorKey) && keyPattern.MatchString(provider) && validConnectionBinding(binding)
}

func validNangoRevocationAuthority(value ConnectionRevocationRequest) bool {
	return validBaseURL(value.NangoBaseURL) && referencePattern.MatchString(value.ServiceSecretReference) && environmentPattern.MatchString(value.Environment) &&
		keyPattern.MatchString(value.ConnectorKey) && keyPattern.MatchString(value.Provider) && value.Provider == value.ConnectorKey && validRevocationBinding(value.Binding)
}

func validConnectionBinding(value ConnectionBinding) bool {
	return productIDPattern.MatchString(value.OrganizationID) && productIDPattern.MatchString(value.WorkspaceID) && productIDPattern.MatchString(value.EnvironmentID) && productIDPattern.MatchString(value.IntegrationID) && productIDPattern.MatchString(value.AttemptID)
}

func validRevocationBinding(value RevocationBinding) bool {
	return productIDPattern.MatchString(value.OrganizationID) && productIDPattern.MatchString(value.WorkspaceID) && productIDPattern.MatchString(value.EnvironmentID) && productIDPattern.MatchString(value.IntegrationID)
}

func validAuthorizationHost(value string) bool {
	return validProviderHost(value) && !strings.HasSuffix(value, ".svc.cluster.local")
}

func validAuthorizationPath(value string) bool {
	return validProxyPath(value)
}

func validPublicCallbackURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && validAuthorizationHost(strings.ToLower(parsed.Hostname())) && parsed.Port() == "" && parsed.User == nil && parsed.Path == "/api/v1/integrations/oauth/callback" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func nangoOrganizationID(value ConnectionBinding) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{value.OrganizationID, value.WorkspaceID, value.EnvironmentID}, "\x1f")))
	return "org_" + hex.EncodeToString(digest[:8])
}

func nangoRevocationOrganizationID(value RevocationBinding) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{value.OrganizationID, value.WorkspaceID, value.EnvironmentID}, "\x1f")))
	return "org_" + hex.EncodeToString(digest[:8])
}

func nangoEndUserID(value ConnectionBinding) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{value.OrganizationID, value.WorkspaceID, value.EnvironmentID, value.IntegrationID, value.AttemptID}, "\x1f")))
	return "user_" + hex.EncodeToString(digest[:8])
}
