package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type HTTPCallbackProvider struct {
	endpoint string
	bearer   string
	client   *http.Client
}

func (provider *HTTPCallbackProvider) Ready(ctx context.Context) error {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, provider.endpoint, nil)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+provider.bearer)
	response, err := provider.client.Do(request)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return ErrRepositoryUnavailable
	}
	return nil
}

func NewHTTPCallbackProvider(endpoint, bearer string, timeout time.Duration) (*HTTPCallbackProvider, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed == nil {
		return nil, ErrRepositoryConfiguration
	}
	loopback := net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback)) || len(bearer) < 8 || len(bearer) > 4096 || strings.TrimSpace(bearer) != bearer || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirect rejected") }}
	return &HTTPCallbackProvider{endpoint: endpoint, bearer: bearer, client: client}, nil
}

func (provider *HTTPCallbackProvider) Complete(ctx context.Context, code, state string) (SessionGrant, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || code == "" || state == "" || len(code) > 4096 || len(state) > 512 {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	payload, err := json.Marshal(map[string]string{"authorization_code": code, "state": state})
	if err != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.endpoint, bytes.NewReader(payload))
	if err != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	request.Header.Set("Authorization", "Bearer "+provider.bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := provider.client.Do(request)
	if err != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8*1024+1))
	decoder.DisallowUnknownFields()
	var value struct {
		PrincipalID    string   `json:"principal_id"`
		OrganizationID string   `json:"organization_id"`
		WorkspaceID    string   `json:"workspace_id"`
		EnvironmentID  string   `json:"environment_id"`
		Permissions    []string `json:"permissions"`
		ExpiresAt      string   `json:"expires_at"`
	}
	if decoder.Decode(&value) != nil {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	principal, principalErr := domain.ParseProductID(value.PrincipalID)
	organization, organizationErr := domain.ParseProductID(value.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(value.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(value.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	expiresAt, expiresErr := time.Parse(time.RFC3339, value.ExpiresAt)
	grant := SessionGrant{PrincipalID: principal, Scope: scope, Permissions: append([]string(nil), value.Permissions...), ExpiresAt: expiresAt}
	if principalErr != nil || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || expiresErr != nil || !validSessionGrant(grant) {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	return grant, nil
}
