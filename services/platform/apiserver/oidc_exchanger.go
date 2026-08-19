package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OIDCCodeExchanger struct {
	endpoint, clientID, clientSecret string
	client                           *http.Client
}

func NewOIDCCodeExchanger(endpoint, clientID, clientSecret string, timeout time.Duration) (*OIDCCodeExchanger, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	loopback := net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback)) || !boundedSecret(clientID) || !boundedSecret(clientSecret) || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	return &OIDCCodeExchanger{endpoint: endpoint, clientID: clientID, clientSecret: clientSecret, client: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("identity redirect rejected") }}}, nil
}

func (exchanger *OIDCCodeExchanger) Ready(ctx context.Context) error {
	if exchanger == nil || exchanger.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, exchanger.endpoint, nil)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	request.SetBasicAuth(exchanger.clientID, exchanger.clientSecret)
	response, err := exchanger.client.Do(request)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (exchanger *OIDCCodeExchanger) Exchange(ctx context.Context, code, state string) (ExternalIdentity, error) {
	if exchanger == nil || exchanger.client == nil || ctx == nil || ctx.Err() != nil || code == "" || len(code) > 4096 || len(state) < 32 || len(state) > 512 {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "state": {state}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, exchanger.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(exchanger.clientID, exchanger.clientSecret)
	response, err := exchanger.client.Do(request)
	if err != nil {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	var value struct {
		OrganizationReference string `json:"organization_reference"`
		MemberReference       string `json:"member_reference"`
		ExpiresAt             string `json:"expires_at"`
	}
	if decoder.Decode(&value) != nil {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	expires, err := time.Parse(time.RFC3339, value.ExpiresAt)
	identity := ExternalIdentity{OrganizationReference: value.OrganizationReference, MemberReference: value.MemberReference, ExpiresAt: expires}
	if err != nil || !validExternalIdentity(identity) {
		return ExternalIdentity{}, ErrRepositoryAuthentication
	}
	return identity, nil
}

func boundedSecret(value string) bool {
	return len(value) >= 8 && len(value) <= 4096 && strings.TrimSpace(value) == value
}
