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
)

type HTTPCallbackProvider struct {
	endpoint string
	bearer   string
	client   *http.Client
}

func NewHTTPCallbackProvider(endpoint, bearer string, timeout time.Duration) (*HTTPCallbackProvider, error) {
	parsed, err := url.Parse(endpoint)
	loopback := net.ParseIP(parsed.Hostname()) != nil && net.ParseIP(parsed.Hostname()).IsLoopback()
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback)) || len(bearer) < 8 || len(bearer) > 4096 || strings.TrimSpace(bearer) != bearer || timeout <= 0 || timeout > 30*time.Second {
		return nil, ErrRepositoryConfiguration
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider redirect rejected") }}
	return &HTTPCallbackProvider{endpoint: endpoint, bearer: bearer, client: client}, nil
}

func (provider *HTTPCallbackProvider) Complete(ctx context.Context, code, state string) (string, error) {
	if provider == nil || provider.client == nil || ctx == nil || ctx.Err() != nil || code == "" || state == "" || len(code) > 4096 || len(state) > 512 {
		return "", ErrRepositoryAuthentication
	}
	payload, err := json.Marshal(map[string]string{"authorization_code": code, "state": state})
	if err != nil {
		return "", ErrRepositoryAuthentication
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", ErrRepositoryAuthentication
	}
	request.Header.Set("Authorization", "Bearer "+provider.bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := provider.client.Do(request)
	if err != nil {
		return "", ErrRepositoryAuthentication
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return "", ErrRepositoryAuthentication
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8*1024+1))
	decoder.DisallowUnknownFields()
	var value struct {
		SessionToken string `json:"session_token"`
	}
	if decoder.Decode(&value) != nil || value.SessionToken == "" || len(value.SessionToken) > 4096 {
		return "", ErrRepositoryAuthentication
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", ErrRepositoryAuthentication
	}
	return value.SessionToken, nil
}
