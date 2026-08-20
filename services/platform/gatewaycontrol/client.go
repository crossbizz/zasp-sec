package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type HTTPClientConfig struct {
	BaseURL          string
	OrganizationID   string
	WorkspaceID      string
	EnvironmentID    string
	DeviceID         string
	CredentialID     string
	KeyID            string
	PrivateKey       ed25519.PrivateKey
	OperationTimeout time.Duration
	Clock            func() time.Time
}

type HTTPClient struct {
	baseURL        *url.URL
	organizationID string
	workspaceID    string
	environmentID  string
	deviceID       string
	credentialID   string
	keyID          string
	privateKey     ed25519.PrivateKey
	timeout        time.Duration
	clock          func() time.Time
	http           *http.Client
}

func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: config.OperationTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   config.OperationTimeout,
		ResponseHeaderTimeout: config.OperationTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	httpClient := &http.Client{Transport: transport, Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errHTTPControl }}
	client, err := newHTTPClient(config, httpClient)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}

func newHTTPClient(config HTTPClientConfig, httpClient *http.Client) (*HTTPClient, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.String() != config.BaseURL || baseURL.Scheme != "https" || baseURL.Hostname() == "" || baseURL.User != nil || baseURL.Path != "" || baseURL.RawQuery != "" || baseURL.Fragment != "" ||
		!validProductID(config.OrganizationID) || !validProductID(config.WorkspaceID) || !validProductID(config.EnvironmentID) || !validProductID(config.DeviceID) || !validProductID(config.CredentialID) || !keyIDPattern.MatchString(config.KeyID) || len(config.PrivateKey) != ed25519.PrivateKeySize || config.OperationTimeout < 50*time.Millisecond || config.OperationTimeout > 10*time.Second || config.Clock == nil || httpClient == nil || httpClient.Transport == nil {
		return nil, errHTTPControl
	}
	return &HTTPClient{baseURL: baseURL, organizationID: config.OrganizationID, workspaceID: config.WorkspaceID, environmentID: config.EnvironmentID, deviceID: config.DeviceID, credentialID: config.CredentialID, keyID: config.KeyID, privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), timeout: config.OperationTimeout, clock: config.Clock, http: httpClient}, nil
}

func (client *HTTPClient) Ready(ctx context.Context) error {
	if client == nil {
		return errHTTPControl
	}
	_, err := client.Authority(ctx, client.credentialID)
	return err
}

func (client *HTTPClient) Authority(ctx context.Context, credentialID string) (Authority, error) {
	if !validClientCall(client, ctx, credentialID) {
		return Authority{}, errHTTPControl
	}
	response, err := client.do(ctx, http.MethodGet, AuthorityPath, nil, "")
	if err != nil {
		return Authority{}, errHTTPControl
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != JSONMediaType || response.Header.Get("Cache-Control") != "no-store" {
		return Authority{}, errHTTPControl
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return Authority{}, errHTTPControl
	}
	var payload authorityPayload
	if strictJSON(raw, &payload) != nil {
		return Authority{}, errHTTPControl
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != payload.PublicKey {
		return Authority{}, errHTTPControl
	}
	authority := Authority{
		OrganizationID: payload.OrganizationID, WorkspaceID: payload.WorkspaceID, EnvironmentID: payload.EnvironmentID,
		DeviceID: payload.DeviceID, DeviceVersion: payload.DeviceVersion, ReplayFloor: payload.ReplayFloor,
		CredentialID: payload.CredentialID, CredentialGeneration: payload.CredentialGeneration, KeyID: payload.KeyID,
		Algorithm: payload.Algorithm, PublicKey: ed25519.PublicKey(publicKey), Audience: payload.Audience, ExpiresAt: payload.ExpiresAt,
	}
	if !validAuthority(authority, credentialID, client.clock()) || authority.OrganizationID != client.organizationID || authority.WorkspaceID != client.workspaceID || authority.EnvironmentID != client.environmentID || authority.DeviceID != client.deviceID || authority.KeyID != client.keyID || !bytes.Equal(client.privateKey.Public().(ed25519.PublicKey), authority.PublicKey) {
		return Authority{}, errHTTPControl
	}
	return cloneAuthority(authority), nil
}

func (client *HTTPClient) Policy(ctx context.Context, credentialID string, after uint64) (*policy.GatewayPolicyEnvelope, error) {
	if !validClientCall(client, ctx, credentialID) || after > uint64(^uint64(0)>>1) {
		return nil, errHTTPControl
	}
	path := PolicyPathPrefix + client.environmentID + "?after_sequence=" + strconv.FormatUint(after, 10)
	response, err := client.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, errHTTPControl
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent && response.Header.Get("Cache-Control") == "no-store" {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != JSONMediaType || response.Header.Get("Cache-Control") != "no-store" {
		return nil, errHTTPControl
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return nil, errHTTPControl
	}
	var envelope policy.GatewayPolicyEnvelope
	if strictJSON(raw, &envelope) != nil || envelope.OrganizationID != client.organizationID || envelope.WorkspaceID != client.workspaceID || envelope.EnvironmentID != client.environmentID || envelope.DeviceID != client.deviceID || envelope.Audience != PolicyAudience || envelope.Sequence <= after {
		return nil, errHTTPControl
	}
	return &envelope, nil
}

func (client *HTTPClient) Record(ctx context.Context, event DecisionEvent) error {
	if !validClientCall(client, ctx, event.CredentialID) || !validDecisionEvent(event) {
		return errHTTPControl
	}
	body, err := json.Marshal(event)
	if err != nil {
		return errHTTPControl
	}
	response, err := client.do(ctx, http.MethodPost, DecisionPath, body, JSONMediaType)
	if err != nil {
		return errHTTPControl
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Cache-Control") != "no-store" {
		return errHTTPControl
	}
	return nil
}

func (client *HTTPClient) Close() error {
	if client == nil {
		return nil
	}
	clear(client.privateKey)
	client.privateKey = nil
	if transport, ok := client.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (client *HTTPClient) do(ctx context.Context, method, path string, body []byte, mediaType string) (*http.Response, error) {
	operation, cancel := context.WithTimeout(ctx, client.timeout)
	target := *client.baseURL
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		cancel()
		return nil, errHTTPControl
	}
	target.Path = parsed.Path
	target.RawQuery = parsed.RawQuery
	request, err := http.NewRequestWithContext(operation, method, target.String(), bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, errHTTPControl
	}
	if mediaType != "" {
		request.Header.Set("Content-Type", mediaType)
	}
	if err := SignRequest(request, body, client.credentialID, client.privateKey, client.clock()); err != nil {
		cancel()
		return nil, errHTTPControl
	}
	response, err := client.http.Do(request)
	if err != nil || operation.Err() != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		cancel()
		return nil, errHTTPControl
	}
	response.Body = &cancelingReadCloser{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelingReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelingReadCloser) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

func validClientCall(client *HTTPClient, ctx context.Context, credentialID string) bool {
	return client != nil && client.baseURL != nil && client.http != nil && len(client.privateKey) == ed25519.PrivateKeySize && ctx != nil && ctx.Err() == nil && credentialID == client.credentialID
}
