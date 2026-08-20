package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type discoveryTokenRoundTripper struct {
	request *http.Request
	body    []byte
	status  int
	header  http.Header
	err     error
}

func (transport *discoveryTokenRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.request = request.Clone(request.Context())
	body, _ := io.ReadAll(request.Body)
	transport.request.Body = io.NopCloser(bytes.NewReader(body))
	if transport.err != nil {
		return nil, transport.err
	}
	return &http.Response{StatusCode: transport.status, Header: transport.header.Clone(), Body: io.NopCloser(bytes.NewReader(transport.body)), Request: request}, nil
}

func TestProductionDiscoveryGitHubTokenClientMintsExactInstallationToken(t *testing.T) {
	now := time.Now().UTC()
	transport := &discoveryTokenRoundTripper{status: http.StatusCreated, header: http.Header{"Content-Type": {"application/json; charset=utf-8"}}, body: []byte(`{"token":"github-installation-token","expires_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `","permissions":{"contents":"read","metadata":"read"},"repository_selection":"all"}`)}
	client, err := newProductionDiscoveryGitHubTokenClient(&http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: rejectDiscoveryProviderRedirect}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	result, err := client.MintDiscoveryInstallationToken(context.Background(), "123456", privateKey, 987654)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Token) != "github-installation-token" || result.InstallationID != 987654 || !result.ExpiresAt.Equal(now.Add(time.Hour).Truncate(time.Second)) {
		t.Fatalf("result=%#v", result)
	}
	if transport.request.Method != http.MethodPost || transport.request.URL.String() != "https://api.github.com/app/installations/987654/access_tokens" || transport.request.Header.Get("Authorization") == "" || !strings.HasPrefix(transport.request.Header.Get("Authorization"), "Bearer eyJ") || transport.request.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Fatalf("request=%#v", transport.request)
	}
	payload, _ := io.ReadAll(transport.request.Body)
	if string(payload) != `{}` || bytes.Contains(payload, privateKey) {
		t.Fatalf("payload=%q", payload)
	}
	result.Destroy()
}

func TestProductionDiscoveryOktaTokenClientExchangesExactRefreshWithoutRotationLoss(t *testing.T) {
	now := time.Now().UTC()
	transport := &discoveryTokenRoundTripper{status: http.StatusOK, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"access_token":"okta-access-token-value","token_type":"Bearer","expires_in":3600,"scope":"okta.apps.read okta.groups.read okta.users.read"}`)}
	client, err := newProductionDiscoveryOktaTokenClient(&http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: rejectDiscoveryProviderRedirect}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ExchangeDiscoveryRefreshToken(context.Background(), "https://acme.okta.com", "0oa1234567890abcdef", []byte("okta-client-secret-value"), []byte("okta-refresh-token-value"))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Token) != "okta-access-token-value" || result.Tenant != "acme.okta.com" || !equalDiscoveryStrings(result.Scopes, []string{"okta.apps.read", "okta.groups.read", "okta.users.read"}) || !result.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("result=%#v", result)
	}
	username, password, ok := transport.request.BasicAuth()
	if !ok || username != "0oa1234567890abcdef" || password != "okta-client-secret-value" || transport.request.Method != http.MethodPost || transport.request.URL.String() != "https://acme.okta.com/oauth2/v1/token" {
		t.Fatalf("request=%#v", transport.request)
	}
	payload, _ := io.ReadAll(transport.request.Body)
	form, _ := url.ParseQuery(string(payload))
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "okta-refresh-token-value" || len(form) != 2 {
		t.Fatalf("form=%v", form)
	}
	result.Destroy()

	transport.body = []byte(`{"access_token":"okta-access-token-value","token_type":"Bearer","expires_in":3600,"scope":"okta.apps.read okta.groups.read okta.users.read","refresh_token":"rotated-refresh-token"}`)
	if _, err := client.ExchangeDiscoveryRefreshToken(context.Background(), "https://acme.okta.com", "0oa1234567890abcdef", []byte("okta-client-secret-value"), []byte("okta-refresh-token-value")); err == nil {
		t.Fatal("unpersistable refresh rotation accepted")
	}
}

func TestProductionDiscoveryTokenClientsRejectRedirectsAndHostileOutputs(t *testing.T) {
	now := time.Now().UTC()
	client, transport, err := newDiscoveryProviderHTTPClient(time.Second)
	if err != nil || client.CheckRedirect == nil || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("client=%#v transport=%#v err=%v", client, transport, err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.github.com", nil)
	if err := client.CheckRedirect(request, []*http.Request{request}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect err=%v", err)
	}

	hostile := &discoveryTokenRoundTripper{status: http.StatusOK, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"access_token":"secret","token_type":"Bearer","expires_in":999999,"scope":"admin"}`)}
	okta, _ := newProductionDiscoveryOktaTokenClient(&http.Client{Transport: hostile}, func() time.Time { return now })
	_, err = okta.ExchangeDiscoveryRefreshToken(context.Background(), "https://acme.okta.com", "0oa1234567890abcdef", []byte("okta-client-secret-value"), []byte("okta-refresh-token-value"))
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "acme") {
		t.Fatalf("unstable hostile error=%v", err)
	}
}

var _ http.RoundTripper = (*discoveryTokenRoundTripper)(nil)
