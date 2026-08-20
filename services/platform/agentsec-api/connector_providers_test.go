package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/githubdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/idpdiscovery"
)

type connectorRoundTripFunc func(*http.Request) (*http.Response, error)

func (function connectorRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func connectorJSONResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestGitHubExchangeUsesFixedEndpointsStrictParsersAndReferenceOnlyResult(t *testing.T) {
	secret := "github-client-secret-value"
	secretAPI := &connectorSecretsAPIStub{values: map[string][]byte{"zasp/github/app-secret-0001": []byte(secret)}}
	calls := 0
	client := &http.Client{Transport: connectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if request.Method != http.MethodPost || request.URL.String() != "https://github.com/login/oauth/access_token" || request.Header.Get("Accept") != "application/json" || request.ParseForm() != nil || request.Form.Get("client_secret") != secret || request.Form.Get("code_verifier") != "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" {
				t.Fatalf("token request = %s %s %#v", request.Method, request.URL, request.Form)
			}
			return connectorJSONResponse(http.StatusOK, `{"access_token":"github-access-token-value","token_type":"bearer","scope":"read:org repo"}`), nil
		case 2:
			if request.Method != http.MethodGet || request.URL.String() != "https://api.github.com/user/installations?per_page=2" || request.Header.Get("Authorization") != "Bearer github-access-token-value" {
				t.Fatalf("installation request = %s %s %#v", request.Method, request.URL, request.Header)
			}
			return connectorJSONResponse(http.StatusOK, `{"total_count":1,"installations":[{"id":123456,"account":{"login":"acme"},"repository_selection":"selected","permissions":{"metadata":"read"}}]}`), nil
		case 3:
			if request.Method != http.MethodDelete || request.URL.String() != "https://api.github.com/applications/Iv1.1234567890abcdef/token" || request.Header.Get("Authorization") == "" {
				t.Fatalf("revocation request = %s %s %#v", request.Method, request.URL, request.Header)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			t.Fatalf("unexpected provider call %d", calls)
			return nil, nil
		}
	})}
	exchange := &githubExchangeClient{http: client, secrets: &connectorProviderSecrets{driver: &connectorSecretsDriver{client: secretAPI}, root: "zasp", kmsKey: "kms"}}
	result, err := exchange.Exchange(context.Background(), githubdiscovery.ExchangeRequest{EffectID: "pid_70000003-0000-4000-8000-000000000003", ClientID: "Iv1.1234567890abcdef", ClientSecretReference: "ref:github/app-secret-0001", CallbackURL: "https://app.zasp.example/api/v1/integrations/oauth/callback", Code: "provider-code-0001", PKCEVerifier: []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")})
	if err != nil || result.Reference != "ref:github/install/123456" || result.AccountLogin != "acme" || calls != 3 {
		t.Fatalf("GitHub exchange = %#v, %v, calls=%d", result, err, calls)
	}
	if strings.Contains(result.Reference, secret) {
		t.Fatal("secret reached reference-only result")
	}
	recovered, err := exchange.Recover(context.Background(), "pid_70000003-0000-4000-8000-000000000003")
	if err != nil || recovered.Reference != result.Reference || calls != 3 {
		t.Fatalf("durable GitHub recovery = %#v, %v, calls=%d", recovered, err, calls)
	}
	if err := exchange.Discard(context.Background(), "pid_70000003-0000-4000-8000-000000000003", true); err != nil {
		t.Fatalf("GitHub cleanup: %v", err)
	}

	calls = 0
	client.Transport = connectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return connectorJSONResponse(http.StatusOK, `{"access_token":"github-access-token-value","token_type":"bearer","scope":"read:org","unexpected":"rejected"}`), nil
	})
	if _, err := exchange.Exchange(context.Background(), githubdiscovery.ExchangeRequest{EffectID: "pid_70000004-0000-4000-8000-000000000004", ClientID: "Iv1.1234567890abcdef", ClientSecretReference: "ref:github/app-secret-0001", CallbackURL: "https://app.zasp.example/api/v1/integrations/oauth/callback", Code: "provider-code-0001", PKCEVerifier: []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("hostile GitHub response error = %v", err)
	}
}

func TestOktaExchangePersistsDeterministicOutcomeAndRevokesTransientTokens(t *testing.T) {
	secret := "okta-client-secret-value"
	secretAPI := &connectorSecretsAPIStub{values: map[string][]byte{"zasp/okta/client-secret-0001": []byte(secret)}}
	calls := 0
	client := &http.Client{Transport: connectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if request.Method != http.MethodPost || request.URL.String() != "https://acme.okta.com/oauth2/v1/token" || request.Header.Get("Authorization") == "" {
				t.Fatalf("Okta token request = %s %s %#v", request.Method, request.URL, request.Header)
			}
			return connectorJSONResponse(http.StatusOK, `{"access_token":"okta-access-token-value","refresh_token":"okta-refresh-token-value","token_type":"bearer","scope":"offline_access okta.apps.read okta.groups.read okta.users.read","expires_in":300}`), nil
		case 2:
			if request.Method != http.MethodGet || request.URL.String() != "https://acme.okta.com/oauth2/v1/userinfo" || request.Header.Get("Authorization") != "Bearer okta-access-token-value" {
				t.Fatalf("Okta profile request = %s %s %#v", request.Method, request.URL, request.Header)
			}
			return connectorJSONResponse(http.StatusOK, `{"sub":"00u1234567890abcdef"}`), nil
		case 3, 4:
			if request.Method != http.MethodPost || request.URL.String() != "https://acme.okta.com/oauth2/v1/revoke" || request.ParseForm() != nil || request.Form.Get("token") == "" || request.Header.Get("Authorization") == "" {
				t.Fatalf("Okta revoke request = %s %s %#v", request.Method, request.URL, request.Form)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			t.Fatalf("unexpected Okta call %d", calls)
			return nil, nil
		}
	})}
	exchange := &oktaExchangeClient{http: client, secrets: &connectorProviderSecrets{driver: &connectorSecretsDriver{client: secretAPI}, root: "zasp", kmsKey: "kms"}}
	effectID := "pid_70000003-0000-4000-8000-000000000003"
	result, err := exchange.Exchange(context.Background(), idpdiscovery.ExchangeRequest{EffectID: effectID, Issuer: "https://acme.okta.com", ClientID: "0oa1234567890abcdef", ClientSecretReference: "ref:okta/client-secret-0001", CallbackURL: "https://app.zasp.example/api/v1/integrations/oauth/callback", Code: "provider-code-0001", PKCEVerifier: []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")})
	if err != nil || result.Reference != "ref:okta/refresh/70000003-0000-4000-8000-000000000003" || calls != 3 {
		t.Fatalf("Okta exchange = %#v, %v, calls=%d", result, err, calls)
	}
	recovered, err := exchange.Recover(context.Background(), effectID)
	if err != nil || recovered.Reference != result.Reference || calls != 3 {
		t.Fatalf("durable Okta recovery = %#v, %v, calls=%d", recovered, err, calls)
	}
	if err := exchange.Discard(context.Background(), effectID, true); err != nil || calls != 4 {
		t.Fatalf("Okta cleanup err=%v calls=%d", err, calls)
	}
	for name := range secretAPI.values {
		if strings.Contains(name, "70000003-0000-4000-8000-000000000003") {
			t.Fatalf("effect secret residue %q", name)
		}
	}
}

func TestPerformConnectorJSONRejectsRedirectWrongMediaTypeOversizeAndTrailingValues(t *testing.T) {
	tests := []struct {
		name, body, contentType, location string
		status                            int
	}{
		{name: "redirect", status: http.StatusFound, body: `{}`, contentType: "application/json", location: "https://attacker.invalid"},
		{name: "media", status: http.StatusOK, body: `{}`, contentType: "text/plain"},
		{name: "media prefix", status: http.StatusOK, body: `{}`, contentType: "application/jsonfoo"},
		{name: "oversize", status: http.StatusOK, body: `{"value":"` + strings.Repeat("x", 200) + `"}`, contentType: "application/json"},
		{name: "oversize whitespace", status: http.StatusOK, body: `{}` + strings.Repeat(" ", 63), contentType: "application/json"},
		{name: "trailing", status: http.StatusOK, body: `{} {}`, contentType: "application/json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: connectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
				response := connectorJSONResponse(test.status, test.body)
				response.Header.Set("Content-Type", test.contentType)
				response.Header.Set("Location", test.location)
				return response, nil
			})}
			request, _ := http.NewRequest(http.MethodGet, "https://provider.invalid/value", nil)
			var target map[string]string
			if err := performConnectorJSON(client, request, &target, 64); err == nil {
				t.Fatal("hostile provider response accepted")
			}
		})
	}
}
