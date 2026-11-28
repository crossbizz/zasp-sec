package nango

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProductionConnectionClientStartsAndCompletesTenantBoundOAuth(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	binding := ConnectionBinding{
		OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222",
		EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", IntegrationID: "pid_44444444-4444-4444-8444-444444444444", AttemptID: "pid_55555555-5555-4555-8555-555555555555",
	}
	serviceSecret := "00000000-0000-4000-8000-000000000001"
	resolverCalls := 0
	resolver := serviceSecretResolverFunc(func(_ context.Context, reference string) ([]byte, error) {
		resolverCalls++
		if reference != "ref:nango/service-key-0001" {
			t.Fatalf("reference %q", reference)
		}
		return []byte(serviceSecret), nil
	})
	step := 0
	client, err := newProductionConnectionClientWithHTTP(resolver, &http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			step++
			switch step {
			case 1:
				if request.Method != http.MethodPost || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/connect/sessions" || request.Header.Get("Authorization") != "Bearer "+serviceSecret {
					t.Fatalf("session request %s %s %#v", request.Method, request.URL, request.Header)
				}
				var body struct {
					EndUser struct {
						ID   string            `json:"id"`
						Tags map[string]string `json:"tags"`
					} `json:"end_user"`
					Organization struct {
						ID string `json:"id"`
					} `json:"organization"`
					Allowed []string `json:"allowed_integrations"`
				}
				if json.NewDecoder(request.Body).Decode(&body) != nil || body.EndUser.ID != nangoEndUserID(binding) || body.EndUser.Tags["origin"] != "zasp" || body.Organization.ID != nangoOrganizationID(binding) || len(body.Allowed) != 1 || body.Allowed[0] != "slack" {
					t.Fatalf("session body %#v", body)
				}
				return jsonHTTPResponse(http.StatusCreated, `{"data":{"token":"nango_connect_session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","connect_link":"http://nango.connector.svc.cluster.local:3003/connect?session_token=nango_connect_session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expires_at":"2026-08-28T12:10:00Z"}}`), nil
			case 2:
				if request.Method != http.MethodGet || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/oauth/connect/slack?connect_session_token=nango_connect_session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || request.Header.Get("Authorization") != "" || request.Header.Get("Accept") != "application/json" {
					t.Fatalf("connect request %s %s %#v", request.Method, request.URL, request.Header)
				}
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://slack.com/oauth/v2/authorize?client_id=client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fapi%2Fv1%2Fintegrations%2Foauth%2Fcallback&state=nango_state_12345678&code_challenge=challenge_1234567890123456789012345678901234567890123&code_challenge_method=S256"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			case 3:
				if request.Method != http.MethodGet || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/oauth/callback?code=provider_code_123&state=nango_state_12345678" || request.Header.Get("Authorization") != "" {
					t.Fatalf("callback request %s %s %#v", request.Method, request.URL, request.Header)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader("<html>connected</html>"))}, nil
			case 4:
				expected := "http://nango.connector.svc.cluster.local:3003/connection?endUserId=" + nangoEndUserID(binding) + "&integrationId=slack&limit=2&page=0"
				if request.Method != http.MethodGet || request.URL.String() != expected || request.Header.Get("Authorization") != "Bearer "+serviceSecret {
					t.Fatalf("connection request %s %s %#v", request.Method, request.URL, request.Header)
				}
				payload := map[string]any{"connections": []any{map[string]any{
					"id": 1, "connection_id": "11111111-1111-4111-8111-111111111111", "provider_config_key": "slack", "provider": "slack", "errors": []any{}, "metadata": map[string]string{"team.id": "T024BE7LD", "bot_user_id": "U01234567"}, "created": "2026-08-28T12:00:01.000Z",
					"end_user": map[string]any{"id": nangoEndUserID(binding), "display_name": nil, "email": nil, "tags": map[string]any{"origin": "zasp"}, "organization": map[string]any{"id": nangoOrganizationID(binding), "display_name": nil}},
					"tags":     map[string]any{"end_user_id": nangoEndUserID(binding), "organization_id": nangoOrganizationID(binding), "origin": "zasp"},
				}}}
				encoded, _ := json.Marshal(payload)
				return jsonHTTPResponse(http.StatusOK, string(encoded)), nil
			default:
				t.Fatalf("unexpected request %d", step)
				return nil, nil
			}
		}),
		Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.StartOAuth(context.Background(), OAuthStartRequest{
		NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", Provider: "slack", AuthorizationHost: "slack.com", AuthorizationPath: "/oauth/v2/authorize", CallbackURL: "https://app.example.test/api/v1/integrations/oauth/callback", Binding: binding,
	})
	if err != nil || authorization.State != "nango_state_12345678" || authorization.URL == "" || !authorization.ExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("authorization=%#v error=%v", authorization, err)
	}
	connection, err := client.CompleteOAuth(context.Background(), OAuthCompleteRequest{
		NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", Provider: "slack", State: authorization.State, Code: "provider_code_123", Binding: binding,
	})
	if err != nil || connection.Reference != "ref:nango/connection/11111111-1111-4111-8111-111111111111" || connection.ProviderSubject != nangoEndUserID(binding) || connection.ConnectorKey != "slack" {
		t.Fatalf("connection=%#v error=%v", connection, err)
	}
	if step != 4 || resolverCalls != 2 {
		t.Fatalf("steps=%d resolver=%d", step, resolverCalls)
	}
}

func jsonHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestNangoTenantBindingProducesDistinctProviderIdentities(t *testing.T) {
	base := ConnectionBinding{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", IntegrationID: "pid_44444444-4444-4444-8444-444444444444", AttemptID: "pid_55555555-5555-4555-8555-555555555555"}
	foreign := base
	foreign.OrganizationID = "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if nangoOrganizationID(base) == nangoOrganizationID(foreign) || nangoEndUserID(base) == nangoEndUserID(foreign) {
		t.Fatal("cross-tenant provider identities collided")
	}
}

func TestProductionConnectionClientRevokesOnlyExactTenantConnection(t *testing.T) {
	serviceSecret := "00000000-0000-4000-8000-000000000001"
	reference := "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	binding := RevocationBinding{
		OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222",
		EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", IntegrationID: "pid_44444444-4444-4444-8444-444444444444",
	}
	step := 0
	client, err := newProductionConnectionClientWithHTTP(serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte(serviceSecret), nil
	}), &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			expected := "http://nango.connector.svc.cluster.local:3003/connection?connectionId=11111111-1111-4111-8111-111111111111&endUserOrganizationId=" + nangoRevocationOrganizationID(binding) + "&integrationId=slack&limit=2&page=0"
			if request.Method != http.MethodGet || request.URL.String() != expected || request.Header.Get("Authorization") != "Bearer "+serviceSecret {
				t.Fatalf("lookup request %s %s %#v", request.Method, request.URL, request.Header)
			}
			payload := map[string]any{"connections": []any{map[string]any{
				"id": 1, "connection_id": "11111111-1111-4111-8111-111111111111", "provider_config_key": "slack", "provider": "slack", "errors": []any{}, "metadata": nil, "created": "2026-08-28T12:00:01.000Z",
				"end_user": map[string]any{"id": "user_0123456789abcdef", "display_name": nil, "email": nil, "tags": map[string]any{"origin": "nango_dashboard"}, "organization": map[string]any{"id": nangoRevocationOrganizationID(binding), "display_name": nil}},
				"tags":     map[string]any{"end_user_id": "user_0123456789abcdef", "organization_id": nangoRevocationOrganizationID(binding), "origin": "nango_dashboard"},
			}}}
			encoded, _ := json.Marshal(payload)
			return jsonHTTPResponse(http.StatusOK, string(encoded)), nil
		case 2:
			if request.Method != http.MethodDelete || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/connection/11111111-1111-4111-8111-111111111111?provider_config_key=slack" || request.Header.Get("Authorization") != "Bearer "+serviceSecret {
				t.Fatalf("delete request %s %s %#v", request.Method, request.URL, request.Header)
			}
			return jsonHTTPResponse(http.StatusOK, `{"success":true}`), nil
		default:
			t.Fatalf("unexpected request %d", step)
			return nil, nil
		}
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeConnection(context.Background(), ConnectionRevocationRequest{
		NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", Provider: "slack", ConnectionReference: reference, Binding: binding,
	})
	if err != nil || step != 2 {
		t.Fatalf("revoke err=%v steps=%d", err, step)
	}
}

func TestProductionConnectionClientRejectsForeignConnectionBeforeDelete(t *testing.T) {
	binding := RevocationBinding{OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222", EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", IntegrationID: "pid_44444444-4444-4444-8444-444444444444"}
	requests := 0
	client, err := newProductionConnectionClientWithHTTP(serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	}), &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return jsonHTTPResponse(http.StatusOK, `{"connections":[{"id":1,"connection_id":"11111111-1111-4111-8111-111111111111","provider_config_key":"slack","provider":"slack","errors":[],"end_user":{"id":"user_0123456789abcdef","display_name":null,"email":null,"tags":{"origin":"nango_dashboard"},"organization":{"id":"org_foreign000000","display_name":null}},"tags":{"end_user_id":"user_0123456789abcdef","organization_id":"org_foreign000000","origin":"nango_dashboard"},"metadata":null,"created":"2026-08-28T12:00:01.000Z"}]}`), nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeConnection(context.Background(), ConnectionRevocationRequest{NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", ConnectorKey: "slack", Provider: "slack", ConnectionReference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", Binding: binding})
	if !errors.Is(err, ErrConnection) || requests != 1 {
		t.Fatalf("foreign revoke err=%v requests=%d", err, requests)
	}
}

func TestProductionConnectionClientChecksExactPrivateReadiness(t *testing.T) {
	requests := 0
	client, err := newProductionConnectionClientWithHTTP(serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	}), &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			if request.Method != http.MethodGet || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/ready" || len(request.Header) != 0 {
				t.Fatalf("readiness request %s %s %#v", request.Method, request.URL, request.Header)
			}
			return jsonHTTPResponse(http.StatusOK, `{"result":"ok"}`), nil
		}
		if request.Method != http.MethodGet || request.URL.String() != "http://nango.connector.svc.cluster.local:3003/integrations/slack" || request.Header.Get("Authorization") != "Bearer 00000000-0000-4000-8000-000000000001" {
			t.Fatalf("integration readiness request %s %s %#v", request.Method, request.URL, request.Header)
		}
		return jsonHTTPResponse(http.StatusOK, `{"data":{"unique_key":"slack","provider":"slack","display_name":"Slack","logo":"https://app.example.test/images/template-logos/slack.svg","forward_webhooks":true,"created_at":"2026-08-28T12:00:00.000Z","updated_at":"2026-08-28T12:00:00.000Z"}}`), nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	readiness := ReadinessRequest{NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "prod", ConnectorKey: "slack", Provider: "slack"}
	if err := client.CheckReadiness(context.Background(), readiness); err != nil || requests != 2 {
		t.Fatalf("readiness err=%v requests=%d", err, requests)
	}
	for _, response := range []*http.Response{
		jsonHTTPResponse(http.StatusServiceUnavailable, `{"result":"not ready"}`),
		jsonHTTPResponse(http.StatusOK, `{"result":"ok","extra":true}`),
		{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(`{"result":"ok"}`))},
	} {
		client.client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) { return response, nil })
		if err := client.CheckReadiness(context.Background(), readiness); !errors.Is(err, ErrConnection) {
			t.Fatalf("hostile readiness response accepted: %v", err)
		}
	}
	client.client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/ready" {
			return jsonHTTPResponse(http.StatusOK, `{"result":"ok"}`), nil
		}
		return jsonHTTPResponse(http.StatusOK, `{"data":{"unique_key":"other","provider":"slack","display_name":"Slack","logo":"https://app.example.test/images/template-logos/slack.svg","forward_webhooks":true,"created_at":"2026-08-28T12:00:00.000Z","updated_at":"2026-08-28T12:00:00.000Z"}}`), nil
	})
	if err := client.CheckReadiness(context.Background(), readiness); !errors.Is(err, ErrConnection) {
		t.Fatalf("drifted integration readiness accepted: %v", err)
	}
}

func TestConfiguredIntegrationsUsesTheServiceKeyPublicInventory(t *testing.T) {
	const base = "http://nango.connector.svc.cluster.local:3003"
	const secret = "00000000-0000-4000-8000-000000000001"
	payload := `{"data":[{"unique_key":"slack","provider":"slack","display_name":"Slack","forward_webhooks":true},{"unique_key":"my-vault","provider":"1password","display_name":"1Password"}]}`
	status := http.StatusOK
	client, err := newProductionConnectionClientWithHTTP(serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte(secret), nil
	}), &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != base+"/integrations" || request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatal("inventory did not use the environment key at the public list endpoint")
		}
		return jsonHTTPResponse(status, payload), nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	list := func() (map[string]string, error) {
		return client.ConfiguredIntegrations(context.Background(), base, "ref:nango/service-key-0001")
	}
	if configured, err := list(); err != nil || configured["slack"] != "slack" {
		t.Fatalf("supported provider missing: %v", err)
	}
	payload = `{"data":[]}`
	if configured, err := list(); err != nil || len(configured) != 0 {
		t.Fatalf("empty inventory was not respected: %v", err)
	}
	for _, malformed := range []string{
		`{"data":null}`, `{}`, `{"data":[{"unique_key":"slack","provider":"slack","credentials":{}}]}`,
		`{"data":[{"unique_key":"slack","provider":"slack"},{"unique_key":"slack","provider":"gitlab"}]}`,
	} {
		payload = malformed
		if _, err := list(); !errors.Is(err, ErrConnection) {
			t.Fatal("invalid integration inventory accepted")
		}
	}
	status, payload = http.StatusUnauthorized, `{"error":"unauthorized"}`
	if configured, err := list(); !errors.Is(err, ErrConnection) || configured != nil {
		t.Fatalf("refused credentials returned an inventory: %v", err)
	}
}

func TestConfiguredCallbackCanUseThePublishedHTTPSPort(t *testing.T) {
	const path = "/api/v1/integrations/oauth/callback"
	for origin, want := range map[string]bool{"https://zasp.example.test:8443": true, "https://zasp.example.test:": false, "https://zasp.example.test:65536": false, "https://zasp.example.test:0": false, "http://zasp.example.test:8443": false} {
		if ValidPublicCallbackURL(origin+path) != want {
			t.Errorf("callback validation for %s, want %v", origin, want)
		}
	}
}

func TestConnectionMetadataAcceptsOnlyPublicSlackIdentifiers(t *testing.T) {
	for _, test := range []struct {
		provider string
		metadata string
		want     bool
	}{
		{"slack", `{"team.id":"T024BE7LD","bot_user_id":"U024BE7LD"}`, true},
		{"slack", `{"incoming_webhook.url":"https://example.test"}`, false},
		{"slack", `{"team.id":"not an id"}`, false},
		{"gitlab", `{"team.id":"T024BE7LD"}`, false},
		{"gitlab", `{}`, true},
	} {
		if got := validNangoConnectionMetadata(test.provider, json.RawMessage(test.metadata)); got != test.want {
			t.Errorf("%s metadata validity = %t, want %t", test.provider, got, test.want)
		}
	}
}
