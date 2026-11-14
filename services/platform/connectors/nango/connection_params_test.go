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

// A sign-in to a provider whose addresses differ per tenant: the connection
// parameter reaches Nango, the authorization page must be on the tenant's
// host, and a connection of an integration whose provider template is not
// known is still bound to its integration key, end user and organization.
func TestConnectionClientStartsAPerTenantSignInAndBindsTheConnectionWithoutATemplateName(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	binding := ConnectionBinding{
		OrganizationID: "pid_11111111-1111-4111-8111-111111111111", WorkspaceID: "pid_22222222-2222-4222-8222-222222222222",
		EnvironmentID: "pid_33333333-3333-4333-8333-333333333333", IntegrationID: "pid_44444444-4444-4444-8444-444444444444", AttemptID: "pid_55555555-5555-4555-8555-555555555555",
	}
	const token = "nango_connect_session_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	location := "https://acme.service-now.com/oauth_auth.do?client_id=client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fapi%2Fv1%2Fintegrations%2Foauth%2Fcallback&state=nango_state_12345678"
	provider := "servicenow"
	var connectURLs []string
	client, err := newProductionConnectionClientWithHTTP(serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	}), &http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			switch {
			case request.URL.Path == "/api/v1/connect/sessions":
				return jsonHTTPResponse(http.StatusCreated, `{"data":{"token":"`+token+`","connect_link":"http://nango.connector.svc.cluster.local:3003/connect?session_token=`+token+`","expires_at":"2026-11-14T12:20:00.000Z"}}`), nil
			case strings.HasPrefix(request.URL.Path, "/oauth/connect/"):
				connectURLs = append(connectURLs, request.URL.String())
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{location}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			case request.URL.Path == "/connection":
				payload := map[string]any{"connections": []any{map[string]any{
					"id": 7, "connection_id": "11111111-1111-4111-8111-111111111111", "provider_config_key": "servicenow", "provider": provider, "errors": []any{}, "metadata": nil, "created": "2026-11-14T12:00:01.000Z",
					"end_user": map[string]any{"id": nangoEndUserID(binding), "display_name": nil, "email": nil, "tags": map[string]any{"origin": "nango_dashboard"}, "organization": map[string]any{"id": nangoOrganizationID(binding), "display_name": nil}},
					"tags":     map[string]any{"end_user_id": nangoEndUserID(binding), "organization_id": nangoOrganizationID(binding), "origin": "nango_dashboard"},
				}}}
				encoded, _ := json.Marshal(payload)
				return jsonHTTPResponse(http.StatusOK, string(encoded)), nil
			}
			t.Fatalf("unexpected request %s", request.URL)
			return nil, nil
		}),
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	start := OAuthStartRequest{NangoBaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "servicenow", AuthorizationHost: "acme.service-now.com", AuthorizationPath: "/oauth_auth.do", CallbackURL: "https://app.example.test/api/v1/integrations/oauth/callback",
		Binding: binding, ConnectionParams: map[string]string{"subdomain": "acme"}}
	authorization, err := client.StartOAuth(context.Background(), start)
	if err != nil || authorization.URL != location || authorization.State != "nango_state_12345678" {
		t.Fatalf("authorization = %+v, %v", authorization, err)
	}
	if len(connectURLs) != 1 || connectURLs[0] != "http://nango.connector.svc.cluster.local:3003/oauth/connect/servicenow?connect_session_token="+token+"&params%5Bsubdomain%5D=acme" {
		t.Fatalf("connect request = %v", connectURLs)
	}
	// Nango sends the browser to another tenant's host, or to another
	// provider: the sign-in is refused.
	for _, other := range []string{"https://globex.service-now.com/oauth_auth.do", "https://acme.service-now.com.attacker.net/oauth_auth.do", "https://acme.service-now.com/other"} {
		location = other + "?client_id=client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fapi%2Fv1%2Fintegrations%2Foauth%2Fcallback&state=nango_state_12345678"
		if _, err := client.StartOAuth(context.Background(), start); !errors.Is(err, ErrConnection) {
			t.Fatalf("authorization page %s: %v", other, err)
		}
	}
	// Connection parameters that are not plain names and values never reach
	// Nango.
	connectURLs = nil
	for name, params := range map[string]map[string]string{
		"a name with brackets": {"sub][domain": "acme"}, "a value with a line break": {"subdomain": "acme\nx"}, "an empty value": {"subdomain": ""},
		"too many": {"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
	} {
		invalid := start
		invalid.ConnectionParams = params
		if _, err := client.StartOAuth(context.Background(), invalid); !errors.Is(err, ErrInvalid) || len(connectURLs) != 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// The connection Nango created is found by the end user of this sign-in.
	// Its provider template is not compared when the caller names none, and
	// is compared when the caller names one.
	recovery := OAuthCompleteRequest{NangoBaseURL: start.NangoBaseURL, ServiceSecretReference: start.ServiceSecretReference, Environment: start.Environment, ConnectorKey: "servicenow", Binding: binding}
	provider = "service-now"
	connection, err := client.RecoverOAuth(context.Background(), recovery)
	if err != nil || connection.Reference != "ref:nango/connection/11111111-1111-4111-8111-111111111111" || connection.ConnectorKey != "servicenow" {
		t.Fatalf("connection = %+v, %v", connection, err)
	}
	recovery.Provider = "servicenow"
	if _, err := client.RecoverOAuth(context.Background(), recovery); !errors.Is(err, ErrConnection) {
		t.Fatalf("a connection of another template: %v", err)
	}
	// A connection of another integration key is never accepted.
	recovery.Provider, recovery.ConnectorKey = "", "slack"
	if _, err := client.RecoverOAuth(context.Background(), recovery); !errors.Is(err, ErrConnection) {
		t.Fatalf("a connection of another integration: %v", err)
	}
}
