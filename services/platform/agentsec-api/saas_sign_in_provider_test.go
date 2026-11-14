package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/platforms"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// saasSignInNango stands in for the Nango connection client.
type saasSignInNango struct {
	starts      []nango.OAuthStartRequest
	completions []nango.OAuthCompleteRequest
	revocations []nango.ConnectionRevocationRequest
	startErr    error
	completeErr error
	connection  nango.Connection
}

func (client *saasSignInNango) StartOAuth(_ context.Context, request nango.OAuthStartRequest) (nango.OAuthAuthorization, error) {
	client.starts = append(client.starts, request)
	if client.startErr != nil {
		return nango.OAuthAuthorization{}, client.startErr
	}
	return nango.OAuthAuthorization{URL: "https://" + request.AuthorizationHost + request.AuthorizationPath + "?state=nango_state_12345678", State: "nango_state_12345678", ExpiresAt: time.Now().UTC().Add(9 * time.Minute)}, nil
}

func (client *saasSignInNango) CompleteOAuth(_ context.Context, request nango.OAuthCompleteRequest) (nango.Connection, error) {
	client.completions = append(client.completions, request)
	return client.connection, client.completeErr
}

func (client *saasSignInNango) RecoverOAuth(context.Context, nango.OAuthCompleteRequest) (nango.Connection, error) {
	return nango.Connection{}, nango.ErrConnectionNotFound
}

func (client *saasSignInNango) RevokeConnection(_ context.Context, request nango.ConnectionRevocationRequest) error {
	client.revocations = append(client.revocations, request)
	return nil
}

func newSaaSSignInProvider(t *testing.T, client *saasSignInNango, proxy *saasProbeProxy) (*saasSignInProvider, apiserver.SaaSSignInRequest) {
	t.Helper()
	registry, err := platforms.Registry()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 3)
	for index := range ids {
		if ids[index], err = domain.ParseProductID("pid_7d00000" + string(rune('1'+index)) + "-0000-4000-8000-000000000001"); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	provider := &saasSignInProvider{registry: registry, client: client, proxy: proxy, baseURL: "http://nango.zasp.svc.cluster.local:3003", serviceSecretReference: "ref:nango/service-key-0001", environment: "prod",
		callbackURL: "https://app.zasp.test/api/v1/integrations/oauth/callback", clock: func() time.Time { return time.Now().UTC() }}
	return provider, apiserver.SaaSSignInRequest{Scope: scope, PrincipalID: "pid_7d000004-0000-4000-8000-000000000001", IntegrationID: "pid_7d000005-0000-4000-8000-000000000001", AttemptID: "pid_7d000006-0000-4000-8000-000000000001", Platform: "servicenow", TenantID: "acme"}
}

func TestSaaSSignInProviderStartsAtThePlatformsOwnAuthorizationPage(t *testing.T) {
	client := &saasSignInNango{}
	provider, request := newSaaSSignInProvider(t, client, &saasProbeProxy{})
	// ServiceNow: the page is on the instance's own host and Nango is given
	// the instance as the connection's subdomain.
	target, err := provider.Start(context.Background(), request)
	if err != nil || target.State != "nango_state_12345678" || target.URL != "https://acme.service-now.com/oauth_auth.do?state=nango_state_12345678" {
		t.Fatalf("target = %+v, %v", target, err)
	}
	start := client.starts[0]
	if start.ConnectorKey != "servicenow" || start.Provider != "" || start.AuthorizationHost != "acme.service-now.com" || start.AuthorizationPath != "/oauth_auth.do" || start.CallbackURL != "https://app.zasp.test/api/v1/integrations/oauth/callback" ||
		len(start.ConnectionParams) != 1 || start.ConnectionParams["subdomain"] != "acme" || start.Binding.IntegrationID != request.IntegrationID || start.Binding.AttemptID != request.AttemptID || start.Binding.OrganizationID != request.Scope.OrganizationID().String() {
		t.Fatalf("Nango start = %+v", start)
	}
	// Google Workspace: one fixed page, no connection parameter.
	google := request
	google.Platform, google.TenantID = "google_workspace", "C03az79cb"
	if _, err := provider.Start(context.Background(), google); err != nil || client.starts[1].ConnectorKey != "google-workspace-admin" || client.starts[1].AuthorizationHost != "accounts.google.com" || client.starts[1].AuthorizationPath != "/o/oauth2/v2/auth" || len(client.starts[1].ConnectionParams) != 0 {
		t.Fatalf("google start = %+v, %v", client.starts[1], err)
	}
	if !provider.Available(context.Background(), "servicenow") || !provider.Available(context.Background(), "slack") || !provider.Available(context.Background(), "gitlab") {
		t.Fatal("a platform with a sign-in is not available")
	}
	// What a sign-in is not started for. Nango is not asked.
	asked := len(client.starts)
	for name, mutate := range map[string]func(*apiserver.SaaSSignInRequest){
		"a platform that takes an API key": func(value *apiserver.SaaSSignInRequest) {
			value.Platform, value.TenantID = "anthropic", "6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b"
		},
		"a platform that is not registered":  func(value *apiserver.SaaSSignInRequest) { value.Platform = "zendesk" },
		"a tenant of another grammar":        func(value *apiserver.SaaSSignInRequest) { value.TenantID = "acme.attacker.net" },
		"a tenant that would leave the host": func(value *apiserver.SaaSSignInRequest) { value.TenantID = "acme.service-now.com" },
		"an attempt that is not a product id": func(value *apiserver.SaaSSignInRequest) {
			value.AttemptID = "attempt"
		},
	} {
		invalid := request
		mutate(&invalid)
		if _, err := provider.Start(context.Background(), invalid); !errors.Is(err, errRuntimeUnavailable) || len(client.starts) != asked {
			t.Fatalf("%s: %v, Nango asked %d times", name, err, len(client.starts)-asked)
		}
	}
	for _, platform := range []string{"anthropic", "openai", "atlassian", "databricks", "zendesk"} {
		if provider.Available(context.Background(), platform) {
			t.Fatalf("%s offers a sign-in", platform)
		}
	}
	client.startErr = nango.ErrConnection
	if _, err := provider.Start(context.Background(), request); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("Nango refusal: %v", err)
	}
}

func TestSaaSSignInProviderKeepsOnlyAConnectionThatReachesTheNamedTenant(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	completion := func(request apiserver.SaaSSignInRequest) apiserver.SaaSSignInCompletion {
		return apiserver.SaaSSignInCompletion{SaaSSignInRequest: request, State: "nango_state_12345678", Code: "provider_code_123"}
	}
	// The instance answers its own name: the connection is kept.
	client := &saasSignInNango{connection: nango.Connection{Reference: reference, ConnectorKey: "servicenow"}}
	proxy := &saasProbeProxy{body: `{"result":[{"name":"instance_name","value":"acme"}]}`}
	provider, request := newSaaSSignInProvider(t, client, proxy)
	got, err := provider.Complete(context.Background(), completion(request))
	if err != nil || got != reference || len(client.revocations) != 0 {
		t.Fatalf("reference = %q, %v, revocations %d", got, err, len(client.revocations))
	}
	if exchange := client.completions[0]; exchange.ConnectorKey != "servicenow" || exchange.State != "nango_state_12345678" || exchange.Code != "provider_code_123" || exchange.Binding.AttemptID != request.AttemptID {
		t.Fatalf("exchange = %+v", exchange)
	}
	// The tenant was asked on the instance's own host, with the reference.
	if len(proxy.calls) != 1 || proxy.calls[0] != "servicenow "+reference+" GET //acme.service-now.com/api/now/table/sys_properties?sysparm_fields=name%2Cvalue&sysparm_limit=1&sysparm_query=name%3Dinstance_name" {
		t.Fatalf("tenant lookup = %v", proxy.calls)
	}

	for name, test := range map[string]struct {
		body       string
		proxyErr   error
		connection nango.Connection
		exchange   error
		want       error
		revoked    int
	}{
		"the person signed in to another instance": {`{"result":[{"name":"instance_name","value":"globex"}]}`, nil, nango.Connection{Reference: reference, ConnectorKey: "servicenow"}, nil, apiserver.ErrSaaSSignInTenantMismatch, 1},
		"the account may not read the instance":    {"", &nango.StatusError{StatusCode: http.StatusForbidden}, nango.Connection{Reference: reference, ConnectorKey: "servicenow"}, nil, apiserver.ErrSaaSSignInTenantMismatch, 1},
		"the instance cannot be reached":           {"", nango.ErrProxy, nango.Connection{Reference: reference, ConnectorKey: "servicenow"}, nil, errRuntimeUnavailable, 1},
		"the instance names no tenant":             {`{"result":[]}`, nil, nango.Connection{Reference: reference, ConnectorKey: "servicenow"}, nil, errRuntimeUnavailable, 1},
		"Nango cannot finish the exchange":         {`{}`, nil, nango.Connection{}, nango.ErrConnection, errRuntimeUnavailable, 0},
		"a connection of another integration":      {`{}`, nil, nango.Connection{Reference: reference, ConnectorKey: "slack"}, nil, errRuntimeUnavailable, 0},
		"something that is not a connection":       {`{}`, nil, nango.Connection{Reference: "ref:nango/service-key-0001", ConnectorKey: "servicenow"}, nil, errRuntimeUnavailable, 0},
	} {
		client := &saasSignInNango{connection: test.connection, completeErr: test.exchange}
		provider, request := newSaaSSignInProvider(t, client, &saasProbeProxy{body: test.body, err: test.proxyErr})
		got, err := provider.Complete(context.Background(), completion(request))
		if !errors.Is(err, test.want) || got != "" || len(client.revocations) != test.revoked {
			t.Fatalf("%s: reference=%q err=%v revocations=%d", name, got, err, len(client.revocations))
		}
		// A connection that is not kept is removed from Nango, bound to
		// this scope and this integration.
		if test.revoked == 1 {
			revocation := client.revocations[0]
			if revocation.ConnectionReference != reference || revocation.ConnectorKey != "servicenow" || revocation.Binding.IntegrationID != request.IntegrationID || revocation.Binding.OrganizationID != request.Scope.OrganizationID().String() {
				t.Fatalf("%s: revocation = %+v", name, revocation)
			}
		}
	}
}
