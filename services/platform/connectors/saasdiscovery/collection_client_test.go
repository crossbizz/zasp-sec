package saasdiscovery_test

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// acme is a platform that exists only in this test. It uses every paging
// style and every entity kind, so the framework is proven without a real
// provider.
func acme() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "acme", DisplayName: "Acme AI", Description: "Inventory the agents, AI apps and MCP servers of one Acme account.",
		Nango: nango.Entry{Key: "acme", ProviderHost: "api.acme.example", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/v1/account"},
			{Method: http.MethodGet, PathPrefix: "/v1/agents", QueryKeys: []string{"page_size", "page_token"}},
			{Method: http.MethodGet, PathPrefix: "/v1/apps", QueryKeys: []string{"limit", "offset"}},
			{Method: http.MethodGet, PathPrefix: "/v1/mcp-servers", QueryKeys: []string{"per_page", "after"}},
			{Method: http.MethodGet, PathPrefix: "/v1/copilots"},
		}},
		RequiredScopes: []string{"agents:read", "apps:read"}, TenantLabel: "Account ID", TenantHint: "The account id shown in Acme settings.", TenantPattern: regexp.MustCompile(`^acct-[0-9]{1,12}$`),
		AccessGuidance: "Authorize a read-only Acme connection in Nango.",
		Failure: func(document saasdiscovery.Item) (collection.FailureCode, bool) {
			switch document.Text("error") {
			case "":
				return "", false
			case "slow_down":
				return collection.FailureRateLimited, true
			}
			return collection.FailureDenied, true
		},
		Tenant: saasdiscovery.TenantLookup{Path: "/v1/account", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("account", "id"), Name: document.Text("account", "name")}, document.Has("account", "id")
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "agents", Path: "/v1/agents", ItemsPath: []string{"agents"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "page_token", NextPath: []string{"next_page_token"}, LimitParam: "page_size", PageSize: 2},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					if item.Text("kind") != "agent" {
						return saasdiscovery.Entity{}, false
					}
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: item.Text("id"), DisplayName: saasdiscovery.CleanText(item.Text("name"), 256), ObjectType: "agent", Status: item.Text("state"), Model: item.Text("model"),
						Posture: agentsignals.Posture{CredentialActive: item.Text("state") == "ACTIVE", UntrustedInput: item.Bool("public")}}, true
				}},
			{Name: "apps", Path: "/v1/apps", ItemsPath: []string{"data"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingOffset, OffsetParam: "offset", LimitParam: "limit", PageSize: 2},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					var evidence agentsignals.Evidence
					category := evidence.Application(item.Text("name"))
					if category == "" {
						return saasdiscovery.Entity{}, false
					}
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: item.Text("id"), DisplayName: saasdiscovery.CleanText(item.Text("name"), 256), ObjectType: "app", Status: "installed", AgentType: category, Signals: evidence.Signals()}, true
				}},
			{Name: "mcp_servers", Path: "/v1/mcp-servers", Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingLink, LimitParam: "per_page", PageSize: 1},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					return saasdiscovery.Entity{Kind: saasdiscovery.KindMCPServer, NativeID: item.Text("id"), DisplayName: item.Text("label"), ObjectType: "mcp_server", Status: "registered", EndpointHost: item.Text("host")}, true
				}},
			{Name: "copilots", Path: "/v1/copilots", ItemsPath: []string{"copilots"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Absent: []int{http.StatusNotFound},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: item.Text("id"), DisplayName: item.Text("name"), ObjectType: "copilot", Status: "enabled"}, true
				}},
		},
	}
}

func acmeRegistry(t *testing.T) (*saasdiscovery.Registry, saasdiscovery.Platform) {
	t.Helper()
	platform := acme()
	registry, err := saasdiscovery.NewRegistry(platform)
	if err != nil {
		t.Fatalf("fake platform definition refused: %v", err)
	}
	return registry, platform
}

const acmeAccount = `{"account":{"id":"acct-42","name":"Acme Corp"}}`

func acmeRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/v1/account": saastest.Static(acmeAccount),
		"/v1/agents": func(query url.Values, _ int) saastest.Response {
			switch query.Get("page_token") {
			case "":
				return saastest.Response{Body: `{"agents":[{"id":"ag_1","name":"  Support Agent ","kind":"agent","state":"ACTIVE","model":"gpt-4o","public":true},{"id":"wf_1","name":"Nightly export","kind":"workflow","state":"ACTIVE"}],"next_page_token":"tok-2"}`}
			case "tok-2":
				return saastest.Response{Body: `{"agents":[{"id":"ag_2","name":"Sales Coach","kind":"agent","state":"PAUSED"}],"next_page_token":""}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/v1/apps": func(query url.Values, _ int) saastest.Response {
			switch query.Get("offset") {
			case "0":
				return saastest.Response{Body: `{"data":[{"id":"app_1","name":"ChatGPT for Acme"},{"id":"app_2","name":"Calendar"}]}`}
			case "2":
				return saastest.Response{Body: `{"data":[{"id":"app_3","name":"Glean"}]}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/v1/mcp-servers": func(query url.Values, _ int) saastest.Response {
			if query.Get("after") == "" {
				return saastest.Response{Body: `[{"id":"mcp_1","label":"Docs search","host":"mcp.docs.example"}]`, Link: `<https://api.acme.example/v1/mcp-servers?after=mcp_1&per_page=1>; rel="next", <https://api.acme.example/v1/mcp-servers?per_page=1>; rel="first"`}
			}
			return saastest.Response{Body: `[{"id":"mcp_2","label":"Tickets"}]`}
		},
	}
}

// B1/B2: a platform that is only a definition is collected end to end,
// through the allow-listed adapter, the production proxy client and a
// stand-in Nango, to a typed snapshot of the generic saas provider.
func TestFakePlatformIsCollectedThroughAStandInNangoToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := acmeRegistry(t)
	standIn := saastest.NewNango(t, registry, acmeRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, "acct-42")

	if tenants, agents, apps, servers := snapshot.Kind("saas_tenant"), snapshot.Kind("saas_agent"), snapshot.Kind("saas_ai_application"), snapshot.Kind("saas_mcp_server"); len(tenants) != 1 || len(agents) != 2 || len(apps) != 2 || len(servers) != 2 || len(snapshot.Relationships) != 6 {
		t.Fatalf("tenants=%d agents=%d apps=%d servers=%d relationships=%d: %s", len(tenants), len(agents), len(apps), len(servers), len(snapshot.Relationships), snapshot.Raw)
	}
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "Acme Corp" || tenant.SourceNativeID != "saas:acme:tenant:acct-42" || !reflect.DeepEqual(tenant.StableFields, map[string]any{"name": "Acme Corp", "platform": "acme", "tenant": "acct-42"}) || len(tenant.Attributes) != 0 {
		t.Fatalf("tenant = %+v", tenant)
	}
	agent := snapshot.Named(t, "saas_agent", "Support Agent")
	posture := agent.Attributes["posture"].(map[string]any)
	if agent.SourceNativeID != "saas:acme:agent:ag_1" || agent.Attributes["status"] != "ACTIVE" || agent.Attributes["model"] != "gpt-4o" || posture["credential_active"] != true || posture["untrusted_input"] != true || posture["shell_execution"] != false ||
		!reflect.DeepEqual(agent.StableFields, map[string]any{"name": "Support Agent", "object_type": "agent", "platform": "acme", "tenant": "acct-42"}) {
		t.Fatalf("agent = %+v", agent)
	}
	if paused := snapshot.Named(t, "saas_agent", "Sales Coach"); paused.Attributes["posture"].(map[string]any)["credential_active"] != false || paused.Attributes["model"] != nil {
		t.Fatalf("paused agent = %+v", paused)
	}
	application := snapshot.Named(t, "saas_ai_application", "ChatGPT for Acme")
	if discovery := application.Attributes["discovery"].(map[string]any); !reflect.DeepEqual(discovery["signals"], []any{"app:chatgpt"}) || application.Attributes["agent_type"] != "assistant" {
		t.Fatalf("application = %+v", application)
	}
	if server := snapshot.Named(t, "saas_mcp_server", "Docs search"); server.Attributes["endpoint_host"] != "mcp.docs.example" || server.Attributes["posture"] != nil || server.Attributes["discovery"] != nil {
		t.Fatalf("mcp server = %+v", server)
	}
	if !strings.Contains(string(snapshot.Raw), `"attributes":{"discovery":{"method":"provider_api","platform":"acme","signals":[]},"model":"gpt-4o","posture":{`) {
		t.Fatalf("agent attributes are not in canonical order: %s", snapshot.Raw)
	}

	// One provider request per page, each within the platform's proxy rules,
	// each naming the platform's Nango key.
	want := []string{"/v1/account?", "/v1/agents?page_size=2", "/v1/agents?page_size=2&page_token=tok-2", "/v1/apps?limit=2&offset=0", "/v1/apps?limit=2&offset=2", "/v1/mcp-servers?per_page=1", "/v1/mcp-servers?after=mcp_1&per_page=1", "/v1/copilots?"}
	var got []string
	for _, call := range standIn.Calls() {
		if call.Key != "acme" {
			t.Fatalf("call %s used Nango key %q", call.Path, call.Key)
		}
		got = append(got, call.Path+"?"+call.Query.Encode())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("provider requests\n got %v\nwant %v", got, want)
	}
}

func failureCode(t *testing.T, err error) collection.FailureCode {
	t.Helper()
	var failure *collection.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error is not a collection failure: %v", err)
	}
	return failure.Code()
}

// B2: provider refusals reach the pipeline as its existing failure classes.
func TestProviderFailuresMapToTheCollectionFailureClasses(t *testing.T) {
	t.Parallel()
	registry, platform := acmeRegistry(t)
	for name, test := range map[string]struct {
		path  string
		route saastest.Route
		want  collection.FailureCode
	}{
		"rate limit with Retry-After": {"/v1/agents", func(url.Values, int) saastest.Response {
			return saastest.Response{Status: 429, RetryAfter: "30", Body: `{}`}
		}, collection.FailureRateLimited},
		"rate limit inside a 200":      {"/v1/agents", saastest.Static(`{"error":"slow_down"}`), collection.FailureRateLimited},
		"denied":                       {"/v1/agents", func(url.Values, int) saastest.Response { return saastest.Response{Status: 403, Body: `{}`} }, collection.FailureDenied},
		"denied inside a 200":          {"/v1/apps", saastest.Static(`{"error":"missing_scope"}`), collection.FailureDenied},
		"revoked connection":           {"/v1/account", func(url.Values, int) saastest.Response { return saastest.Response{Status: 401, Body: `{}`} }, collection.FailureDenied},
		"provider outage":              {"/v1/apps", func(url.Values, int) saastest.Response { return saastest.Response{Status: 503, Body: `{}`} }, collection.FailureRetryable},
		"unknown client error":         {"/v1/apps", func(url.Values, int) saastest.Response { return saastest.Response{Status: 410, Body: `{}`} }, collection.FailureTerminal},
		"not JSON":                     {"/v1/agents", saastest.Static(`<html>`), collection.FailureMalformed},
		"items are not an array":       {"/v1/agents", saastest.Static(`{"agents":{"id":"ag_1"}}`), collection.FailureMalformed},
		"an item is not an object":     {"/v1/agents", saastest.Static(`{"agents":["ag_1"]}`), collection.FailureMalformed},
		"an entity without an id":      {"/v1/agents", saastest.Static(`{"agents":[{"name":"No id","kind":"agent","state":"ACTIVE"}]}`), collection.FailureMalformed},
		"a repeated item":              {"/v1/agents", saastest.Static(`{"agents":[{"id":"a","name":"A","kind":"agent","state":"ACTIVE"},{"id":"a","name":"A","kind":"agent","state":"ACTIVE"}]}`), collection.FailureMalformed},
		"a cursor that never advances": {"/v1/agents", saastest.Static(`{"agents":[],"next_page_token":"same"}`), collection.FailureMalformed},
		"a next link to another path": {"/v1/mcp-servers", func(url.Values, int) saastest.Response {
			return saastest.Response{Body: `[]`, Link: `</v1/admin/tokens?after=1>; rel="next"`}
		}, collection.FailureMalformed},
		"a connection of another tenant": {"/v1/account", saastest.Static(`{"account":{"id":"acct-43","name":"Other"}}`), collection.FailureDenied},
		"a tenant id of another grammar": {"/v1/account", saastest.Static(`{"account":{"id":"../acct-42","name":"Other"}}`), collection.FailureMalformed},
		// The proxy refuses a response that carries token material; the
		// collection is retried and nothing of the body is stored.
		"a response that carries a token": {"/v1/agents", saastest.Static(`{"agents":[{"id":"ag_1","name":"A","kind":"agent","state":"ACTIVE","access_token":"` + saastest.ProviderToken + `"}]}`), collection.FailureRetryable},
	} {
		routes := acmeRoutes()
		routes[test.path] = test.route
		standIn := saastest.NewNango(t, registry, routes)
		outcome, err := saastest.Run(t, standIn, registry, platform, "acct-42")
		if _, complete := outcome.(collection.CompleteResult); complete || err == nil {
			t.Fatalf("%s: collection completed: %T, %v", name, outcome, err)
		}
		if got := failureCode(t, err); got != test.want {
			t.Fatalf("%s: failure = %s, want %s", name, got, test.want)
		}
		if test.want == collection.FailureRateLimited {
			var failure *collection.Failure
			if errors.As(err, &failure); failure.RetryAt().IsZero() {
				t.Fatalf("%s: no retry time", name)
			}
		}
	}
}

// A request outside the platform's own proxy rules is never sent.
func TestCollectorCannotLeaveThePlatformsProxyRules(t *testing.T) {
	t.Parallel()
	platform := acme()
	// The definition asks for a query parameter its rule does not list.
	platform.Nango.Rules[1].QueryKeys = []string{"page_size"}
	if _, err := saasdiscovery.NewRegistry(platform); !errors.Is(err, saasdiscovery.ErrInvalid) {
		t.Fatalf("definition whose endpoint is outside its rules: %v", err)
	}
	// A Link header may name parameters the rule does not list; the adapter
	// refuses the request and the collection ends without sending it.
	registry, platform := acmeRegistry(t)
	routes := acmeRoutes()
	routes["/v1/mcp-servers"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Body: `[{"id":"mcp_1","label":"Docs search"}]`, Link: `</v1/mcp-servers?admin=true&per_page=1>; rel="next"`}
	}
	standIn := saastest.NewNango(t, registry, routes)
	_, err := saastest.Run(t, standIn, registry, platform, "acct-42")
	if got := failureCode(t, err); got != collection.FailureTerminal {
		t.Fatalf("failure = %s", got)
	}
	for _, call := range standIn.Calls() {
		if call.Query.Get("admin") != "" {
			t.Fatalf("request outside the proxy rules was sent: %v", call)
		}
	}
}

func TestPlatformDefinitionsAreValidated(t *testing.T) {
	t.Parallel()
	if _, err := saasdiscovery.NewRegistry(acme(), acme()); !errors.Is(err, saasdiscovery.ErrInvalid) {
		t.Fatalf("repeated platform: %v", err)
	}
	for name, mutate := range map[string]func(*saasdiscovery.Platform){
		"upper-case token":              func(platform *saasdiscovery.Platform) { platform.Token = "Acme" },
		"no tenant pattern":             func(platform *saasdiscovery.Platform) { platform.TenantPattern = nil },
		"no tenant mapping":             func(platform *saasdiscovery.Platform) { platform.Tenant.Map = nil },
		"no scopes":                     func(platform *saasdiscovery.Platform) { platform.RequiredScopes = nil },
		"no list endpoint":              func(platform *saasdiscovery.Platform) { platform.Lists = nil },
		"a write rule":                  func(platform *saasdiscovery.Platform) { platform.Nango.Rules[0].Method = http.MethodPost },
		"an endpoint without a rule":    func(platform *saasdiscovery.Platform) { platform.Lists[0].Path = "/v1/secrets" },
		"an endpoint without a mapping": func(platform *saasdiscovery.Platform) { platform.Lists[0].Map = nil },
		"a repeated endpoint name":      func(platform *saasdiscovery.Platform) { platform.Lists[1].Name = "agents" },
		"a reserved endpoint name":      func(platform *saasdiscovery.Platform) { platform.Lists[1].Name = "tenant" },
		"cursor paging without a path":  func(platform *saasdiscovery.Platform) { platform.Lists[0].Paging.NextPath = nil },
		"offset paging without a limit": func(platform *saasdiscovery.Platform) {
			platform.Lists[1].Paging.LimitParam, platform.Lists[1].Paging.PageSize = "", 0
		},
		"a page size above the bound": func(platform *saasdiscovery.Platform) { platform.Lists[0].Paging.PageSize = 5000 },
		"an unknown paging style":     func(platform *saasdiscovery.Platform) { platform.Lists[3].Paging.Style = "graphql" },
		"a 500 declared as absent":    func(platform *saasdiscovery.Platform) { platform.Lists[3].Absent = []int{500} },
		"an IP provider host":         func(platform *saasdiscovery.Platform) { platform.Nango.ProviderHost = "10.0.0.1" },
	} {
		platform := acme()
		mutate(&platform)
		if err := platform.Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Fatalf("%s: definition accepted", name)
		}
		if _, err := saasdiscovery.NewRegistry(platform); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Fatalf("%s: registry accepted", name)
		}
	}
}
