package platforms

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// Atlassian lists the AI applications installed on one Atlassian Cloud site
// (<site>.atlassian.net): the installed applications whose name is in the
// reviewed application catalog, and the ones whose key says they are Rovo.
//
// The API host differs per site. The tenant id is the site name and every
// request is sent to that site's host only.
//
// Rovo agents come from two places, and the definition reads both.
//
// Agents an installed app ships. A Forge app declares an agent as a
// rovo:agent module, and Atlassian's GraphQL gateway lists the modules
// (extensions) installed on a site by type. That read is open to an API
// token, so it is the one that finds agents today: for the site's Jira and
// Confluence contexts the definition asks for the extensions of type
// rovo:agent and records the module's name and key and the app it belongs
// to. The module's properties, which hold the agent's prompt, are not
// selected.
//
// Agents people build in Rovo Studio. The gateway field
// agentStudio_getAgents lists them, and the definition asks it for the id,
// the name and whether the agent is deactivated. Atlassian's published
// schema says who may call it: its edges and pageInfo are callable with a
// browser session only, not with an API token and not with OAuth, and no
// public API exists yet (the requests ROVO-516 and ROVO-479 are open,
// https://jira.atlassian.com/browse/ROVO-516). An API token is the only
// credential this connection can hold, so today this list is expected to be
// refused: the answer carries GraphQL errors, the list is then empty and
// the rest of the site is collected. The query is kept, in the form the
// schema gives it, so that the agents appear when Atlassian opens the field
// to API tokens; until then Studio-built agents are not found, and "no
// Studio agent listed" does not mean the site has none.
//
// DOCUMENTED: https://www.npmjs.com/package/@atlassian/forge-graphql-types
// (4.3.0, Atlassian's types generated from the gateway schema):
//   - Query.agentStudio_getAgents(cloudId: String!, first: Int, after:
//     String) answers AgentStudioAgentsConnection {edges {node}, pageInfo};
//     a node is an AgentStudioAssistant with id, name and deactivated; the
//     field is experimental and needs the directive @optIn(to:
//     "AgentStudio"); edges and pageInfo are marked SESSION yes, API_TOKEN
//     no, FIRST_PARTY_OAUTH no, THIRD_PARTY_OAUTH no;
//   - Query.extensionContext(contextId: ID!) answers an ExtensionContext
//     whose extensionsByType(type: String!) is marked API_TOKEN yes and
//     lists Extension {id, key, name, appId, environmentType, type};
//   - a site's context ids are ari:cloud:jira::site/{cloudId} and
//     ari:cloud:confluence::site/{cloudId} (the examples of
//     @atlassian/forge-graphql 16.4.0);
//   - https://developer.atlassian.com/platform/forge/manifest-reference/modules/rovo-agent/
//     (as returned by a web search): rovo:agent is the Forge module of an
//     agent, with key, name, prompt and actions.
//
// UNVERIFIED (not run against a site):
//   - GET /_edge/tenant_info answers {"cloudId":"<uuid>"} for the site;
//   - POST /gateway/api/graphql on the site host accepts the API token of
//     the jira-basic connection;
//   - that extensionsByType lists a module of type rovo:agent under the Jira
//     or Confluence site context and not only under a Rovo context.
//
// UNVERIFIED: the paths and the response members below are written from
// memory of the Jira Cloud REST API and of the Universal Plugin Manager and
// have not been run against a real site. Before the first production use,
// check against a site:
//   - GET /rest/api/3/serverInfo answers
//     {"baseUrl":"https://<site>.atlassian.net","serverTitle":"…"};
//   - GET /rest/plugins/1.0/ answers {"plugins":[{"key":"…","name":"…",
//     "enabled":true,"userInstalled":true}]} for a site administrator, in
//     one response of less than 1 MiB;
//   - the plugin list is not reachable with an OAuth 2.0 (3LO) token, which
//     is why the connection is an API token of an administrator (the Nango
//     integration jira-basic, with the site as its subdomain) and why this
//     platform has no sign-in from the product.
func Atlassian() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "atlassian", DisplayName: "Atlassian",
		Description: "Inventory the AI applications and Rovo applications installed on one Atlassian Cloud site through a Nango connection.",
		Nango: nango.Entry{Key: "jira-basic", AuthMode: "api_key",
			HostPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}\.atlassian\.net$`), HostSuffixes: []string{".atlassian.net"},
			Rules: []nango.Rule{
				{Method: http.MethodGet, PathPrefix: "/rest/api/3/serverInfo"},
				{Method: http.MethodGet, PathPrefix: "/rest/plugins/1.0/"},
				{Method: http.MethodGet, PathPrefix: "/_edge/tenant_info"},
				{Method: http.MethodPost, PathPrefix: "/gateway/api/graphql", GraphQLDocuments: []string{atlassianRovoAgentsQuery, atlassianRovoModulesQuery}},
			}},
		HostTemplate:   "{tenant}.atlassian.net",
		RequiredScopes: []string{"site-administrator"},
		TenantLabel:    "Site name", TenantHint: "The first part of the site address: acme for acme.atlassian.net.",
		TenantPattern:  regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}$`),
		AccessGuidance: "Create the Nango connection with the email address and an API token of a site administrator. The product never receives the token; it reads the list of installed applications only.",
		Tenant: saasdiscovery.TenantLookup{Path: "/rest/api/3/serverInfo", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			base, err := url.Parse(document.Text("baseUrl"))
			if err != nil || base.Scheme != "https" || base.Port() != "" {
				return saasdiscovery.Tenant{}, false
			}
			site, isCloud := strings.CutSuffix(strings.ToLower(base.Hostname()), ".atlassian.net")
			return saasdiscovery.Tenant{ID: site, Name: site + ".atlassian.net"}, isCloud && site != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "apps", Path: "/rest/plugins/1.0/", ItemsPath: []string{"plugins"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Map: atlassianApplication},
			atlassianRovoModules("rovo_jira_modules", "jira"),
			atlassianRovoModules("rovo_confluence_modules", "confluence"),
			{Name: "rovo_agents", Path: "/gateway/api/graphql", ItemsPath: []string{"data", "agentStudio_getAgents", "edges"},
				GraphQL: &saasdiscovery.GraphQL{Document: atlassianRovoAgentsQuery, Variables: map[string]string{"cloudId": saasdiscovery.ParentValue}, ErrorsAbsent: true},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LimitParam: "first", PageSize: 50,
					NextPath: []string{"data", "agentStudio_getAgents", "pageInfo", "endCursor"}, MorePath: []string{"data", "agentStudio_getAgents", "pageInfo", "hasNextPage"}},
				// A site without the gateway route, or one that refuses the
				// token there, lists no agents.
				Absent: []int{http.StatusNotFound, http.StatusForbidden},
				Parent: atlassianCloudID(),
				MapChild: func(_ string, edge saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					node := edge.Object("node")
					id, name := node.Text("id"), saasdiscovery.CleanText(node.Text("name"), 256)
					if id == "" || name == "" {
						return saasdiscovery.Entity{}, false
					}
					status := "active"
					if node.Bool("deactivated") {
						status = "deactivated"
					}
					var evidence agentsignals.Evidence
					evidence.Surface("rovo")
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: "rovo_agent", Status: status, AgentType: "enterprise_agent",
						Posture: agentsignals.Posture{CredentialActive: status == "active"}, Signals: evidence.Signals()}, true
				}},
		},
	}
}

// atlassianRovoAgentsQuery lists the agents built in Rovo Studio on one site,
// a page at a time, in the form Atlassian's schema gives the field. See
// Atlassian for who may call it.
const atlassianRovoAgentsQuery = `query($cloudId: String!, $first: Int!, $after: String) { agentStudio_getAgents(cloudId: $cloudId, first: $first, after: $after) @optIn(to: "AgentStudio") { edges { node { id name deactivated } } pageInfo { hasNextPage endCursor } } }`

// atlassianRovoModulesQuery lists the rovo:agent modules of the apps
// installed in one context of a site (its Jira or its Confluence). The
// module's properties, which hold its prompt, are not selected.
const atlassianRovoModulesQuery = `query($context: ID!) { extensionContext(contextId: $context) { extensionsByType(type: "rovo:agent") { id key name appId environmentType } } }`

// atlassianCloudID is the one request that states the site's cloud id, by
// which the gateway queries name the site.
func atlassianCloudID() *saasdiscovery.ParentList {
	return &saasdiscovery.ParentList{Path: "/_edge/tenant_info", Single: true, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, ID: func(item saasdiscovery.Item) string { return item.Text("cloudId") }}
}

// atlassianRovoModules lists the agents that apps installed in one product
// of the site ship as rovo:agent modules. An app installed in both products
// is listed for each: the entity is the module in that product.
func atlassianRovoModules(name, product string) saasdiscovery.ListEndpoint {
	return saasdiscovery.ListEndpoint{Name: name, Path: "/gateway/api/graphql", ItemsPath: []string{"data", "extensionContext", "extensionsByType"},
		GraphQL: &saasdiscovery.GraphQL{Document: atlassianRovoModulesQuery, Variables: map[string]string{"context": "ari:cloud:" + product + "::site/" + saasdiscovery.ParentValue}, ErrorsAbsent: true},
		Paging:  saasdiscovery.Paging{Style: saasdiscovery.PagingNone},
		// A site without the gateway route, or one that refuses the token
		// there, lists no module.
		Absent: []int{http.StatusNotFound, http.StatusForbidden},
		Parent: atlassianCloudID(),
		MapChild: func(_ string, extension saasdiscovery.Item) (saasdiscovery.Entity, bool) {
			id := extension.Text("id")
			display := saasdiscovery.CleanText(extension.Text("name"), 256)
			if display == "" {
				display = saasdiscovery.CleanText(extension.Text("key"), 256)
			}
			if id == "" || display == "" {
				return saasdiscovery.Entity{}, false
			}
			// DEVELOPMENT, STAGING or PRODUCTION: the environment of the
			// app the module was installed from.
			status := "installed"
			switch environment := strings.ToLower(extension.Text("environmentType")); environment {
			case "development", "staging", "production":
				status = environment
			}
			var evidence agentsignals.Evidence
			evidence.Surface("rovo")
			evidence.Surface("marketplace_app")
			return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: display, ObjectType: product + "_rovo_agent", Status: status, AgentType: "enterprise_agent",
				// An installed module can be invoked on the site.
				Posture: agentsignals.Posture{CredentialActive: true}, Signals: evidence.Signals()}, true
		},
	}
}

func atlassianApplication(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	key := item.Text("key")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if key == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	var evidence agentsignals.Evidence
	category := evidence.Application(name)
	lowerKey := strings.ToLower(key)
	// Atlassian's own Rovo applications carry rovo in their key.
	if strings.Contains(lowerKey, "rovo") {
		evidence.Surface("rovo")
		if category == "" {
			category = "enterprise_agent"
		}
	}
	if len(evidence.Signals()) == 0 {
		// Not an AI application: it stays out of the inventory.
		return saasdiscovery.Entity{}, false
	}
	if item.Bool("userInstalled") {
		evidence.Surface("marketplace_app")
	}
	enabled := item.Bool("enabled")
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return saasdiscovery.Entity{
		Kind: saasdiscovery.KindAIApplication, NativeID: key, DisplayName: name, ObjectType: "app", Status: status, AgentType: category,
		// The one posture fact the list states: the application is enabled.
		Posture: agentsignals.Posture{CredentialActive: enabled},
		Signals: evidence.Signals(),
	}, true
}
