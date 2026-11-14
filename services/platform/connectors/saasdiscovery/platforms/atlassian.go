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
// Rovo agents. Atlassian documents no public API that lists the Rovo agents
// of a site: the requests for one are open (ROVO-516 "Public APIs for Rovo
// Agent Management", ROVO-479 "Enable Forge app access to Rovo Agent Studio
// GraphQL API", https://jira.atlassian.com/browse/ROVO-516). What exists is
// a field of Atlassian's GraphQL gateway, agentStudio_getAgents, which the
// Agent Studio web application uses. It refuses OAuth 2.0 (3LO) and Forge
// clients ("third party oauth clients not allowed"); no scope covers it.
// This connection is not such a client: it is the API token of a site
// administrator, sent to the site's own gateway.
//
// The definition therefore asks that field, as the last list, with one
// allow-listed query that reads the id and the name of each agent and
// nothing else (no instructions, no knowledge sources). The query is a
// guess at an undocumented schema and is treated as one: an answer that
// carries GraphQL errors, or a gateway that answers 404, lists no agents and
// the collection completes with the installed applications. Until the query
// has been run against a real site, read "Rovo agents: none" as "unknown".
//
// UNVERIFIED, all of the Rovo agent read:
//   - GET /_edge/tenant_info answers {"cloudId":"<uuid>"} for the site;
//   - POST /gateway/api/graphql on the site host accepts the API token;
//   - agentStudio_getAgents takes cloudId, first and after and answers a
//     connection of edges whose node has id and name, with pageInfo
//     {hasNextPage, endCursor};
//   - whether the field needs an X-ExperimentalApi opt-in header.
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
				{Method: http.MethodPost, PathPrefix: "/gateway/api/graphql", GraphQLDocuments: []string{atlassianRovoAgentsQuery}},
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
			{Name: "rovo_agents", Path: "/gateway/api/graphql", ItemsPath: []string{"data", "agentStudio_getAgents", "edges"},
				GraphQL: &saasdiscovery.GraphQL{Document: atlassianRovoAgentsQuery, Variables: map[string]string{"cloudId": saasdiscovery.ParentValue}, ErrorsAbsent: true},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LimitParam: "first", PageSize: 50,
					NextPath: []string{"data", "agentStudio_getAgents", "pageInfo", "endCursor"}, MorePath: []string{"data", "agentStudio_getAgents", "pageInfo", "hasNextPage"}},
				// A site without the gateway route, or one that refuses the
				// token there, lists no agents.
				Absent: []int{http.StatusNotFound, http.StatusForbidden},
				// The query names the site by its cloud id, which only the
				// site states.
				Parent: &saasdiscovery.ParentList{Path: "/_edge/tenant_info", Single: true, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, ID: func(item saasdiscovery.Item) string { return item.Text("cloudId") }},
				MapChild: func(_ string, edge saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					node := edge.Object("node")
					id, name := node.Text("id"), saasdiscovery.CleanText(node.Text("name"), 256)
					if id == "" || name == "" {
						return saasdiscovery.Entity{}, false
					}
					var evidence agentsignals.Evidence
					evidence.Surface("rovo")
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: "rovo_agent", Status: "listed", AgentType: "enterprise_agent", Signals: evidence.Signals()}, true
				}},
		},
	}
}

// atlassianRovoAgentsQuery lists the Rovo agents of one site, a page at a
// time. UNVERIFIED: see Atlassian.
const atlassianRovoAgentsQuery = `query($cloudId: String!, $first: Int!, $after: String) { agentStudio_getAgents(cloudId: $cloudId, first: $first, after: $after) { edges { node { id name } } pageInfo { hasNextPage endCursor } } }`

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
