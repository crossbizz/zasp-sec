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

// GitLab reads one group of gitlab.com: whether GitLab Duo is switched on
// for the group, the Duo agents and flows that are enabled in the group (the
// AI catalog of the Duo Agent Platform), and the projects of the group and
// its subgroups that their owners tagged with an AI topic or named after a
// known AI product.
//
// What it does not read: no file, no repository tree, no pipeline and no
// variable is requested, so a project that is an agent but says so only in
// its code is not listed. Of a Duo agent or flow it reads the name, the kind
// and whether it is enabled; never a system prompt or a flow definition.
// A self-managed GitLab and GitLab Dedicated are not covered. The framework
// can send a platform's requests to a tenant's own host, but only to a host
// under a domain the provider owns (the adapter's guard against a request
// being sent to an address a customer chose), which a self-managed
// instance's domain is not; and for such a platform the tenant id is the
// host, while everything read here is addressed by a group id.
//
// The agents and flows are read with one GraphQL query. It is a POST and
// still a read: the collector sends gitLabDuoCatalogQuery and nothing else,
// and the Nango rule of /api/graphql admits that document only.
//
// DOCUMENTED:
//   - https://docs.gitlab.com/api/groups/ : GET /api/v4/groups/{id} states
//     duo_features_enabled, lock_duo_features_enabled, duo_availability and
//     experiment_features_enabled for a group of a tier with Duo;
//   - https://docs.gitlab.com/api/graphql/reference/ (Query.
//     aiCatalogConfiguredItems, AiCatalogItemConsumer, AiCatalogItem,
//     AiCatalogItemType): the query's arguments groupId (GroupID), first and
//     after, the fields id and enabled of a configured item, the fields
//     name, itemType, foundational and softDeleted of its item, the item
//     types AGENT, FLOW, FOUNDATIONAL_AGENT, SKILL and THIRD_PARTY_FLOW, and
//     the standard connection fields nodes and pageInfo;
//   - the same reference, AiCatalogAgentVersion.mcpServers (a connection of
//     AiCatalogMcpServer: id, name, url, transport HTTP, authType NO_AUTH or
//     OAUTH) and AiCatalogItem.latestVersion. Query.aiCatalogMcpServers
//     takes no group or project argument, which is why it is not used;
//   - https://docs.gitlab.com/api/graphql/ : the endpoint is POST
//     /api/graphql and the scope read_api is sufficient for queries.
//
// UNVERIFIED (not run against a real group):
//   - the global id of a group is gid://gitlab/Group/<numeric id>;
//   - how a group without the Duo Agent Platform answers the query. An
//     answer with GraphQL errors is read as "not available" and lists
//     nothing;
//   - GET /api/v4/groups/{id}/projects with include_subgroups, archived,
//     order_by, sort, page and per_page answers an array of projects, each
//     with id, path_with_namespace, archived and topics[];
//   - the Nango integration key (gitlab).
func GitLab() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "gitlab", DisplayName: "GitLab",
		Description: "Inventory GitLab Duo, its agents and flows, and the AI projects of one gitlab.com group through a Nango connection.",
		Nango: nango.Entry{Key: "gitlab", ProviderHost: "gitlab.com", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/v4/groups/", QueryKeys: []string{"archived", "include_subgroups", "order_by", "page", "per_page", "sort", "with_projects"}},
			{Method: http.MethodPost, PathPrefix: "/api/graphql", GraphQLDocuments: []string{gitLabDuoCatalogQuery, gitLabDuoMCPServersQuery}},
		}},
		RequiredScopes: []string{"read_api"},
		TenantLabel:    "Group ID", TenantHint: "The numeric ID of the group, shown on the group's overview page.",
		TenantPattern:  regexp.MustCompile(`^[1-9][0-9]{0,17}$`),
		AccessGuidance: "Sign in as a member of the group with at least the Reporter role. The connection asks for the read_api scope only.",
		SignIn:         &saasdiscovery.SignIn{AuthorizationHost: "gitlab.com", AuthorizationPath: "/oauth/authorize"},
		Tenant: saasdiscovery.TenantLookup{Path: "/api/v4/groups/{tenant}", Query: map[string]string{"with_projects": "false"}, Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			name := document.Text("full_path")
			if name == "" {
				name = document.Text("name")
			}
			return saasdiscovery.Tenant{ID: document.Text("id"), Name: name}, document.Text("id") != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "duo", Path: "/api/v4/groups/{tenant}", Query: map[string]string{"with_projects": "false"}, Single: true, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					// A group on a tier without Duo does not state the
					// member; nothing is then listed.
					if !item.Bool("duo_features_enabled") {
						return saasdiscovery.Entity{}, false
					}
					var evidence agentsignals.Evidence
					evidence.Surface("duo")
					// The group's setting for its subgroups and projects:
					// default_on, default_off or never_on.
					status := "enabled"
					switch availability := item.Text("duo_availability"); availability {
					case "default_on", "default_off", "never_on":
						status = availability
					}
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: "duo", DisplayName: "GitLab Duo", ObjectType: "duo", Status: status, AgentType: "coding_agent", Signals: evidence.Signals()}, true
				}},
			{Name: "duo_catalog", Path: "/api/graphql", ItemsPath: []string{"data", "aiCatalogConfiguredItems", "nodes"},
				GraphQL: &saasdiscovery.GraphQL{Document: gitLabDuoCatalogQuery, Variables: map[string]string{"group": "gid://gitlab/Group/" + saasdiscovery.TenantValue}, ErrorsAbsent: true},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LimitParam: "first", PageSize: 50,
					NextPath: []string{"data", "aiCatalogConfiguredItems", "pageInfo", "endCursor"}, MorePath: []string{"data", "aiCatalogConfiguredItems", "pageInfo", "hasNextPage"}},
				Map: gitLabCatalogItem},
			// The MCP servers of the agents enabled in the group. The catalog's
			// own list of MCP servers (aiCatalogMcpServers) takes no group or
			// project, so the servers are read where the schema ties them to
			// the group: under the latest version of each configured agent. A
			// server several agents use is reported once.
			{Name: "duo_mcp_servers", Path: "/api/graphql", ItemsPath: []string{"data", "aiCatalogConfiguredItems", "nodes"}, ChildrenPath: []string{"item", "latestVersion", "mcpServers", "nodes"}, Distinct: true,
				GraphQL: &saasdiscovery.GraphQL{Document: gitLabDuoMCPServersQuery, Variables: map[string]string{"group": "gid://gitlab/Group/" + saasdiscovery.TenantValue}, ErrorsAbsent: true},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LimitParam: "first", PageSize: 20,
					NextPath: []string{"data", "aiCatalogConfiguredItems", "pageInfo", "endCursor"}, MorePath: []string{"data", "aiCatalogConfiguredItems", "pageInfo", "hasNextPage"}},
				Map: gitLabMCPServer},
			{Name: "projects", Path: "/api/v4/groups/{tenant}/projects", Query: map[string]string{"include_subgroups": "true", "archived": "false", "order_by": "id", "sort": "asc"},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingPage, PageParam: "page", LimitParam: "per_page", PageSize: 100}, Map: gitLabProject},
		},
	}
}

// gitLabDuoCatalogQuery lists the AI catalog items (agents and flows)
// enabled in one group, a page at a time.
const gitLabDuoCatalogQuery = `query($group: GroupID!, $first: Int!, $after: String) { aiCatalogConfiguredItems(groupId: $group, first: $first, after: $after) { nodes { id enabled item { id name itemType foundational softDeleted } } pageInfo { hasNextPage endCursor } } }`

// gitLabDuoMCPServersQuery lists, for the agents enabled in one group, the
// MCP servers of each agent's latest version: name, address, transport and
// how the server authenticates. No OAuth client id and no tool is selected.
const gitLabDuoMCPServersQuery = `query($group: GroupID!, $first: Int!, $after: String) { aiCatalogConfiguredItems(groupId: $group, first: $first, after: $after, itemTypes: [AGENT, FOUNDATIONAL_AGENT]) { nodes { id item { id latestVersion { ... on AiCatalogAgentVersion { mcpServers(first: 20) { nodes { id name url transport authType } } } } } } pageInfo { hasNextPage endCursor } } }`

// gitLabMCPServer maps one MCP server of a group's agents. Of its address
// only the host is kept.
func gitLabMCPServer(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	id := item.Text("id")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if id == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	entity := saasdiscovery.Entity{Kind: saasdiscovery.KindMCPServer, NativeID: id, DisplayName: name, ObjectType: "duo_mcp_server", Status: "configured"}
	if address, err := url.Parse(item.Text("url")); err == nil && (address.Scheme == "https" || address.Scheme == "http") && address.User == nil {
		if host := strings.ToLower(address.Hostname()); gitLabMCPHostPattern.MatchString(host) {
			entity.EndpointHost = host
		}
	}
	if item.Text("transport") == "HTTP" {
		entity.Transport = agentsignals.MCPTransportHTTP
	}
	switch item.Text("authType") {
	case "NO_AUTH":
		entity.Auth = agentsignals.MCPAuthNone
	case "OAUTH":
		entity.Auth = agentsignals.MCPAuthDeclared
	}
	return entity, true
}

var gitLabMCPHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// gitLabCatalogItem maps one AI catalog item that is configured for the
// group: a Duo agent or a flow. A skill is not an agent and is not listed.
// The entity is the configuration (the item in this group), so its id is
// the configuration's.
func gitLabCatalogItem(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	catalog := item.Object("item")
	id := item.Text("id")
	name := saasdiscovery.CleanText(catalog.Text("name"), 256)
	if id == "" || name == "" || catalog.Bool("softDeleted") {
		return saasdiscovery.Entity{}, false
	}
	objectType, agentType := "", ""
	switch catalog.Text("itemType") {
	case "AGENT":
		objectType, agentType = "duo_agent", "agent"
	case "FOUNDATIONAL_AGENT":
		objectType, agentType = "duo_agent", "foundational_agent"
	case "FLOW":
		objectType, agentType = "duo_flow", "flow"
	case "THIRD_PARTY_FLOW":
		objectType, agentType = "duo_flow", "third_party_flow"
	default:
		return saasdiscovery.Entity{}, false
	}
	enabled := item.Bool("enabled")
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	var evidence agentsignals.Evidence
	evidence.Surface("duo")
	return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: objectType, Status: status, AgentType: agentType,
		// The one posture fact the query states: the item can run in the group.
		Posture: agentsignals.Posture{CredentialActive: enabled}, Signals: evidence.Signals()}, true
}

// gitLabAITopics are the project topics that say a project is an agent, an
// AI application or an MCP server. A topic is compared whole, lower-cased.
var gitLabAITopics = map[string]bool{
	"ai-agent": true, "ai-agents": true, "agent": true, "agents": true, "agentic": true, "llm": true, "llm-agent": true, "genai": true, "generative-ai": true,
	"mcp": true, "mcp-server": true, "model-context-protocol": true, "langchain": true, "langgraph": true, "crewai": true, "autogen": true, "rag": true, "chatbot": true,
}

func gitLabProject(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	id := item.Text("id")
	name := saasdiscovery.CleanText(item.Text("path_with_namespace"), 256)
	if id == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	var evidence agentsignals.Evidence
	// The product name is looked for in the project's own name, not in the
	// names of the groups above it.
	category := evidence.Application(item.Text("name"))
	for _, topic := range item.Texts("topics") {
		if gitLabAITopics[strings.ToLower(strings.TrimSpace(topic))] {
			evidence.Surface("repository_topic")
			if category == "" {
				category = "repository"
			}
		}
	}
	signals := evidence.Signals()
	if len(signals) == 0 {
		// Nothing the API states says this project is AI.
		return saasdiscovery.Entity{}, false
	}
	status := "active"
	if item.Bool("archived") {
		status = "archived"
	}
	return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: id, DisplayName: name, ObjectType: "project", Status: status, AgentType: category, Signals: signals}, true
}
