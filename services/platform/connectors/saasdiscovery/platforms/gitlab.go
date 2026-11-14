package platforms

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// GitLab reads one group of gitlab.com: whether GitLab Duo is switched on
// for the group, and the projects of the group and its subgroups that their
// owners tagged with an AI topic or named after a known AI product.
//
// What it does not read: no file, no repository tree, no pipeline and no
// variable is requested, so a project that is an agent but says so only in
// its code is not listed. Duo agents and flows (the AI catalog) are served
// by GitLab's GraphQL API, which is not a GET and is outside this collector.
// A self-managed GitLab has its own host and is not covered.
//
// UNVERIFIED: the paths and the response members below are written from
// memory of the GitLab REST API and have not been run against a real
// group. Before the first production use, check against a group:
//   - GET /api/v4/groups/{id}?with_projects=false answers
//     {"id":<number>,"name":"…","full_path":"…"} and, on a tier with Duo,
//     "duo_features_enabled":true|false;
//   - GET /api/v4/groups/{id}/projects with include_subgroups, archived,
//     order_by, sort, page and per_page answers an array of projects, each
//     with id, path_with_namespace, archived and topics[];
//   - the scope read_api is enough;
//   - the Nango integration key (gitlab).
func GitLab() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "gitlab", DisplayName: "GitLab",
		Description: "Inventory GitLab Duo and the AI projects of one gitlab.com group through a Nango connection.",
		Nango: nango.Entry{Key: "gitlab", ProviderHost: "gitlab.com", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/v4/groups/", QueryKeys: []string{"archived", "include_subgroups", "order_by", "page", "per_page", "sort", "with_projects"}},
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
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: "duo", DisplayName: "GitLab Duo", ObjectType: "duo", Status: "enabled", AgentType: "coding_agent", Signals: evidence.Signals()}, true
				}},
			{Name: "projects", Path: "/api/v4/groups/{tenant}/projects", Query: map[string]string{"include_subgroups": "true", "archived": "false", "order_by": "id", "sort": "asc"},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingPage, PageParam: "page", LimitParam: "per_page", PageSize: 100}, Map: gitLabProject},
		},
	}
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
