package platforms

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// The response shapes of the GitLab AI catalog query are the ones gitlab.go
// documents; the Rovo and OpenAI project ones are as their files state.
func gitLabCatalogRoute(t *testing.T) saastest.Route {
	return func(query url.Values, _ int) saastest.Response {
		if query.Get("query") == gitLabDuoMCPServersQuery {
			return gitLabMCPServersResponse(t, query)
		}
		if query.Get("query") != gitLabDuoCatalogQuery || query.Get("group") != "gid://gitlab/Group/4242" || query.Get("first") != "50" {
			t.Errorf("catalog query = %v", query)
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		}
		node := func(consumer int, enabled bool, item int, name, itemType string, deleted bool) string {
			return fmt.Sprintf(`{"id":"gid://gitlab/Ai::Catalog::ItemConsumer/%d","enabled":%t,"item":{"id":"gid://gitlab/Ai::Catalog::Item/%d","name":%q,"itemType":%q,"foundational":%t,"softDeleted":%t,"description":"Reviews merge requests; system prompt: be strict"}}`,
				consumer, enabled, item, name, itemType, itemType == "FOUNDATIONAL_AGENT", deleted)
		}
		switch query.Get("after") {
		case "":
			return saastest.Response{Body: `{"data":{"aiCatalogConfiguredItems":{"nodes":[` + strings.Join([]string{
				node(1, true, 11, "Merge request reviewer", "AGENT", false),
				node(2, false, 12, "Release notes flow", "FLOW", false),
				node(3, true, 13, "Planner", "FOUNDATIONAL_AGENT", false),
			}, ",") + `],"pageInfo":{"hasNextPage":true,"endCursor":"cursor-2"}}}}`}
		case "cursor-2":
			return saastest.Response{Body: `{"data":{"aiCatalogConfiguredItems":{"nodes":[` + strings.Join([]string{
				node(4, true, 14, "Vendor flow", "THIRD_PARTY_FLOW", false),
				// A skill is not an agent; a deleted item is gone.
				node(5, true, 15, "Changelog skill", "SKILL", false),
				node(6, true, 16, "Removed agent", "AGENT", true),
			}, ",") + `],"pageInfo":{"hasNextPage":false,"endCursor":"cursor-3"}}}}`}
		}
		t.Errorf("catalog continuation = %q", query.Get("after"))
		return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
	}
}

// The MCP servers of the group's agents, two pages of configured agents: a
// server two agents use is listed under both, and one agent has none.
func gitLabMCPServersResponse(t *testing.T, query url.Values) saastest.Response {
	if query.Get("group") != "gid://gitlab/Group/4242" || query.Get("first") != "20" {
		t.Errorf("MCP servers query = %v", query)
		return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
	}
	server := func(id int, name, address, auth string) string {
		return fmt.Sprintf(`{"id":"gid://gitlab/Ai::Catalog::McpServer/%d","name":%q,"url":%q,"transport":"HTTP","authType":%q,"oauthClientId":"do-not-keep-client-id"}`, id, name, address, auth)
	}
	agent := func(consumer int, servers ...string) string {
		return fmt.Sprintf(`{"id":"gid://gitlab/Ai::Catalog::ItemConsumer/%d","item":{"id":"gid://gitlab/Ai::Catalog::Item/%d","latestVersion":{"mcpServers":{"nodes":[%s]}}}}`, consumer, consumer+10, strings.Join(servers, ","))
	}
	linear := server(1, "Linear", "https://mcp.linear.example/sse?token=do-not-keep-query", "OAUTH")
	switch query.Get("after") {
	case "":
		return saastest.Response{Body: `{"data":{"aiCatalogConfiguredItems":{"nodes":[` + agent(1, linear, server(2, "Internal docs", "http://docs.internal.example:8080/mcp", "NO_AUTH")) + `,` + agent(3) + `],"pageInfo":{"hasNextPage":true,"endCursor":"m2"}}}}`}
	case "m2":
		// A flow has no agent version: latestVersion states no servers.
		return saastest.Response{Body: `{"data":{"aiCatalogConfiguredItems":{"nodes":[` + agent(4, linear, server(3, "Odd address", "not a url", "NO_AUTH")) + `,{"id":"gid://gitlab/Ai::Catalog::ItemConsumer/5","item":{"id":"gid://gitlab/Ai::Catalog::Item/15","latestVersion":{}}},{"id":"gid://gitlab/Ai::Catalog::ItemConsumer/6","item":{"id":"gid://gitlab/Ai::Catalog::Item/16","latestVersion":null}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`}
	}
	t.Errorf("MCP servers continuation = %q", query.Get("after"))
	return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
}

func TestGitLabMCPServersOfTheGroupsAgentsAreCollectedOnce(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab")
	routes := gitLabRoutes(`,"duo_features_enabled":true`)
	routes["/api/graphql"] = gitLabCatalogRoute(t)
	snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "4242")
	servers := snapshot.Kind("saas_mcp_server")
	if len(servers) != 3 {
		t.Fatalf("servers=%d: %s", len(servers), snapshot.Raw)
	}
	linear := snapshot.Named(t, "saas_mcp_server", "Linear")
	if linear.SourceNativeID != "saas:gitlab:duo_mcp_server:gid://gitlab/Ai::Catalog::McpServer/1" || linear.ProductKind != "tool" ||
		!reflect.DeepEqual(linear.Attributes, map[string]any{"auth": "declared", "endpoint_host": "mcp.linear.example", "status": "configured", "transport": "http"}) {
		t.Fatalf("server = %+v", linear)
	}
	if docs := snapshot.Named(t, "saas_mcp_server", "Internal docs"); docs.Attributes["auth"] != "none" || docs.Attributes["endpoint_host"] != "docs.internal.example" {
		t.Fatalf("server without authentication = %+v", docs.Attributes)
	}
	// An address that is not a URL names no host.
	if odd := snapshot.Named(t, "saas_mcp_server", "Odd address"); odd.Attributes["endpoint_host"] != nil {
		t.Fatalf("odd server = %+v", odd.Attributes)
	}
	// Of an address only the host is kept; an OAuth client id is not asked for.
	if bytes.Contains(snapshot.Raw, []byte("do-not-keep")) || bytes.Contains(snapshot.Raw, []byte("/sse")) || strings.Contains(gitLabDuoMCPServersQuery, "oauthClientId") || strings.Contains(gitLabDuoMCPServersQuery, "systemPrompt") {
		t.Fatal("the snapshot or the query holds more than the server's name, host, transport and authentication")
	}
}

func TestGitLabDuoAgentsAndFlowsAreCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab")
	routes := gitLabRoutes(`,"duo_features_enabled":true,"duo_availability":"default_on","experiment_features_enabled":false`)
	routes["/api/graphql"] = gitLabCatalogRoute(t)
	standIn := saastest.NewNango(t, registry, routes)
	snapshot := saastest.Collect(t, standIn, registry, platform, "4242")

	agents := snapshot.Kind("saas_agent")
	if len(agents) != 4 || len(snapshot.Kind("saas_ai_application")) != 4 {
		t.Fatalf("agents=%d: %s", len(agents), snapshot.Raw)
	}
	reviewer := snapshot.Named(t, "saas_agent", "Merge request reviewer")
	if reviewer.SourceNativeID != "saas:gitlab:duo_agent:gid://gitlab/Ai::Catalog::ItemConsumer/1" || reviewer.Attributes["status"] != "enabled" || reviewer.Attributes["agent_type"] != "agent" || reviewer.ProductKind != "agent" ||
		!reflect.DeepEqual(reviewer.Attributes["discovery"], map[string]any{"method": "provider_api", "platform": "gitlab", "signals": []any{"surface:duo"}}) || reviewer.Attributes["posture"].(map[string]any)["credential_active"] != true {
		t.Fatalf("agent = %+v", reviewer)
	}
	if flow := snapshot.Named(t, "saas_agent", "Release notes flow"); flow.StableFields["object_type"] != "duo_flow" || flow.Attributes["status"] != "disabled" || flow.Attributes["agent_type"] != "flow" || flow.Attributes["posture"].(map[string]any)["credential_active"] != false {
		t.Fatalf("flow = %+v", flow)
	}
	if planner := snapshot.Named(t, "saas_agent", "Planner"); planner.Attributes["agent_type"] != "foundational_agent" {
		t.Fatalf("foundational agent = %+v", planner.Attributes)
	}
	if vendor := snapshot.Named(t, "saas_agent", "Vendor flow"); vendor.Attributes["agent_type"] != "third_party_flow" {
		t.Fatalf("third-party flow = %+v", vendor.Attributes)
	}
	// The group's Duo setting is the status of the Duo application.
	if duo := snapshot.Named(t, "saas_ai_application", "GitLab Duo"); duo.Attributes["status"] != "default_on" {
		t.Fatalf("Duo = %+v", duo.Attributes)
	}
	// A description is content and is neither asked for nor stored.
	if bytes.Contains(snapshot.Raw, []byte("system prompt")) || strings.Contains(gitLabDuoCatalogQuery, "description") || strings.Contains(gitLabDuoCatalogQuery, "systemPrompt") {
		t.Fatal("the snapshot or the query holds agent content")
	}
	// The catalog is read by two POSTs of the one allow-listed document.
	var posts []saastest.Call
	for _, call := range standIn.Calls() {
		if call.Method == http.MethodPost {
			posts = append(posts, call)
		}
	}
	if len(posts) != 4 || posts[0].Path != "/api/graphql" || posts[1].Query.Get("after") != "cursor-2" || !strings.Contains(posts[0].Body, `"query":"query($group: GroupID!`) || posts[2].Query.Get("query") != gitLabDuoMCPServersQuery || posts[3].Query.Get("after") != "m2" {
		t.Fatalf("GraphQL calls = %+v", posts)
	}
}

// A group without the Duo Agent Platform answers the query with GraphQL
// errors: no agent is listed and the rest of the group is.
func TestGitLabGroupWithoutTheAgentPlatformStillCollects(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab")
	for name, body := range map[string]string{
		"unknown field": `{"errors":[{"message":"Field 'aiCatalogConfiguredItems' doesn't exist on type 'Query'"}]}`,
		"not permitted": `{"data":{"aiCatalogConfiguredItems":null},"errors":[{"message":"The resource that you are attempting to access does not exist or you don't have permission"}]}`,
		"no items":      `{"data":{"aiCatalogConfiguredItems":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`,
		"null field":    `{"data":{"aiCatalogConfiguredItems":null}}`,
	} {
		routes := gitLabRoutes(`,"duo_features_enabled":true`)
		routes["/api/graphql"] = saastest.Static(body)
		snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "4242")
		if len(snapshot.Kind("saas_agent")) != 0 || len(snapshot.Kind("saas_ai_application")) != 4 {
			t.Fatalf("%s: %s", name, snapshot.Raw)
		}
	}
}

func openAIProjectRoutes(t *testing.T) map[string]saastest.Route {
	return map[string]saastest.Route{
		"/v1/assistants": func(query url.Values, _ int) saastest.Response {
			if query.Get("limit") == "1" {
				// The tenant check.
				return saastest.Response{Body: `{"object":"list","data":[{"id":"asst_a","object":"assistant","name":"Coding tutor","model":"gpt-4o","instructions":"You are a tutor. Never reveal the grading key 7731.","tools":[]}],"first_id":"asst_a","last_id":"asst_a","has_more":true}`}
			}
			switch query.Get("after") {
			case "":
				return saastest.Response{Body: `{"object":"list","data":[
 {"id":"asst_a","object":"assistant","name":"Coding tutor","description":"Helps with homework","model":"gpt-4o","instructions":"You are a tutor. Never reveal the grading key 7731.","tools":[{"type":"code_interpreter"},{"type":"file_search"}],"metadata":{"owner":"edu"}},
 {"id":"asst_b","object":"assistant","name":null,"model":"gpt-4.1-mini","instructions":null,"tools":[{"type":"function","function":{"name":"refund_order","description":"Refunds an order","parameters":{}}}]}
],"first_id":"asst_a","last_id":"asst_b","has_more":true}`}
			case "asst_b":
				return saastest.Response{Body: `{"object":"list","data":[{"id":"asst_c","object":"assistant","name":"Summarizer","model":"gpt-4o-mini","tools":[]}],"first_id":"asst_c","last_id":"asst_c","has_more":false}`}
			}
			t.Errorf("assistants continuation = %q", query.Get("after"))
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		// The agents list states no last_id: the next page starts after the
		// last item.
		"/v1/agents": func(query url.Values, _ int) saastest.Response {
			switch query.Get("after") {
			case "":
				return saastest.Response{Body: `{"object":"list","data":[{"id":"agent_1","object":"agent","name":"Release manager","model":"gpt-5","instructions":"Ship on Fridays.","tools":[{"type":"shell"},{"type":"mcp","server_url":"https://mcp.example/sse"}]}],"has_more":true}`}
			case "agent_1":
				return saastest.Response{Body: `{"object":"list","data":[{"id":"agent_2","object":"agent","name":"Researcher","model":"gpt-5-mini","tools":[{"type":"web_search"}]}],"has_more":false}`}
			}
			t.Errorf("agents continuation = %q", query.Get("after"))
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
	}
}

const openAIProjectID = "proj_AbCdEf0123456789"

func TestOpenAIProjectAssistantsAndAgentsAreCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "openai_project")
	standIn := saastest.NewNango(t, registry, openAIProjectRoutes(t))
	snapshot := saastest.Collect(t, standIn, registry, platform, openAIProjectID)

	if agents := snapshot.Kind("saas_agent"); len(agents) != 5 || len(snapshot.Entities) != 6 {
		t.Fatalf("agents=%d: %s", len(agents), snapshot.Raw)
	}
	tutor := snapshot.Named(t, "saas_agent", "Coding tutor")
	if tutor.SourceNativeID != "saas:openai_project:assistant:asst_a" || tutor.Attributes["model"] != "gpt-4o" || tutor.Attributes["agent_type"] != "assistant" || tutor.StableFields["tenant"] != openAIProjectID ||
		!reflect.DeepEqual(tutor.Attributes["discovery"], map[string]any{"method": "provider_api", "platform": "openai_project", "signals": []any{"model:openai", "tool:code_interpreter", "tool:file_search"}}) ||
		tutor.Attributes["posture"].(map[string]any)["shell_execution"] != true {
		t.Fatalf("assistant = %+v", tutor)
	}
	// An unnamed assistant is shown by its id; a function tool runs no code.
	if unnamed := snapshot.Named(t, "saas_agent", "asst_b"); unnamed.Attributes["posture"].(map[string]any)["shell_execution"] != false || !reflect.DeepEqual(unnamed.Attributes["discovery"].(map[string]any)["signals"], []any{"model:openai", "tool:function"}) {
		t.Fatalf("unnamed assistant = %+v", unnamed.Attributes)
	}
	if manager := snapshot.Named(t, "saas_agent", "Release manager"); manager.SourceNativeID != "saas:openai_project:agent:agent_1" || manager.Attributes["posture"].(map[string]any)["shell_execution"] != true ||
		!reflect.DeepEqual(manager.Attributes["discovery"].(map[string]any)["signals"], []any{"model:openai", "tool:mcp", "tool:shell"}) {
		t.Fatalf("agent = %+v", manager)
	}
	snapshot.Named(t, "saas_agent", "Summarizer")
	snapshot.Named(t, "saas_agent", "Researcher")
	// Instructions, descriptions, metadata and tool definitions are content.
	for _, content := range []string{"grading key", "Ship on Fridays", "Helps with homework", "refund_order", "mcp.example", "edu"} {
		if bytes.Contains(snapshot.Raw, []byte(content)) {
			t.Fatalf("the snapshot holds %q", content)
		}
	}
	// Every request names the project and the API version in headers the
	// proxy forwards, and goes to the standard OpenAI integration.
	calls := standIn.Calls()
	if len(calls) != 5 {
		t.Fatalf("calls = %+v", calls)
	}
	for _, call := range calls {
		beta := "assistants=v2"
		if call.Path == "/v1/agents" {
			beta = "agents=v1"
		}
		if call.Key != "openai" || call.Method != http.MethodGet || !reflect.DeepEqual(call.Headers, map[string]string{"Openai-Beta": beta, "Openai-Project": openAIProjectID}) {
			t.Fatalf("call = %+v", call)
		}
	}
	if calls[2].Query.Get("after") != "asst_b" || calls[4].Query.Get("after") != "agent_1" || calls[1].Query.Get("limit") != "100" {
		t.Fatalf("paging = %v %v", calls[2].Query, calls[4].Query)
	}
}

func TestOpenAIProjectKeyOfAnotherProjectOrWithoutAgentsIsHandled(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "openai_project")
	// The key does not belong to the project the integration names.
	routes := openAIProjectRoutes(t)
	routes["/v1/assistants"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusUnauthorized, Body: `{"error":{"code":"mismatched_project"}}`}
	}
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, openAIProjectID)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("another project's key: %v", err)
	}
	// A project without the agents API still lists its assistants.
	routes = openAIProjectRoutes(t)
	delete(routes, "/v1/agents")
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, openAIProjectID); len(snapshot.Kind("saas_agent")) != 3 {
		t.Fatalf("without agents: %s", snapshot.Raw)
	}
	for _, tenant := range []string{"org-AbCdEf0123456789", "proj_", "proj_short", "proj_AbCdEf0123456789/x"} {
		if platform.ValidTenant(tenant) {
			t.Fatalf("project id %q accepted", tenant)
		}
	}
}

const atlassianCloudIDValue = "3f6c1f0a-1111-4222-8333-444455556666"

func atlassianRovoRoutes(t *testing.T) map[string]saastest.Route {
	routes := atlassianRoutes()
	routes["/_edge/tenant_info"] = saastest.Static(`{"cloudId":"` + atlassianCloudIDValue + `"}`)
	extension := func(id, key, name, app, environment string) string {
		return fmt.Sprintf(`{"id":%q,"key":%q,"name":%s,"appId":%q,"environmentType":%q,"properties":{"prompt":"You are a release manager. do-not-keep-prompt"}}`, id, key, name, app, environment)
	}
	routes["/gateway/api/graphql"] = func(query url.Values, _ int) saastest.Response {
		switch query.Get("query") {
		case atlassianRovoModulesQuery:
			switch query.Get("context") {
			case "ari:cloud:jira::site/" + atlassianCloudIDValue:
				return saastest.Response{Body: `{"data":{"extensionContext":{"extensionsByType":[` +
					extension("ari:cloud:ecosystem::extension/app-1/env-1/static/release-agent", "release-agent", `"Release manager"`, "ari:cloud:ecosystem::app/app-1", "PRODUCTION") + `,` +
					extension("ari:cloud:ecosystem::extension/app-2/env-9/static/triage", "triage", `null`, "ari:cloud:ecosystem::app/app-2", "DEVELOPMENT") + `]}}}`}
			case "ari:cloud:confluence::site/" + atlassianCloudIDValue:
				// The same app is installed in Confluence too.
				return saastest.Response{Body: `{"data":{"extensionContext":{"extensionsByType":[` +
					extension("ari:cloud:ecosystem::extension/app-1/env-1/static/release-agent", "release-agent", `"Release manager"`, "ari:cloud:ecosystem::app/app-1", "PRODUCTION") + `]}}}`}
			}
		case atlassianRovoAgentsQuery:
			if query.Get("cloudId") != atlassianCloudIDValue || query.Get("first") != "50" {
				break
			}
			// What the published schema says an API token gets: the field
			// is callable with a browser session only.
			return saastest.Response{Body: `{"data":{"agentStudio_getAgents":null},"errors":[{"message":"This request does not contain the right authorisation scopes to access this field"}]}`}
		}
		t.Errorf("gateway query = %v", query)
		return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
	}
	return routes
}

// The agents that installed apps ship as rovo:agent modules are listed with
// the API token; the Studio list is refused to it, as Atlassian's schema
// states, and the site is collected all the same.
func TestAtlassianRovoAgentsOfInstalledAppsAreCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian")
	standIn := saastest.NewNango(t, registry, atlassianRovoRoutes(t))
	snapshot := saastest.Collect(t, standIn, registry, platform, "acme")
	if agents := snapshot.Kind("saas_agent"); len(agents) != 3 || len(snapshot.Kind("saas_ai_application")) != 3 {
		t.Fatalf("agents=%d: %s", len(agents), snapshot.Raw)
	}
	var jira, confluence, unnamed saastest.Entity
	for _, agent := range snapshot.Kind("saas_agent") {
		switch {
		case agent.DisplayName == "triage":
			unnamed = agent
		case agent.StableFields["object_type"] == "jira_rovo_agent":
			jira = agent
		case agent.StableFields["object_type"] == "confluence_rovo_agent":
			confluence = agent
		}
	}
	if jira.DisplayName != "Release manager" || jira.SourceNativeID != "saas:atlassian:jira_rovo_agent:ari:cloud:ecosystem::extension/app-1/env-1/static/release-agent" || jira.Attributes["status"] != "production" || jira.Attributes["agent_type"] != "enterprise_agent" ||
		!reflect.DeepEqual(jira.Attributes["discovery"], map[string]any{"method": "provider_api", "platform": "atlassian", "signals": []any{"surface:marketplace_app", "surface:rovo"}}) || jira.Attributes["posture"].(map[string]any)["credential_active"] != true {
		t.Fatalf("Jira module = %+v", jira)
	}
	if confluence.DisplayName != "Release manager" || confluence.ID == jira.ID || unnamed.Attributes["status"] != "development" || unnamed.StableFields["object_type"] != "jira_rovo_agent" {
		t.Fatalf("Confluence module = %+v, unnamed = %+v", confluence, unnamed)
	}
	// A module's properties hold its prompt: they are neither asked for nor kept.
	if bytes.Contains(snapshot.Raw, []byte("do-not-keep")) || strings.Contains(atlassianRovoModulesQuery, "properties") || strings.Contains(atlassianRovoAgentsQuery, "instructions") {
		t.Fatal("the snapshot or a query holds agent content")
	}
	for _, call := range standIn.Calls() {
		if call.Host != "acme.atlassian.net" {
			t.Fatalf("call = %+v", call)
		}
	}
}

// When Atlassian opens the Studio field to API tokens the same query lists
// the Studio agents; every way the gateway can refuse leaves the site's
// applications collected.
func TestAtlassianStudioAgentsAreListedWhenTheGatewayAnswersAndSkippedWhenItDoesNot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian")
	answered := atlassianRovoRoutes(t)
	modules := answered["/gateway/api/graphql"]
	answered["/gateway/api/graphql"] = func(query url.Values, call int) saastest.Response {
		if query.Get("query") != atlassianRovoAgentsQuery {
			return modules(query, call)
		}
		if !strings.Contains(query.Get("query"), `@optIn(to: "AgentStudio")`) {
			t.Errorf("the Studio query does not opt in: %s", query.Get("query"))
		}
		if query.Get("after") == "" {
			return saastest.Response{Body: `{"data":{"agentStudio_getAgents":{"edges":[{"cursor":"c1","node":{"id":"ari:cloud:rovo::agent/a1","name":"Release notes writer","deactivated":false}},{"cursor":"c2","node":{"id":"ari:cloud:rovo::agent/a2","name":"Incident scribe","deactivated":true}}],"pageInfo":{"hasNextPage":true,"endCursor":"c2"}}}}`}
		}
		return saastest.Response{Body: `{"data":{"agentStudio_getAgents":{"edges":[{"cursor":"c3","node":{"id":"ari:cloud:rovo::agent/a3","name":"Backlog groomer"}}],"pageInfo":{"hasNextPage":false,"endCursor":"c3"}}}}`}
	}
	snapshot := saastest.Collect(t, saastest.NewNango(t, registry, answered), registry, platform, "acme")
	if len(snapshot.Kind("saas_agent")) != 6 {
		t.Fatalf("agents: %s", snapshot.Raw)
	}
	if writer := snapshot.Named(t, "saas_agent", "Release notes writer"); writer.SourceNativeID != "saas:atlassian:rovo_agent:ari:cloud:rovo::agent/a1" || writer.Attributes["status"] != "active" {
		t.Fatalf("Studio agent = %+v", writer)
	}
	if scribe := snapshot.Named(t, "saas_agent", "Incident scribe"); scribe.Attributes["status"] != "deactivated" || scribe.Attributes["posture"].(map[string]any)["credential_active"] != false {
		t.Fatalf("deactivated agent = %+v", scribe.Attributes)
	}
	for name, change := range map[string]func(map[string]saastest.Route){
		"no gateway route": func(routes map[string]saastest.Route) { delete(routes, "/gateway/api/graphql") },
		"no tenant info":   func(routes map[string]saastest.Route) { delete(routes, "/_edge/tenant_info") },
		"every query refused": func(routes map[string]saastest.Route) {
			routes["/gateway/api/graphql"] = saastest.Static(`{"errors":[{"message":"third party oauth clients not allowed"}],"data":null}`)
		},
		"forbidden": func(routes map[string]saastest.Route) {
			routes["/gateway/api/graphql"] = func(url.Values, int) saastest.Response {
				return saastest.Response{Status: http.StatusForbidden, Body: `{}`}
			}
		},
	} {
		routes := atlassianRovoRoutes(t)
		change(routes)
		if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "acme"); len(snapshot.Kind("saas_agent")) != 0 || len(snapshot.Kind("saas_ai_application")) != 3 {
			t.Fatalf("%s: %s", name, snapshot.Raw)
		}
	}
}
