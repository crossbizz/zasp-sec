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

// The response shapes are the ones gitlab.go and atlassian.go document as
// unverified.
func gitLabRoutes(duo string) map[string]saastest.Route {
	return map[string]saastest.Route{
		"/api/v4/groups/4242": saastest.Static(`{"id":4242,"name":"Platform","path":"platform","full_path":"acme/platform","visibility":"private"` + duo + `}`),
		"/api/v4/groups/4242/projects": func(query url.Values, _ int) saastest.Response {
			if query.Get("include_subgroups") != "true" || query.Get("archived") != "false" || query.Get("per_page") != "100" {
				return saastest.Response{Status: http.StatusBadRequest, Body: `[]`}
			}
			switch query.Get("page") {
			case "1":
				projects := []string{
					`{"id":101,"name":"support-agent","path_with_namespace":"acme/platform/support-agent","archived":false,"topics":["Python","AI-Agent"],"description":"Answers tickets"}`,
					`{"id":102,"name":"docs-mcp","path_with_namespace":"acme/platform/tools/docs-mcp","archived":false,"topics":["mcp-server"]}`,
					`{"id":103,"name":"LangChain playground","path_with_namespace":"acme/platform/langchain-playground","archived":false,"topics":[]}`,
				}
				// Ninety-seven projects that say nothing about AI fill the page.
				for index := 0; index < 97; index++ {
					projects = append(projects, fmt.Sprintf(`{"id":%d,"name":"service-%d","path_with_namespace":"acme/platform/service-%d","archived":false,"topics":["go","agentless"]}`, 200+index, index, index))
				}
				return saastest.Response{Body: `[` + strings.Join(projects, ",") + `]`}
			case "2":
				return saastest.Response{Body: `[{"id":301,"name":"website","path_with_namespace":"acme/platform/website","archived":false,"topics":["hugo"]}]`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `[]`}
		},
	}
}

func TestGitLabGroupIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab")
	standIn := saastest.NewNango(t, registry, gitLabRoutes(`,"duo_features_enabled":true`))
	snapshot := saastest.Collect(t, standIn, registry, platform, "4242")

	if applications := snapshot.Kind("saas_ai_application"); len(applications) != 4 || len(snapshot.Entities) != 5 {
		t.Fatalf("applications=%d: %s", len(applications), snapshot.Raw)
	}
	if duo := snapshot.Named(t, "saas_ai_application", "GitLab Duo"); !reflect.DeepEqual(duo.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:duo"}) || duo.Attributes["status"] != "enabled" {
		t.Fatalf("Duo = %+v", duo.Attributes)
	}
	agent := snapshot.Named(t, "saas_ai_application", "acme/platform/support-agent")
	if agent.SourceNativeID != "saas:gitlab:project:101" || !reflect.DeepEqual(agent.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:repository_topic"}) {
		t.Fatalf("tagged project = %+v", agent)
	}
	// A project named after a product of the application catalog.
	if named := snapshot.Named(t, "saas_ai_application", "acme/platform/langchain-playground"); !reflect.DeepEqual(named.Attributes["discovery"].(map[string]any)["signals"], []any{"app:langchain"}) {
		t.Fatalf("named project = %+v", named.Attributes)
	}
	snapshot.Named(t, "saas_ai_application", "acme/platform/tools/docs-mcp")
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "acme/platform" || tenant.StableFields["tenant"] != "4242" {
		t.Fatalf("tenant = %+v", tenant)
	}
	// A project's description is content: it is never stored.
	if bytes.Contains(snapshot.Raw, []byte("Answers tickets")) {
		t.Fatal("the snapshot holds a project description")
	}
	// The group is named in every path; the projects are read page by page.
	var pages []string
	for _, call := range standIn.Calls() {
		if !strings.HasPrefix(call.Path, "/api/v4/groups/4242") || call.Host != "" {
			t.Fatalf("call = %+v", call)
		}
		pages = append(pages, call.Query.Get("page"))
	}
	if !reflect.DeepEqual(pages, []string{"", "", "1", "2"}) {
		t.Fatalf("pages = %v", pages)
	}
}

func TestGitLabGroupWithoutDuoOrOfAnotherIDIsHandled(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab")
	// A group on a tier without Duo does not state the member; one with Duo
	// switched off states false.
	for _, duo := range []string{``, `,"duo_features_enabled":false`} {
		snapshot := saastest.Collect(t, saastest.NewNango(t, registry, gitLabRoutes(duo)), registry, platform, "4242")
		if len(snapshot.Kind("saas_ai_application")) != 3 {
			t.Fatalf("duo %q: %s", duo, snapshot.Raw)
		}
	}
	// The path asks for group 4243 and the API answers with another group.
	routes := gitLabRoutes(``)
	routes["/api/v4/groups/4243"] = routes["/api/v4/groups/4242"]
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, "4243")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("another group: %v", err)
	}
	// A group the connection cannot see.
	_, err = saastest.Run(t, saastest.NewNango(t, registry, gitLabRoutes(``)), registry, platform, "999")
	if !errors.As(err, &failure) || failure.Code() != collection.FailureTerminal {
		t.Fatalf("unknown group: %v", err)
	}
	for _, tenant := range []string{"acme", "0", "4242/projects", "../4242"} {
		if platform.ValidTenant(tenant) {
			t.Fatalf("group id %q accepted", tenant)
		}
	}
}

func atlassianRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/rest/api/3/serverInfo": saastest.Static(`{"baseUrl":"https://acme.atlassian.net","version":"1001.0.0-SNAPSHOT","deploymentType":"Cloud","serverTitle":"Jira"}`),
		"/rest/plugins/1.0/": saastest.Static(`{"plugins":[
 {"key":"com.atlassian.rovo.agents","name":"Rovo Agents","enabled":true,"userInstalled":false,"vendor":{"name":"Atlassian"}},
 {"key":"com.openai.chatgpt-jira","name":"ChatGPT for Jira","enabled":true,"userInstalled":true,"vendor":{"name":"Example"}},
 {"key":"com.example.glean","name":"Glean","enabled":false,"userInstalled":true},
 {"key":"com.example.timesheets","name":"Timesheets","enabled":true,"userInstalled":true},
 {"key":"com.atlassian.jira.plugin.system.issueoperations","name":"Issue Operations Plugin","enabled":true,"userInstalled":false}
],"links":{"self":"/rest/plugins/1.0/"}}`),
	}
}

func TestAtlassianSiteIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian")
	standIn := saastest.NewNango(t, registry, atlassianRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, "acme")

	for _, call := range standIn.Calls() {
		if call.Host != "acme.atlassian.net" || call.Key != "jira-basic" {
			t.Fatalf("call = %+v", call)
		}
	}
	if applications := snapshot.Kind("saas_ai_application"); len(applications) != 3 || len(snapshot.Entities) != 4 {
		t.Fatalf("applications=%d: %s", len(applications), snapshot.Raw)
	}
	rovo := snapshot.Named(t, "saas_ai_application", "Rovo Agents")
	if rovo.SourceNativeID != "saas:atlassian:app:com.atlassian.rovo.agents" || !reflect.DeepEqual(rovo.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:rovo"}) || rovo.Attributes["agent_type"] != "enterprise_agent" {
		t.Fatalf("Rovo = %+v", rovo)
	}
	chatgpt := snapshot.Named(t, "saas_ai_application", "ChatGPT for Jira")
	if !reflect.DeepEqual(chatgpt.Attributes["discovery"].(map[string]any)["signals"], []any{"app:chatgpt", "surface:marketplace_app"}) || chatgpt.Attributes["posture"].(map[string]any)["credential_active"] != true {
		t.Fatalf("ChatGPT = %+v", chatgpt.Attributes)
	}
	if glean := snapshot.Named(t, "saas_ai_application", "Glean"); glean.Attributes["status"] != "disabled" || glean.Attributes["posture"].(map[string]any)["credential_active"] != false {
		t.Fatalf("Glean = %+v", glean.Attributes)
	}
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "acme.atlassian.net" {
		t.Fatalf("tenant = %+v", tenant)
	}
	// The site the connection reaches is not the one the integration names.
	other := saastest.NewNango(t, registry, atlassianRoutes())
	_, err := saastest.Run(t, other, registry, platform, "globex")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied || other.Calls()[0].Host != "globex.atlassian.net" {
		t.Fatalf("another site: %v", err)
	}
	// A base URL that is not an Atlassian Cloud site names no tenant.
	routes := atlassianRoutes()
	routes["/rest/api/3/serverInfo"] = saastest.Static(`{"baseUrl":"https://jira.acme.example","deploymentType":"Server"}`)
	_, err = saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, "acme")
	if !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
		t.Fatalf("server deployment: %v", err)
	}
}
