package platforms

import (
	"net/http"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// OpenAIProject lists the assistants and the agents of one OpenAI API
// project. Both belong to a project and are listed only with a key of that
// project; an organization's admin key (the platform openai) cannot call the
// two endpoints. The connection is therefore a key of the project, held by
// Nango: the key of a project service account that has read access is
// enough. One integration reads one project; an organization with several
// projects connects each.
//
// What is recorded of an assistant or an agent: its id, its name, the model
// it names and the kinds of its tools. Its instructions, its metadata and
// the definitions of its tools are not read out of the response.
//
// DOCUMENTED: https://github.com/openai/openai-node (the official SDK,
// published as openai 7.57.0; resources/beta/assistants and
// resources/beta/agents/agents) and
// https://github.com/openai/openai-openapi (listAssistants):
//   - GET /v1/assistants with the header OpenAI-Beta: assistants=v2 and the
//     query parameters after, limit and order answers
//     {"object":"list","data":[{"id":"asst_…","name":…,"model":"…",
//     "tools":[{"type":"code_interpreter"}]}],"has_more":true};
//   - GET /v1/agents with the header OpenAI-Beta: agents=v1 and the same
//     parameters answers the same list shape with {"id","name","model",
//     "tools":[{"type":…}]};
//   - both continue with after=<id of the last item> while has_more is true
//     (the SDK's CursorPage);
//   - a client states its project in the header OpenAI-Project.
//
// UNVERIFIED:
//   - that a request whose OpenAI-Project header names a project the key
//     does not belong to is refused with 401 (mismatched_project). It is
//     what OpenAI's community forum reports, not a statement of the API
//     reference. The tenant check rests on it: the first request names the
//     tenant in that header and must succeed;
//   - which project roles may list assistants and agents, and the name of
//     the restricted-key permission shown in the catalog
//     (api.assistants.read is this definition's label for "Assistants:
//     Read", not a scope name taken from OpenAI's documentation);
//   - the Nango integration key (openai) and that Nango forwards the two
//     headers (sent as Nango-Proxy-<name>);
//   - nothing here was run against a real project.
func OpenAIProject() saasdiscovery.Platform {
	headers := func(beta string) map[string]string {
		return map[string]string{"OpenAI-Beta": beta, "OpenAI-Project": saasdiscovery.TenantValue}
	}
	paging := saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LastItemPath: []string{"id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: 100}
	listRule := func(path string) nango.Rule {
		return nango.Rule{Method: http.MethodGet, PathPrefix: path, QueryKeys: []string{"after", "limit", "order"}, HeaderKeys: []string{"OpenAI-Beta", "OpenAI-Project"}}
	}
	return saasdiscovery.Platform{
		Token: "openai_project", DisplayName: "OpenAI project",
		Description: "Inventory the assistants and agents of one OpenAI API project through a Nango connection.",
		Nango:       nango.Entry{Key: "openai", ProviderHost: "api.openai.com", AuthMode: "api_key", Rules: []nango.Rule{listRule("/v1/assistants"), listRule("/v1/agents")}},
		// The permission of a project key that may list both.
		RequiredScopes: []string{"api.assistants.read"},
		TenantLabel:    "Project ID", TenantHint: "The project ID, which starts with proj_ (Settings, Project, General).",
		TenantPattern:  regexp.MustCompile(`^proj_[A-Za-z0-9]{8,64}$`),
		AccessGuidance: "Create the Nango connection with an API key of the project: a project service account with read access is enough. The product never receives the key; it reads the names, models and tool kinds of the project's assistants and agents, never their instructions.",
		Tenant: saasdiscovery.TenantLookup{Path: "/v1/assistants", Query: map[string]string{"limit": "1", "order": "asc"}, Headers: headers("assistants=v2"),
			// The request named the tenant as its project and was answered:
			// the key is a key of that project. The answer states no project
			// name; the project id is shown.
			Confirm: func(document saasdiscovery.Item, _ string) (string, bool) {
				return "", document.Text("object") == "list" && document.Has("data")
			}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "assistants", Path: "/v1/assistants", Query: map[string]string{"order": "asc"}, Headers: headers("assistants=v2"), ItemsPath: []string{"data"}, Paging: paging,
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) { return openAIAgent(item, "assistant") }},
			{Name: "agents", Path: "/v1/agents", Query: map[string]string{"order": "asc"}, Headers: headers("agents=v1"), ItemsPath: []string{"data"}, Paging: paging,
				// A project without the agents API answers 404.
				Absent: []int{http.StatusNotFound},
				Map:    func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) { return openAIAgent(item, "agent") }},
		},
	}
}

// openAIAgent maps an assistant or an agent. Only id, name, model and the
// type of each tool are read.
func openAIAgent(item saasdiscovery.Item, objectType string) (saasdiscovery.Entity, bool) {
	id := item.Text("id")
	if id == "" {
		return saasdiscovery.Entity{}, false
	}
	// An assistant or agent may be unnamed.
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if name == "" {
		name = id
	}
	var kinds []string
	for _, tool := range item.Objects("tools") {
		kinds = append(kinds, tool.Text("type"))
	}
	var evidence agentsignals.Evidence
	evidence.ModelProvider("openai")
	tools := evidence.Tools(kinds...)
	return saasdiscovery.Entity{
		Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: objectType, Status: "active", AgentType: objectType, Model: saasdiscovery.CleanText(item.Text("model"), 128),
		// A listed assistant can be run with the project's keys; one with a
		// code interpreter, a shell or a computer tool runs code.
		Posture: agentsignals.Posture{CredentialActive: true, ShellExecution: agentsignals.ToolRunsCode(tools)},
		Signals: evidence.Signals(),
	}, true
}
