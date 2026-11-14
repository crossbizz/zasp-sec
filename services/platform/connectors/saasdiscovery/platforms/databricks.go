package platforms

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// Databricks lists the model serving endpoints of one workspace. An endpoint
// whose task says it serves an agent (Mosaic AI Agent Framework) is an
// agent; every other serving endpoint is an AI application.
//
// UNVERIFIED: the request paths and the response members below are written
// from memory of the Databricks REST API and have not been run against a
// real workspace. Before the first production use, check against a
// workspace:
//   - GET /api/2.1/unity-catalog/current-metastore-assignment answers
//     {"workspace_id": <number>, "metastore_id": "…"} (it needs Unity
//     Catalog; a workspace without it answers an error and the connection
//     cannot be authorized);
//   - GET /api/2.0/serving-endpoints answers {"endpoints":[…]} in one
//     response, each with name, id, state.ready, task, and
//     config.served_entities[] carrying external_model{provider,name},
//     foundation_model{name} or entity_name;
//   - the agent task values start with "agent/";
//   - the Nango integration for a workspace and the OAuth scope name;
//   - the three address forms of a workspace this definition accepts.
//
// The API host differs per workspace, and the workspace's address is what
// its people know it by. The tenant id is therefore the workspace host
// (dbc-a1b2c3d4-e5f6.cloud.databricks.com,
// adb-1234567890123456.7.azuredatabricks.net,
// 1234567890123456.7.gcp.databricks.com). Every request is sent to that host
// only, and only when it is a Databricks address that resolves publicly.
//
// No Databricks API states the workspace's host. The tenant lookup therefore
// confirms the tenant instead of comparing an id: it requires an answer that
// names a workspace, from the tenant's own host, and where the host carries
// the workspace id (Azure and Google Cloud) it requires that id to be the
// one the API states. On AWS the proof is that the workspace's own host
// answered the connection's credential.
//
// Sign-in from the product is not declared: the name of the connection
// parameter the Nango integration takes for the workspace host is not known
// to this definition. The integration names an existing Nango connection.
func Databricks() saasdiscovery.Platform {
	hosts := regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,61}\.cloud\.databricks\.com|adb-[0-9]{6,20}\.[0-9]{1,2}\.azuredatabricks\.net|[0-9]{6,20}\.[0-9]{1,2}\.gcp\.databricks\.com)$`)
	return saasdiscovery.Platform{
		Token: "databricks", DisplayName: "Databricks",
		Description: "Inventory the model serving endpoints and served agents of one Databricks workspace through a Nango connection.",
		Nango: nango.Entry{Key: "databricks", AuthMode: "oauth", HostPattern: hosts, HostSuffixes: []string{".cloud.databricks.com", ".azuredatabricks.net", ".gcp.databricks.com"}, Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/2.1/unity-catalog/current-metastore-assignment"},
			{Method: http.MethodGet, PathPrefix: "/api/2.0/serving-endpoints"},
		}},
		HostTemplate:   saasdiscovery.TenantValue,
		RequiredScopes: []string{"all-apis"},
		TenantLabel:    "Workspace address", TenantHint: "The host of the workspace URL, without https://, for example dbc-a1b2c3d4-e5f6.cloud.databricks.com.",
		TenantPattern:  hosts,
		AccessGuidance: "Create the Nango connection as a service principal or user that has Can View on the serving endpoints to inventory. No write permission is needed.",
		Tenant:         saasdiscovery.TenantLookup{Path: "/api/2.1/unity-catalog/current-metastore-assignment", Confirm: databricksWorkspace},
		Lists: []saasdiscovery.ListEndpoint{{
			Name: "serving_endpoints", Path: "/api/2.0/serving-endpoints", ItemsPath: []string{"endpoints"},
			Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Map: databricksServingEndpoint,
		}},
	}
}

var databricksHostWorkspaceID = regexp.MustCompile(`^(?:adb-([0-9]{6,20})\.[0-9]{1,2}\.azuredatabricks\.net|([0-9]{6,20})\.[0-9]{1,2}\.gcp\.databricks\.com)$`)

// databricksWorkspace confirms that the answer of the workspace's own host
// is about that workspace. See Databricks for what this proves.
func databricksWorkspace(document saasdiscovery.Item, host string) (string, bool) {
	workspaceID := document.Text("workspace_id")
	if workspaceID == "" {
		return "", false
	}
	if match := databricksHostWorkspaceID.FindStringSubmatch(host); match != nil && match[1]+match[2] != workspaceID {
		// The host says one workspace and the API another.
		return "", false
	}
	return "Databricks workspace " + host, true
}

func databricksServingEndpoint(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if name == "" {
		return saasdiscovery.Entity{}, false
	}
	// The endpoint name is unique in a workspace and is what every other
	// Databricks API refers to; the id is used when the API states one.
	nativeID := item.Text("id")
	if nativeID == "" {
		nativeID = name
	}
	task := saasdiscovery.CleanText(item.Text("task"), 128)
	status := saasdiscovery.CleanText(item.Text("state", "ready"), 64)
	if status == "" {
		status = "UNKNOWN"
	}
	entity := saasdiscovery.Entity{
		NativeID: nativeID, DisplayName: name, ObjectType: "serving_endpoint", Status: status, AgentType: task,
		// The one posture fact the API states: the endpoint is live.
		Posture: agentsignals.Posture{CredentialActive: status == "READY"},
	}
	var evidence agentsignals.Evidence
	evidence.Surface("model_serving")
	entities := item.Objects("config", "served_entities")
	if len(entities) == 0 {
		entities = item.Objects("config", "served_models")
	}
	for _, served := range entities {
		model := served.Text("external_model", "name")
		if provider := served.Text("external_model", "provider"); provider != "" {
			evidence.ModelProvider(provider)
		}
		if model == "" {
			if model = served.Text("foundation_model", "name"); model != "" {
				evidence.ModelProvider("databricks")
			}
		}
		if model == "" {
			if model = served.Text("entity_name"); model == "" {
				model = served.Text("model_name")
			}
		}
		if entity.Model == "" {
			entity.Model = saasdiscovery.CleanText(model, 128)
		}
	}
	if strings.HasPrefix(task, "agent/") {
		entity.Kind = saasdiscovery.KindAgent
		return entity, true
	}
	entity.Kind = saasdiscovery.KindAIApplication
	entity.Signals = evidence.Signals()
	return entity, true
}
