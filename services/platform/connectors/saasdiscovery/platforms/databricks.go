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
//   - the Nango integration for a workspace and the OAuth scope name.
//
// The workspace host is part of the Nango connection, not of this
// definition: Nango sends the request to the workspace the connection was
// created for. ProviderHost is only the name the proxy adapter resolves to
// refuse a non-public destination.
func Databricks() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "databricks", DisplayName: "Databricks",
		Description: "Inventory the model serving endpoints and served agents of one Databricks workspace through a Nango connection.",
		Nango: nango.Entry{Key: "databricks", ProviderHost: "accounts.cloud.databricks.com", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/2.1/unity-catalog/current-metastore-assignment"},
			{Method: http.MethodGet, PathPrefix: "/api/2.0/serving-endpoints"},
		}},
		RequiredScopes: []string{"all-apis"},
		TenantLabel:    "Workspace ID", TenantHint: "The numeric workspace ID, the o= value of the workspace URL.",
		TenantPattern:  regexp.MustCompile(`^[1-9][0-9]{5,19}$`),
		AccessGuidance: "Create the Nango connection as a service principal or user that has Can View on the serving endpoints to inventory. No write permission is needed.",
		Tenant: saasdiscovery.TenantLookup{Path: "/api/2.1/unity-catalog/current-metastore-assignment", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			id := document.Text("workspace_id")
			return saasdiscovery.Tenant{ID: id, Name: "Databricks workspace " + id}, id != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{{
			Name: "serving_endpoints", Path: "/api/2.0/serving-endpoints", ItemsPath: []string{"endpoints"},
			Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Map: databricksServingEndpoint,
		}},
	}
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
