package platforms

import (
	"net/http"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// Anthropic lists the workspaces and the API keys of one Anthropic API
// organization through the Admin API. A workspace and an API key are each
// recorded as an AI application: a workspace is where an application's API
// usage lives and a key is what an application calls the API with.
//
// Of an API key only the id, the name and the status are recorded. The list
// also carries a partial hint of the key's value; it is never read.
//
// UNVERIFIED: the paths and the response members below are written from
// memory of the Anthropic Admin API and have not been run against a real
// organization. Before the first production use, check against an
// organization:
//   - GET /v1/organizations/me answers {"id":"<uuid>","name":"…"};
//   - GET /v1/organizations/workspaces answers
//     {"data":[{"id":"wrkspc_…","name":"…","archived_at":null}],
//     "has_more":true,"last_id":"…"} and continues with after_id=<last_id>;
//     include_archived=true also lists archived workspaces;
//   - GET /v1/organizations/api_keys answers the same list shape with
//     {"id":"apikey_…","name":"…","status":"active"|"inactive"|"archived"};
//   - the Nango integration key (anthropic-admin), and that Nango sends the
//     admin key in x-api-key together with the anthropic-version header.
func Anthropic() saasdiscovery.Platform {
	paging := saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after_id", NextPath: []string{"last_id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: 100}
	return saasdiscovery.Platform{
		Token: "anthropic", DisplayName: "Anthropic",
		Description: "Inventory the workspaces and API keys of one Anthropic API organization through a Nango connection. Key values are never read.",
		Nango: nango.Entry{Key: "anthropic-admin", ProviderHost: "api.anthropic.com", AuthMode: "api_key", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/v1/organizations/me"},
			{Method: http.MethodGet, PathPrefix: "/v1/organizations/workspaces", QueryKeys: []string{"after_id", "include_archived", "limit"}},
			{Method: http.MethodGet, PathPrefix: "/v1/organizations/api_keys", QueryKeys: []string{"after_id", "limit"}},
		}},
		RequiredScopes: []string{"admin"},
		TenantLabel:    "Organization ID", TenantHint: "The organization ID, a UUID (Console, Settings, Organization).",
		TenantPattern:  regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
		AccessGuidance: "Create the Nango connection with an Admin API key of the organization. The product never receives the key; it reads workspace and key names and states only.",
		Tenant: saasdiscovery.TenantLookup{Path: "/v1/organizations/me", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("id"), Name: document.Text("name")}, document.Text("id") != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "workspaces", Path: "/v1/organizations/workspaces", Query: map[string]string{"include_archived": "true"}, ItemsPath: []string{"data"}, Paging: paging,
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					status := "active"
					if item.Has("archived_at") {
						status = "archived"
					}
					return anthropicEntity(item, "workspace", "api_workspace", status, false)
				}},
			{Name: "api_keys", Path: "/v1/organizations/api_keys", ItemsPath: []string{"data"}, Paging: paging,
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					status := saasdiscovery.CleanText(item.Text("status"), 64)
					if status == "" {
						status = "unknown"
					}
					return anthropicEntity(item, "api_key", "api_key", status, status == "active")
				}},
		},
	}
}

// anthropicEntity reads the id and the name of a list item and nothing else
// of it.
func anthropicEntity(item saasdiscovery.Item, objectType, surface, status string, credentialActive bool) (saasdiscovery.Entity, bool) {
	id := item.Text("id")
	if id == "" {
		return saasdiscovery.Entity{}, false
	}
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if name == "" {
		name = id
	}
	var evidence agentsignals.Evidence
	evidence.ModelProvider("anthropic")
	evidence.Surface(surface)
	return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: id, DisplayName: name, ObjectType: objectType, Status: status,
		Posture: agentsignals.Posture{CredentialActive: credentialActive}, Signals: evidence.Signals()}, true
}
