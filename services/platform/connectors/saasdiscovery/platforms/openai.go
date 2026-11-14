package platforms

import (
	"net/http"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// OpenAI lists the projects of one OpenAI API organization and the service
// accounts of every project, through the organization (admin) API. A project
// and a service account are each recorded as an AI application: a project is
// where an application's API usage lives and a service account is the
// identity an application calls the API with.
//
// Assistants are not listed. The admin API does not expose them: they are
// read with a key of the project they belong to, which this connection does
// not hold.
//
// The connection is an admin API key held by Nango. No key value is read:
// the service account list states ids, names and roles only.
//
// UNVERIFIED: the paths and the response members below are written from
// memory of the OpenAI API and have not been run against a real
// organization. Before the first production use, check against an
// organization:
//   - GET /v1/me, with the admin key, answers
//     {"orgs":{"data":[{"id":"org-…","title":"…"}]}}. No admin endpoint
//     states the organization id, so the tenant is confirmed by finding it
//     in this list. If an admin key may not call /v1/me the connection
//     cannot be authorized;
//   - GET /v1/organization/projects answers
//     {"data":[{"id":"proj_…","name":"…","status":"active"}],"last_id":"…",
//     "has_more":true} and continues with after=<last_id>;
//   - GET /v1/organization/projects/{project}/service_accounts answers the
//     same list shape with {"id":"svc_acct_…","name":"…","role":"member"};
//   - the Nango integration key (openai-admin) and that it sends the key as
//     a bearer token.
func OpenAI() saasdiscovery.Platform {
	listPaging := func(size int) saasdiscovery.Paging {
		return saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", NextPath: []string{"last_id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: size}
	}
	return saasdiscovery.Platform{
		Token: "openai", DisplayName: "OpenAI",
		Description: "Inventory the projects and service accounts of one OpenAI API organization through a Nango connection.",
		Nango: nango.Entry{Key: "openai-admin", ProviderHost: "api.openai.com", AuthMode: "api_key", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/v1/me"},
			{Method: http.MethodGet, PathPrefix: "/v1/organization/projects", QueryKeys: []string{"after", "limit"}},
			{Method: http.MethodGet, PathPrefix: "/v1/organization/projects/", QueryKeys: []string{"after", "limit"}},
		}},
		RequiredScopes: []string{"api.management.read"},
		TenantLabel:    "Organization ID", TenantHint: "The organization ID, which starts with org- (Settings, Organization, General).",
		TenantPattern:  regexp.MustCompile(`^org-[A-Za-z0-9]{8,64}$`),
		AccessGuidance: "Create the Nango connection with an admin API key of the organization. The product never receives the key; it reads project and service account names only.",
		Tenant: saasdiscovery.TenantLookup{Path: "/v1/me", Confirm: func(document saasdiscovery.Item, tenantID string) (string, bool) {
			for _, organization := range document.Objects("orgs", "data") {
				if organization.Text("id") == tenantID {
					return organization.Text("title"), true
				}
			}
			return "", false
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "projects", Path: "/v1/organization/projects", ItemsPath: []string{"data"}, Paging: listPaging(100), Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
				return openAIEntity(item, "project", "api_project", item.Text("status"))
			}},
			{Name: "service_accounts", Path: "/v1/organization/projects/{parent}/service_accounts", ItemsPath: []string{"data"}, Paging: listPaging(100),
				// A project that was archived between the two requests
				// answers 404 for its service accounts.
				Absent: []int{http.StatusNotFound},
				Parent: &saasdiscovery.ParentList{Path: "/v1/organization/projects", ItemsPath: []string{"data"}, Paging: listPaging(1), ID: func(item saasdiscovery.Item) string { return item.Text("id") }},
				MapChild: func(_ string, item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					entity, keep := openAIEntity(item, "service_account", "service_account", "active")
					entity.AgentType = saasdiscovery.CleanText(item.Text("role"), 128)
					// A listed service account can call the API.
					entity.Posture = agentsignals.Posture{CredentialActive: true}
					return entity, keep
				}},
		},
	}
}

func openAIEntity(item saasdiscovery.Item, objectType, surface, status string) (saasdiscovery.Entity, bool) {
	id := item.Text("id")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if id == "" {
		return saasdiscovery.Entity{}, false
	}
	if name == "" {
		name = id
	}
	if status = saasdiscovery.CleanText(status, 64); status == "" {
		status = "unknown"
	}
	var evidence agentsignals.Evidence
	evidence.ModelProvider("openai")
	evidence.Surface(surface)
	return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: id, DisplayName: name, ObjectType: objectType, Status: status, Signals: evidence.Signals()}, true
}
