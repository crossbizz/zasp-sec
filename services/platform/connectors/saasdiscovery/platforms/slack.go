package platforms

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// Slack lists the apps approved for one workspace and keeps the ones that
// are AI applications: an app whose name is in the reviewed application
// catalog (agentsignals), or one that holds the assistant:write scope, which
// Slack grants to apps of its "agents and AI apps" surface.
//
// UNVERIFIED: the methods and the response members below are written from
// memory of the Slack Web API and have not been run against a real
// workspace. Before the first production use, check against a workspace:
//   - team.info answers {"ok":true,"team":{"id":"T…","name":"…"}};
//   - admin.apps.approved.list accepts GET with team_id, limit and cursor,
//     needs the admin.apps:read scope (an Enterprise Grid organization
//     admin token) and answers {"ok":true,"approved_apps":[{"app":{"id",
//     "name","is_internal"},"scopes":[{"name"}]}],"response_metadata":
//     {"next_cursor"}};
//   - a workspace outside Enterprise Grid answers {"ok":false,"error":…}
//     for that method; the collection then ends as denied, because no other
//     Slack method lists installed apps with a read scope;
//   - assistant:write is the scope of an agent or AI app.
func Slack() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "slack", DisplayName: "Slack AI apps",
		Description: "Inventory the AI apps approved in one Slack workspace through a Nango connection.",
		Nango: nango.Entry{Key: "slack", ProviderHost: "slack.com", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/team.info"},
			{Method: http.MethodGet, PathPrefix: "/api/admin.apps.approved.list", QueryKeys: []string{"cursor", "limit", "team_id"}},
		}},
		RequiredScopes: []string{"admin.apps:read", "team:read"},
		TenantLabel:    "Workspace ID", TenantHint: "The workspace (team) ID, which starts with T.",
		TenantPattern:  regexp.MustCompile(`^T[A-Z0-9]{8,20}$`),
		AccessGuidance: "Create the Nango connection as an organization admin with the user scopes admin.apps:read and team:read. Both are read scopes.",
		Failure:        slackFailure,
		Tenant: saasdiscovery.TenantLookup{Path: "/api/team.info", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("team", "id"), Name: document.Text("team", "name")}, document.Bool("ok") && document.Has("team", "id")
		}},
		Lists: []saasdiscovery.ListEndpoint{{
			Name: "approved_apps", Path: "/api/admin.apps.approved.list", Query: map[string]string{"team_id": saasdiscovery.TenantQueryValue}, ItemsPath: []string{"approved_apps"},
			Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "cursor", NextPath: []string{"response_metadata", "next_cursor"}, LimitParam: "limit", PageSize: 200},
			Map:    slackApprovedApp,
		}},
	}
}

// slackFailure reads Slack's error envelope: a refused call answers 200
// with {"ok":false,"error":"…"}. Only the error token is read.
func slackFailure(document saasdiscovery.Item) (collection.FailureCode, bool) {
	if document.Bool("ok") {
		return "", false
	}
	switch document.Text("error") {
	case "ratelimited", "rate_limited":
		return collection.FailureRateLimited, true
	case "token_revoked", "account_inactive", "token_expired":
		return collection.FailureRevoked, true
	case "internal_error", "fatal_error", "service_unavailable", "request_timeout":
		return collection.FailureRetryable, true
	case "invalid_cursor", "invalid_arguments", "invalid_limit":
		return collection.FailureMalformed, true
	}
	// missing_scope, not_allowed_token_type, invalid_auth, not_authed,
	// feature_not_enabled, not_an_admin, team_access_not_granted and any
	// error this list does not know: the connection may not read this.
	return collection.FailureDenied, true
}

// slackSensitiveScopes are the granted scopes that let an app read what
// people wrote or uploaded.
var slackSensitiveScopes = map[string]bool{
	"channels:history": true, "groups:history": true, "im:history": true, "mpim:history": true, "files:read": true, "search:read": true,
	"search:read.public": true, "search:read.private": true, "search:read.im": true, "search:read.mpim": true, "search:read.files": true, "canvases:read": true,
}

func slackApprovedApp(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	id := item.Text("app", "id")
	name := saasdiscovery.CleanText(item.Text("app", "name"), 256)
	if id == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	var evidence agentsignals.Evidence
	category := evidence.Application(name)
	sensitive := false
	for _, scope := range item.Objects("scopes") {
		scopeName := strings.ToLower(scope.Text("name"))
		if scopeName == "assistant:write" {
			evidence.Surface("assistant")
			if category == "" {
				category = "assistant"
			}
		}
		sensitive = sensitive || slackSensitiveScopes[scopeName]
	}
	signals := evidence.Signals()
	if len(signals) == 0 {
		// Not an AI application: it stays out of the inventory.
		return saasdiscovery.Entity{}, false
	}
	return saasdiscovery.Entity{
		Kind: saasdiscovery.KindAIApplication, NativeID: id, DisplayName: name, ObjectType: "app", Status: "approved", AgentType: category,
		// The posture facts the API states: the app is approved for the
		// workspace, and whether its granted scopes read messages or files.
		Posture: agentsignals.Posture{CredentialActive: true, SensitiveDataReach: sensitive},
		Signals: signals,
	}, true
}
