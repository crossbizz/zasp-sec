package platforms

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// GoogleWorkspace lists the third-party AI applications that people of one
// Workspace customer granted OAuth access to, and whether Gemini is in use
// in the Workspace apps. Both come from the Admin SDK Reports API.
//
// The token activity report is a log: it has one event for every grant, so
// the same application appears once per person who authorized it. The list
// is declared Distinct and every application is reported once. The log goes
// back as far as Google keeps it (about 180 days), so an application
// authorized earlier and never again is not listed. The Admin SDK Directory
// API lists current tokens only per user (users.tokens.list), which would be
// one request per person of the domain; this definition does not do that.
//
// UNVERIFIED: the paths, parameters and response members below are written
// from memory of the Admin SDK and have not been run against a real
// customer. Before the first production use, check against a customer:
//   - GET /admin/directory/v1/customers/my_customer answers
//     {"id":"C…","customerDomain":"…"};
//   - GET /admin/reports/v1/activity/users/all/applications/token with
//     eventName=authorize, maxResults and pageToken answers
//     {"items":[{"events":[{"name":"authorize","parameters":[
//     {"name":"app_name","value":"…"},{"name":"client_id","value":"…"},
//     {"name":"scope","multiValue":["…"]}]}]}],"nextPageToken":"…"};
//   - the Gemini usage report is the application
//     gemini_in_workspace_apps of the same API, and a customer without it
//     answers 400 or 404;
//   - the scopes admin.reports.audit.readonly and
//     admin.directory.customer.readonly are enough;
//   - the Nango integration key (google-workspace-admin).
func GoogleWorkspace() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "google_workspace", DisplayName: "Google Workspace",
		Description: "Inventory the third-party AI applications people granted access to in one Google Workspace customer, and Gemini usage.",
		Nango: nango.Entry{Key: "google-workspace-admin", ProviderHost: "admin.googleapis.com", AuthMode: "oauth", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/admin/directory/v1/customers/my_customer"},
			{Method: http.MethodGet, PathPrefix: "/admin/reports/v1/activity/users/all/applications/token", QueryKeys: []string{"eventName", "maxResults", "pageToken"}},
			{Method: http.MethodGet, PathPrefix: "/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps", QueryKeys: []string{"maxResults"}},
		}},
		RequiredScopes: []string{"https://www.googleapis.com/auth/admin.directory.customer.readonly", "https://www.googleapis.com/auth/admin.reports.audit.readonly"},
		TenantLabel:    "Customer ID", TenantHint: "The Workspace customer ID, which starts with C (Admin console, Account settings).",
		TenantPattern:  regexp.MustCompile(`^C[0-9a-z]{6,16}$`),
		AccessGuidance: "Sign in as an administrator whose role includes Reports. The connection reads audit reports and the customer record; it changes nothing.",
		SignIn:         &saasdiscovery.SignIn{AuthorizationHost: "accounts.google.com", AuthorizationPath: "/o/oauth2/v2/auth"},
		Tenant: saasdiscovery.TenantLookup{Path: "/admin/directory/v1/customers/my_customer", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("id"), Name: document.Text("customerDomain")}, document.Text("id") != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "oauth_apps", Path: "/admin/reports/v1/activity/users/all/applications/token", Query: map[string]string{"eventName": "authorize"}, ItemsPath: []string{"items"}, Distinct: true,
				// A page is at most 1 MiB through the proxy; 200 events fit.
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "pageToken", NextPath: []string{"nextPageToken"}, LimitParam: "maxResults", PageSize: 200},
				Map:    googleAuthorizedApplication},
			// One event is enough to know Gemini is in use. Every event maps
			// to the same object, which Distinct reports once.
			{Name: "gemini_usage", Path: "/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps", Query: map[string]string{"maxResults": "1"}, ItemsPath: []string{"items"}, Distinct: true,
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Absent: []int{http.StatusBadRequest, http.StatusNotFound},
				Map: func(saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					var evidence agentsignals.Evidence
					category := evidence.Application("Gemini")
					evidence.ModelProvider("google")
					return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: "gemini_in_workspace_apps", DisplayName: "Gemini in Google Workspace", ObjectType: "gemini", Status: "in_use", AgentType: category, Signals: evidence.Signals()}, true
				}},
		},
	}
}

// googleSensitiveScope reports whether an OAuth scope lets an application
// read what people wrote or stored: mail, Drive files, documents, calendars.
func googleSensitiveScope(scope string) bool {
	lower := strings.ToLower(scope)
	if lower == "https://mail.google.com/" {
		return true
	}
	name, isGoogle := strings.CutPrefix(lower, "https://www.googleapis.com/auth/")
	if !isGoogle || name == "drive.file" || name == "drive.appdata" {
		// drive.file reaches only the files a person opened with the app.
		return false
	}
	for _, prefix := range []string{"drive", "gmail", "documents", "spreadsheets", "presentations", "calendar", "contacts", "chat.messages"} {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

func googleAuthorizedApplication(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	for _, event := range item.Objects("events") {
		if event.Text("name") != "authorize" {
			continue
		}
		clientID, appName, sensitive := "", "", false
		for _, parameter := range event.Objects("parameters") {
			switch parameter.Text("name") {
			case "client_id":
				clientID = parameter.Text("value")
			case "app_name":
				appName = saasdiscovery.CleanText(parameter.Text("value"), 256)
			case "scope":
				for _, scope := range parameter.Texts("multiValue") {
					sensitive = sensitive || googleSensitiveScope(scope)
				}
			}
		}
		if clientID == "" || appName == "" {
			continue
		}
		var evidence agentsignals.Evidence
		category := evidence.Application(appName)
		if category == "" {
			// Not an AI application: it stays out of the inventory.
			return saasdiscovery.Entity{}, false
		}
		evidence.Surface("oauth_grant")
		return saasdiscovery.Entity{
			Kind: saasdiscovery.KindAIApplication, NativeID: clientID, DisplayName: appName, ObjectType: "oauth_app", Status: "authorized", AgentType: category,
			// The report states that a grant was made and which scopes it
			// carried. It does not state that the grant still exists, so
			// no live credential is claimed.
			Posture: agentsignals.Posture{SensitiveDataReach: sensitive},
			Signals: evidence.Signals(),
		}, true
	}
	return saasdiscovery.Entity{}, false
}
