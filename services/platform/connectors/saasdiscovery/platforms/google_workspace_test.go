package platforms

import (
	"bytes"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// The response shapes are the ones google_workspace.go documents as
// unverified.
const googleCustomer = `{"kind":"admin#directory#customer","id":"C03az79cb","customerDomain":"example.com","alternateEmail":"admin@example.org"}`

func googleEvent(user, app, clientID string, scopes string) string {
	return `{"id":{"time":"2026-11-01T10:00:00.000Z","applicationName":"token","customerId":"C03az79cb"},"actor":{"email":"` + user + `","profileId":"1"},
 "events":[{"type":"auth","name":"authorize","parameters":[{"name":"client_id","value":"` + clientID + `"},{"name":"app_name","value":"` + app + `"},{"name":"client_type","value":"WEB"},{"name":"scope","multiValue":[` + scopes + `]}]}]}`
}

func googleRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/admin/directory/v1/customers/my_customer": saastest.Static(googleCustomer),
		"/admin/reports/v1/activity/users/all/applications/token": func(query url.Values, _ int) saastest.Response {
			if query.Get("eventName") != "authorize" || query.Get("maxResults") != "200" {
				return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
			}
			switch query.Get("pageToken") {
			case "":
				return saastest.Response{Body: `{"kind":"admin#reports#activities","items":[` +
					googleEvent("ana@example.com", "ChatGPT", "1001.apps.googleusercontent.com", `"https://www.googleapis.com/auth/drive.readonly","openid"`) + `,` +
					googleEvent("ben@example.com", "Trello", "1002.apps.googleusercontent.com", `"https://www.googleapis.com/auth/calendar"`) + `,` +
					googleEvent("ben@example.com", "ChatGPT", "1001.apps.googleusercontent.com", `"openid"`) +
					`],"nextPageToken":"A:1730455200000000:-123:C03az79cb"}`}
			case "A:1730455200000000:-123:C03az79cb":
				return saastest.Response{Body: `{"items":[` +
					googleEvent("cy@example.com", "Claude", "1003.apps.googleusercontent.com", `"https://www.googleapis.com/auth/drive.file","email"`) + `,` +
					googleEvent("cy@example.com", "ChatGPT", "1001.apps.googleusercontent.com", `"https://mail.google.com/"`) + `]}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps": saastest.Static(`{"items":[{"id":{"applicationName":"gemini_in_workspace_apps"},"actor":{"email":"ana@example.com"},"events":[{"name":"feature_utilization","parameters":[{"name":"app_name","value":"docs"}]}]}]}`),
	}
}

func TestGoogleWorkspaceCustomerIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "google_workspace")
	standIn := saastest.NewNango(t, registry, googleRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, "C03az79cb")

	// Three grants of ChatGPT on two pages are one application; Trello is
	// not an AI application.
	applications := snapshot.Kind("saas_ai_application")
	if len(applications) != 3 || len(snapshot.Entities) != 4 {
		t.Fatalf("applications=%d: %s", len(applications), snapshot.Raw)
	}
	chatgpt := snapshot.Named(t, "saas_ai_application", "ChatGPT")
	// The first grant seen is the one reported: it could read Drive files.
	if chatgpt.SourceNativeID != "saas:google_workspace:oauth_app:1001.apps.googleusercontent.com" || chatgpt.Attributes["status"] != "authorized" ||
		chatgpt.Attributes["posture"].(map[string]any)["sensitive_data_reach"] != true || chatgpt.Attributes["posture"].(map[string]any)["credential_active"] != false ||
		!reflect.DeepEqual(chatgpt.Attributes["discovery"], map[string]any{"method": "inferred", "platform": "google_workspace", "signals": []any{"app:chatgpt", "surface:oauth_grant"}}) {
		t.Fatalf("ChatGPT = %+v", chatgpt)
	}
	// drive.file reaches only files opened with the application.
	if claude := snapshot.Named(t, "saas_ai_application", "Claude"); claude.Attributes["posture"].(map[string]any)["sensitive_data_reach"] != false {
		t.Fatalf("Claude = %+v", claude.Attributes)
	}
	gemini := snapshot.Named(t, "saas_ai_application", "Gemini in Google Workspace")
	if gemini.Attributes["status"] != "in_use" || !reflect.DeepEqual(gemini.Attributes["discovery"].(map[string]any)["signals"], []any{"app:gemini", "model:google"}) {
		t.Fatalf("Gemini = %+v", gemini.Attributes)
	}
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "example.com" {
		t.Fatalf("tenant = %+v", tenant)
	}
	// Who authorized what is not recorded.
	for _, personal := range []string{"ana@example.com", "ben@example.com", "cy@example.com", "admin@example.org"} {
		if bytes.Contains(snapshot.Raw, []byte(personal)) {
			t.Fatalf("the snapshot holds %s", personal)
		}
	}
	// Four requests, to the fixed Admin SDK host.
	if calls := standIn.Calls(); len(calls) != 4 || calls[0].Host != "" || calls[3].Query.Get("maxResults") != "1" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestGoogleWorkspaceWithoutGeminiOrGrantsIsATenantOnly(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "google_workspace")
	routes := googleRoutes()
	routes["/admin/reports/v1/activity/users/all/applications/token"] = saastest.Static(`{"kind":"admin#reports#activities"}`)
	routes["/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
	}
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "C03az79cb"); len(snapshot.Entities) != 1 {
		t.Fatalf("entities = %d", len(snapshot.Entities))
	}
	for scope, want := range map[string]bool{
		"https://mail.google.com/":                                true,
		"https://www.googleapis.com/auth/gmail.readonly":          true,
		"https://www.googleapis.com/auth/drive":                   true,
		"https://www.googleapis.com/auth/drive.file":              false,
		"https://www.googleapis.com/auth/drive.metadata.readonly": true,
		"https://www.googleapis.com/auth/userinfo.email":          false,
		"https://www.googleapis.com/auth/drivefoo":                false,
		"openid":                          false,
		"https://evil.example/auth/drive": false,
	} {
		if got := googleSensitiveScope(scope); got != want {
			t.Errorf("scope %q sensitive = %t", scope, got)
		}
	}
}
