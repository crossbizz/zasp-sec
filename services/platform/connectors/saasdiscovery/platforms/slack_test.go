package platforms

import (
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// The response shapes are the ones slack.go documents as unverified.
const (
	slackTeam     = "T024BE7LD"
	slackTeamInfo = `{"ok":true,"team":{"id":"T024BE7LD","name":"Acme","domain":"acme","email_domain":"acme.example","icon":{"image_34":"https://example.invalid/i.png"}}}`
)

func slackRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/api/team.info": saastest.Static(slackTeamInfo),
		"/api/admin.apps.approved.list": func(query url.Values, _ int) saastest.Response {
			if query.Get("team_id") != slackTeam || query.Get("limit") != "200" {
				return saastest.Response{Body: `{"ok":false,"error":"invalid_arguments"}`}
			}
			switch query.Get("cursor") {
			case "":
				return saastest.Response{Body: `{"ok":true,"approved_apps":[
 {"app":{"id":"A01CHATGPT1","name":"ChatGPT","description":"Ask ChatGPT in Slack","is_internal":false},"scopes":[{"name":"chat:write","is_sensitive":true,"token_type":"bot"},{"name":"channels:history","is_sensitive":true,"token_type":"bot"}],"date_updated":1574296707},
 {"app":{"id":"A02CALENDAR","name":"Google Calendar","is_internal":false},"scopes":[{"name":"chat:write","token_type":"bot"}]}
],"response_metadata":{"next_cursor":"bmV4dDoy"}}`}
			case "bmV4dDoy":
				return saastest.Response{Body: `{"ok":true,"approved_apps":[
 {"app":{"id":"A03HELPDESK","name":"Helpdesk Triage","is_internal":true},"scopes":[{"name":"assistant:write","token_type":"bot"},{"name":"chat:write","token_type":"bot"}]},
 {"app":{"id":"A04GLEAN001","name":"Glean","is_internal":false},"scopes":[]}
],"response_metadata":{"next_cursor":""}}`}
			}
			return saastest.Response{Body: `{"ok":false,"error":"invalid_cursor"}`}
		},
	}
}

func TestSlackWorkspaceIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, _ := registry.Platform("slack")
	standIn := saastest.NewNango(t, registry, slackRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, slackTeam)

	// Three of the four approved apps are AI applications; the calendar is not.
	applications := snapshot.Kind("saas_ai_application")
	if len(applications) != 3 || len(snapshot.Kind("saas_agent")) != 0 || len(snapshot.Entities) != 4 {
		t.Fatalf("applications=%d entities=%d: %s", len(applications), len(snapshot.Entities), snapshot.Raw)
	}
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "Acme" || tenant.StableFields["tenant"] != slackTeam {
		t.Fatalf("tenant = %+v", tenant)
	}
	chatgpt := snapshot.Named(t, "saas_ai_application", "ChatGPT")
	posture := chatgpt.Attributes["posture"].(map[string]any)
	if chatgpt.SourceNativeID != "saas:slack:app:A01CHATGPT1" || chatgpt.Attributes["agent_type"] != "assistant" || chatgpt.Attributes["status"] != "approved" || posture["sensitive_data_reach"] != true || posture["credential_active"] != true ||
		!reflect.DeepEqual(chatgpt.Attributes["discovery"], map[string]any{"method": "inferred", "platform": "slack", "signals": []any{"app:chatgpt"}}) {
		t.Fatalf("ChatGPT = %+v", chatgpt)
	}
	// An internal app nobody has heard of is an AI app because Slack granted
	// it the assistant scope.
	internal := snapshot.Named(t, "saas_ai_application", "Helpdesk Triage")
	if !reflect.DeepEqual(internal.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:assistant"}) || internal.Attributes["posture"].(map[string]any)["sensitive_data_reach"] != false {
		t.Fatalf("internal assistant = %+v", internal)
	}
	if glean := snapshot.Named(t, "saas_ai_application", "Glean"); glean.Attributes["agent_type"] != "enterprise_agent" {
		t.Fatalf("Glean = %+v", glean)
	}
	// The team id travels in the query of every list page; the second page
	// carries the provider's cursor.
	calls := standIn.Calls()
	if len(calls) != 3 || calls[0].Path != "/api/team.info" || calls[1].Query.Encode() != "limit=200&team_id="+slackTeam || calls[2].Query.Encode() != "cursor=bmV4dDoy&limit=200&team_id="+slackTeam {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestSlackErrorEnvelopeIsClassified(t *testing.T) {
	t.Parallel()
	registry, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, _ := registry.Platform("slack")
	for body, want := range map[string]collection.FailureCode{
		`{"ok":false,"error":"missing_scope","needed":"admin.apps:read","provided":"team:read"}`: collection.FailureDenied,
		`{"ok":false,"error":"not_allowed_token_type"}`:                                          collection.FailureDenied,
		`{"ok":false,"error":"ratelimited"}`:                                                     collection.FailureRateLimited,
		`{"ok":false,"error":"token_revoked"}`:                                                   collection.FailureRevoked,
		`{"ok":false,"error":"internal_error"}`:                                                  collection.FailureRetryable,
		`{"ok":false,"error":"something_new"}`:                                                   collection.FailureDenied,
	} {
		routes := slackRoutes()
		routes["/api/admin.apps.approved.list"] = saastest.Static(body)
		_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, slackTeam)
		var failure *collection.Failure
		if !errors.As(err, &failure) || failure.Code() != want {
			t.Fatalf("%s: %v, want %s", body, err, want)
		}
	}
	// A refused team.info never reaches the app list.
	routes := slackRoutes()
	routes["/api/team.info"] = saastest.Static(`{"ok":false,"error":"invalid_auth"}`)
	standIn := saastest.NewNango(t, registry, routes)
	_, err = saastest.Run(t, standIn, registry, platform, slackTeam)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied || len(standIn.Calls()) != 1 {
		t.Fatalf("refused team.info: %v after %d calls", err, len(standIn.Calls()))
	}
}
