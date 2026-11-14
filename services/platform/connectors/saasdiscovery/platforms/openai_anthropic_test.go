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

// The response shapes are the ones openai.go and anthropic.go document as
// unverified.
const (
	openAIOrganization = "org-AbCdEfGh12345678"
	openAIMe           = `{"object":"user","id":"user-1","name":"Ana","orgs":{"object":"list","data":[{"object":"organization","id":"org-Zz99Zz99Zz99Zz99","title":"Personal"},{"object":"organization","id":"org-AbCdEfGh12345678","title":"Acme"}]}}`
)

func openAIRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/v1/me": saastest.Static(openAIMe),
		"/v1/organization/projects": func(query url.Values, _ int) saastest.Response {
			projects := []string{`{"id":"proj_a","object":"organization.project","name":"Support bot","created_at":1711471533,"archived_at":null,"status":"active"}`,
				`{"id":"proj_b","object":"organization.project","name":"Search","created_at":1711471534,"archived_at":null,"status":"active"}`}
			after := map[string]int{"": 0, "proj_a": 1, "proj_b": 2}
			start, known := after[query.Get("after")]
			if !known {
				return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
			}
			// The list of all projects asks for 100; the walk of the parent
			// list asks for one at a time.
			size := 1
			if query.Get("limit") == "100" {
				size = 100
			}
			end := min(start+size, len(projects))
			last := `null`
			if end > start {
				last = fmt.Sprintf(`"proj_%c"`, 'a'+end-1)
			}
			return saastest.Response{Body: `{"object":"list","data":[` + strings.Join(projects[start:end], ",") + `],"first_id":"proj_a","last_id":` + last + `,"has_more":` + fmt.Sprint(end < len(projects)) + `}`}
		},
		"/v1/organization/projects/proj_a/service_accounts": saastest.Static(`{"object":"list","data":[
 {"object":"organization.project.service_account","id":"svc_acct_1","name":"ci-pipeline","role":"member","created_at":1711471533},
 {"object":"organization.project.service_account","id":"svc_acct_2","name":"batch-jobs","role":"owner","created_at":1711471540}
],"first_id":"svc_acct_1","last_id":"svc_acct_2","has_more":false}`),
		"/v1/organization/projects/proj_b/service_accounts": saastest.Static(`{"object":"list","data":[],"first_id":null,"last_id":null,"has_more":false}`),
	}
}

func TestOpenAIOrganizationIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "openai")
	standIn := saastest.NewNango(t, registry, openAIRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, openAIOrganization)

	if applications := snapshot.Kind("saas_ai_application"); len(applications) != 4 || len(snapshot.Entities) != 5 {
		t.Fatalf("applications=%d: %s", len(applications), snapshot.Raw)
	}
	project := snapshot.Named(t, "saas_ai_application", "Support bot")
	if project.SourceNativeID != "saas:openai:project:proj_a" || project.Attributes["status"] != "active" ||
		!reflect.DeepEqual(project.Attributes["discovery"], map[string]any{"method": "inferred", "platform": "openai", "signals": []any{"model:openai", "surface:api_project"}}) {
		t.Fatalf("project = %+v", project)
	}
	account := snapshot.Named(t, "saas_ai_application", "batch-jobs")
	if account.SourceNativeID != "saas:openai:service_account:svc_acct_2" || account.Attributes["agent_type"] != "owner" || account.Attributes["posture"].(map[string]any)["credential_active"] != true ||
		!reflect.DeepEqual(account.Attributes["discovery"].(map[string]any)["signals"], []any{"model:openai", "surface:service_account"}) {
		t.Fatalf("service account = %+v", account)
	}
	// The organization is confirmed among the ones the key's owner belongs
	// to and named by its title.
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "Acme" || tenant.StableFields["tenant"] != openAIOrganization {
		t.Fatalf("tenant = %+v", tenant)
	}
	// The service accounts are read under each project in turn.
	var paths []string
	for _, call := range standIn.Calls() {
		paths = append(paths, call.Path+"?"+call.Query.Get("after"))
	}
	want := []string{"/v1/me?", "/v1/organization/projects?", "/v1/organization/projects?", "/v1/organization/projects/proj_a/service_accounts?", "/v1/organization/projects?proj_a", "/v1/organization/projects/proj_b/service_accounts?"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("calls = %v", paths)
	}
	// An organization the key does not belong to is refused.
	other := saastest.NewNango(t, registry, openAIRoutes())
	_, err := saastest.Run(t, other, registry, platform, "org-NotThisOne1234567")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied || len(other.Calls()) != 1 {
		t.Fatalf("another organization: %v", err)
	}
}

const (
	anthropicOrganization = "6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b"
	// A hint of a key's value, as the list returns it. It is assembled so
	// the file holds nothing shaped like a key.
	anthropicKeyHint = "hint-" + "R2D" + "..." + "igAA"
)

func anthropicRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/v1/organizations/me": saastest.Static(`{"id":"` + anthropicOrganization + `","type":"organization","name":"Acme"}`),
		"/v1/organizations/workspaces": func(query url.Values, _ int) saastest.Response {
			if query.Get("include_archived") != "true" || query.Get("limit") != "100" {
				return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
			}
			if query.Get("after_id") == "" {
				return saastest.Response{Body: `{"data":[{"id":"wrkspc_01","type":"workspace","name":"Production","created_at":"2026-01-10T00:00:00Z","archived_at":null,"display_color":"#6C5BB9"}],"has_more":true,"first_id":"wrkspc_01","last_id":"wrkspc_01"}`}
			}
			return saastest.Response{Body: `{"data":[{"id":"wrkspc_02","type":"workspace","name":"Old experiments","created_at":"2025-03-01T00:00:00Z","archived_at":"2026-02-01T00:00:00Z"}],"has_more":false,"first_id":"wrkspc_02","last_id":"wrkspc_02"}`}
		},
		"/v1/organizations/api_keys": saastest.Static(`{"data":[
 {"id":"apikey_01","type":"api_key","name":"support-bot","workspace_id":"wrkspc_01","created_at":"2026-01-11T00:00:00Z","created_by":{"id":"user_01","type":"user"},"partial_key_hint":"` + anthropicKeyHint + `","status":"active"},
 {"id":"apikey_02","type":"api_key","name":"retired","workspace_id":null,"created_at":"2025-06-01T00:00:00Z","created_by":{"id":"user_01","type":"user"},"partial_key_hint":"` + anthropicKeyHint + `","status":"inactive"}
],"has_more":false,"first_id":"apikey_01","last_id":"apikey_02"}`),
	}
}

func TestAnthropicOrganizationIsCollectedToATypedSnapshotWithoutKeyValues(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "anthropic")
	standIn := saastest.NewNango(t, registry, anthropicRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, anthropicOrganization)

	if applications := snapshot.Kind("saas_ai_application"); len(applications) != 4 || len(snapshot.Entities) != 5 {
		t.Fatalf("applications=%d: %s", len(applications), snapshot.Raw)
	}
	workspace := snapshot.Named(t, "saas_ai_application", "Production")
	if workspace.SourceNativeID != "saas:anthropic:workspace:wrkspc_01" || workspace.Attributes["status"] != "active" ||
		!reflect.DeepEqual(workspace.Attributes["discovery"].(map[string]any)["signals"], []any{"model:anthropic", "surface:api_workspace"}) {
		t.Fatalf("workspace = %+v", workspace)
	}
	if archived := snapshot.Named(t, "saas_ai_application", "Old experiments"); archived.Attributes["status"] != "archived" {
		t.Fatalf("archived workspace = %+v", archived.Attributes)
	}
	key := snapshot.Named(t, "saas_ai_application", "support-bot")
	if key.SourceNativeID != "saas:anthropic:api_key:apikey_01" || key.Attributes["status"] != "active" || key.Attributes["posture"].(map[string]any)["credential_active"] != true ||
		!reflect.DeepEqual(key.Attributes["discovery"].(map[string]any)["signals"], []any{"model:anthropic", "surface:api_key"}) {
		t.Fatalf("key = %+v", key)
	}
	if retired := snapshot.Named(t, "saas_ai_application", "retired"); retired.Attributes["status"] != "inactive" || retired.Attributes["posture"].(map[string]any)["credential_active"] != false {
		t.Fatalf("retired key = %+v", retired.Attributes)
	}
	// Nothing of a key's value is stored, not even the hint the list
	// carries, and not who created it.
	for _, forbidden := range []string{anthropicKeyHint, "igAA", "partial_key_hint", "user_01"} {
		if bytes.Contains(snapshot.Raw, []byte(forbidden)) {
			t.Fatalf("the snapshot holds %q", forbidden)
		}
	}
	// has_more ends each list: no request follows the last page.
	if calls := standIn.Calls(); len(calls) != 4 || calls[2].Query.Get("after_id") != "wrkspc_01" {
		t.Fatalf("calls = %+v", calls)
	}
	// The key of another organization is refused.
	_, err := saastest.Run(t, saastest.NewNango(t, registry, anthropicRoutes()), registry, platform, "00000000-0000-4000-8000-000000000000")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("another organization: %v", err)
	}
}
