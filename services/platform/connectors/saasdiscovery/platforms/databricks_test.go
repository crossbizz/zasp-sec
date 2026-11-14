package platforms

import (
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// The response shapes are the ones databricks.go documents as unverified.
const (
	databricksHost      = "adb-1234567890123456.7.azuredatabricks.net"
	databricksTenant    = `{"metastore_id":"11111111-2222-3333-4444-555555555555","workspace_id":1234567890123456,"default_catalog_name":"main"}`
	databricksEndpoints = `{"endpoints":[
 {"name":"support-agent","id":"0a1b2c3d4e5f","creator":"owner@example.com","state":{"ready":"READY","config_update":"NOT_UPDATING"},"task":"agent/v1/responses",
  "config":{"served_entities":[{"name":"support-agent-1","entity_name":"main.agents.support_agent","entity_version":"3"}]}},
 {"name":"gpt-4o-proxy","id":"1b2c3d4e5f60","state":{"ready":"READY"},"task":"llm/v1/chat",
  "config":{"served_entities":[{"name":"gpt-4o","external_model":{"provider":"openai","name":"gpt-4o","task":"llm/v1/chat","openai_config":{"openai_api_key":"{{secrets/llm/openai}}"}}}]}},
 {"name":"databricks-meta-llama-3-3-70b-instruct","state":{"ready":"NOT_READY"},"task":"llm/v1/chat",
  "config":{"served_entities":[{"name":"llama","foundation_model":{"name":"databricks-meta-llama-3-3-70b-instruct"}}]}},
 {"name":"churn-model","id":"2c3d4e5f6071","state":{"ready":"READY"},
  "config":{"served_models":[{"name":"churn-1","model_name":"main.ml.churn","model_version":"7"}]}}
]}`
)

func TestDatabricksWorkspaceIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, _ := registry.Platform("databricks")
	standIn := saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(databricksTenant),
		"/api/2.0/serving-endpoints":                          saastest.Static(databricksEndpoints),
	})
	snapshot := saastest.Collect(t, standIn, registry, platform, databricksHost)

	if agents, applications := snapshot.Kind("saas_agent"), snapshot.Kind("saas_ai_application"); len(agents) != 1 || len(applications) != 3 || len(snapshot.Kind("saas_tenant")) != 1 {
		t.Fatalf("agents=%d applications=%d: %s", len(agents), len(applications), snapshot.Raw)
	}
	// The API says the endpoint serves an agent: it is a provider-listed agent.
	agent := snapshot.Named(t, "saas_agent", "support-agent")
	if agent.SourceNativeID != "saas:databricks:serving_endpoint:0a1b2c3d4e5f" || agent.Attributes["agent_type"] != "agent/v1/responses" || agent.Attributes["model"] != "main.agents.support_agent" || agent.Attributes["status"] != "READY" ||
		agent.Attributes["posture"].(map[string]any)["credential_active"] != true || !reflect.DeepEqual(agent.Attributes["discovery"], map[string]any{"method": "provider_api", "platform": "databricks", "signals": []any{}}) {
		t.Fatalf("agent = %+v", agent)
	}
	external := snapshot.Named(t, "saas_ai_application", "gpt-4o-proxy")
	if external.Attributes["model"] != "gpt-4o" || !reflect.DeepEqual(external.Attributes["discovery"], map[string]any{"method": "inferred", "platform": "databricks", "signals": []any{"model:openai", "surface:model_serving"}}) {
		t.Fatalf("external model endpoint = %+v", external)
	}
	// An endpoint without an id is identified by its name; one that is not
	// ready has no live credential.
	foundation := snapshot.Named(t, "saas_ai_application", "databricks-meta-llama-3-3-70b-instruct")
	if foundation.SourceNativeID != "saas:databricks:serving_endpoint:databricks-meta-llama-3-3-70b-instruct" || foundation.Attributes["status"] != "NOT_READY" || foundation.Attributes["posture"].(map[string]any)["credential_active"] != false ||
		!reflect.DeepEqual(foundation.Attributes["discovery"].(map[string]any)["signals"], []any{"model:databricks", "surface:model_serving"}) {
		t.Fatalf("foundation model endpoint = %+v", foundation)
	}
	classic := snapshot.Named(t, "saas_ai_application", "churn-model")
	if classic.Attributes["model"] != "main.ml.churn" || classic.Attributes["agent_type"] != nil || !reflect.DeepEqual(classic.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:model_serving"}) {
		t.Fatalf("classic model endpoint = %+v", classic)
	}
	if tenant := snapshot.Kind("saas_tenant")[0]; tenant.DisplayName != "Databricks workspace "+databricksHost {
		t.Fatalf("tenant = %+v", tenant)
	}
	// Two provider requests, both reads inside the platform's rules.
	// Both went to the workspace's own host.
	if calls := standIn.Calls(); len(calls) != 2 || calls[0].Key != "databricks" || len(calls[1].Query) != 0 || calls[0].Host != databricksHost || calls[1].Host != databricksHost {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestDatabricksWorkspaceWithoutEndpointsOrOfAnotherIDIsHandled(t *testing.T) {
	t.Parallel()
	registry, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, _ := registry.Platform("databricks")
	// A workspace with no serving endpoint answers an empty object.
	empty := saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(databricksTenant),
		"/api/2.0/serving-endpoints":                          saastest.Static(`{}`),
	})
	if snapshot := saastest.Collect(t, empty, registry, platform, databricksHost); len(snapshot.Entities) != 1 {
		t.Fatalf("entities = %d", len(snapshot.Entities))
	}
	// The connection reaches another workspace than the integration names.
	other := saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(databricksTenant),
		"/api/2.0/serving-endpoints": func(url.Values, int) saastest.Response {
			t.Error("endpoints of another workspace were read")
			return saastest.Response{Body: `{}`}
		},
	})
	// The host names workspace 9999999999999999; the API answers for
	// 1234567890123456.
	_, err = saastest.Run(t, other, registry, platform, "adb-9999999999999999.7.azuredatabricks.net")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("another workspace: %v", err)
	}
	// An AWS workspace host carries no workspace id: the answer of the
	// workspace's own host is the confirmation.
	aws := saastest.NewNango(t, registry, map[string]saastest.Route{
		"/api/2.1/unity-catalog/current-metastore-assignment": saastest.Static(databricksTenant),
		"/api/2.0/serving-endpoints":                          saastest.Static(`{}`),
	})
	if snapshot := saastest.Collect(t, aws, registry, platform, "dbc-a1b2c3d4-e5f6.cloud.databricks.com"); len(snapshot.Entities) != 1 || aws.Calls()[0].Host != "dbc-a1b2c3d4-e5f6.cloud.databricks.com" {
		t.Fatalf("AWS workspace: %+v", aws.Calls())
	}
	// Only a Databricks address is a workspace.
	for _, host := range []string{"1234567890123456", "databricks.example.com", "adb-1234567890123456.7.azuredatabricks.net.attacker.net", "cloud.databricks.com", "169.254.169.254", "accounts.cloud.databricks.com.internal"} {
		if platform.ValidTenant(host) {
			t.Fatalf("workspace host %q accepted", host)
		}
	}
}

func TestEveryRegisteredPlatformIsAValidDefinition(t *testing.T) {
	t.Parallel()
	registry, err := Registry()
	if err != nil {
		t.Fatalf("a platform definition is invalid: %v", err)
	}
	seen := map[string]bool{}
	for _, platform := range All() {
		if err := platform.Validate(); err != nil {
			t.Fatalf("%s: %v", platform.Token, err)
		}
		if _, ok := registry.Platform(platform.Token); !ok || seen[platform.Token] {
			t.Fatalf("%s is not registered exactly once", platform.Token)
		}
		seen[platform.Token] = true
	}
	// The stand-in builds the production Nango adapter from the entries: it
	// refuses an entry the worker's adapter would refuse.
	saastest.NewNango(t, registry, nil)
}
