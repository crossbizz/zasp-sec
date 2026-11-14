package platforms

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// The response shapes are the ones servicenow.go documents as unverified.
const serviceNowInstance = `{"result":[{"name":"instance_name","value":"acme"}]}`

func registered(t *testing.T, token string) (*saasdiscovery.Registry, saasdiscovery.Platform) {
	t.Helper()
	registry, err := Registry()
	if err != nil {
		t.Fatal(err)
	}
	platform, known := registry.Platform(token)
	if !known {
		t.Fatalf("platform %s is not registered", token)
	}
	return registry, platform
}

func serviceNowRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/api/now/table/sys_properties": func(query url.Values, _ int) saastest.Response {
			if query.Get("sysparm_query") != "name=instance_name" || query.Get("sysparm_limit") != "1" {
				return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
			}
			return saastest.Response{Body: serviceNowInstance}
		},
		"/api/now/table/sn_aia_agent": func(query url.Values, _ int) saastest.Response {
			if query.Get("sysparm_limit") != "100" || query.Get("sysparm_fields") != "sys_id,name,active" {
				return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
			}
			switch query.Get("sysparm_offset") {
			case "0":
				// A full page of one hundred agents, then a short one.
				var body bytes.Buffer
				body.WriteString(`{"result":[{"sys_id":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","name":"Incident triage agent","active":"true","instructions":"You triage incidents."}`)
				for index := 1; index < 100; index++ {
					body.WriteString(`,{"sys_id":"filler` + string(rune('a'+index/26)) + string(rune('a'+index%26)) + `","name":"Filler agent ` + string(rune('a'+index/26)) + string(rune('a'+index%26)) + `","active":"false"}`)
				}
				body.WriteString(`]}`)
				return saastest.Response{Body: body.String()}
			case "100":
				return saastest.Response{Body: `{"result":[{"sys_id":"1b2c3d4e5f60718293a4b5c6d7e8f90a","name":"Change risk agent","active":"false"}]}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/api/now/table/sys_store_app": saastest.Static(`{"result":[
 {"sys_id":"2c3d4e5f60718293a4b5c6d7e8f90a1b","name":"Now Assist for ITSM","scope":"sn_now_assist_itsm","version":"5.0.1","active":"true"},
 {"sys_id":"3d4e5f60718293a4b5c6d7e8f90a1b2c","name":"AI Agent Studio","scope":"sn_aia","version":"2.1.0","active":"false"},
 {"sys_id":"4e5f60718293a4b5c6d7e8f90a1b2c3d","name":"Vendor Risk Management","scope":"sn_vdr_risk","version":"12.0.0","active":"true"}
]}`),
	}
}

func TestServiceNowInstanceIsCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "servicenow")
	standIn := saastest.NewNango(t, registry, serviceNowRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, "acme")

	// Every request went to the instance's own host.
	for _, call := range standIn.Calls() {
		if call.Host != "acme.service-now.com" || call.Key != "servicenow" {
			t.Fatalf("call = %+v", call)
		}
	}
	if agents, applications := snapshot.Kind("saas_agent"), snapshot.Kind("saas_ai_application"); len(agents) != 101 || len(applications) != 2 {
		t.Fatalf("agents=%d applications=%d", len(agents), len(applications))
	}
	agent := snapshot.Named(t, "saas_agent", "Incident triage agent")
	if agent.SourceNativeID != "saas:servicenow:ai_agent:0a1b2c3d4e5f60718293a4b5c6d7e8f9" || agent.Attributes["status"] != "active" || agent.Attributes["posture"].(map[string]any)["credential_active"] != true {
		t.Fatalf("agent = %+v", agent)
	}
	if paused := snapshot.Named(t, "saas_agent", "Change risk agent"); paused.Attributes["status"] != "inactive" || paused.Attributes["posture"].(map[string]any)["credential_active"] != false {
		t.Fatalf("inactive agent = %+v", paused)
	}
	// A name in the application catalog and a platform AI scope.
	assist := snapshot.Named(t, "saas_ai_application", "Now Assist for ITSM")
	if !reflect.DeepEqual(assist.Attributes["discovery"].(map[string]any)["signals"], []any{"app:now_assist", "surface:now_assist"}) || assist.Attributes["agent_type"] != "customer_agent" {
		t.Fatalf("Now Assist = %+v", assist.Attributes)
	}
	// An AI scope alone is enough; an application that is not AI is not
	// listed even though the instance returned it.
	studio := snapshot.Named(t, "saas_ai_application", "AI Agent Studio")
	if !reflect.DeepEqual(studio.Attributes["discovery"].(map[string]any)["signals"], []any{"surface:now_assist"}) || studio.Attributes["status"] != "inactive" {
		t.Fatalf("AI Agent Studio = %+v", studio.Attributes)
	}
	// The agent's instructions are a prompt: they are never stored.
	if bytes.Contains(snapshot.Raw, []byte("You triage incidents")) || bytes.Contains(snapshot.Raw, []byte("Vendor Risk")) {
		t.Fatal("the snapshot holds a prompt or an application that is not AI")
	}
}

func TestServiceNowInstanceWithoutAIProductsOrOfAnotherNameIsHandled(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "servicenow")
	// An instance without the AI agent application answers "Invalid table".
	routes := serviceNowRoutes()
	routes["/api/now/table/sn_aia_agent"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusBadRequest, Body: `{"error":{"message":"Invalid table sn_aia_agent"}}`}
	}
	routes["/api/now/table/sys_store_app"] = saastest.Static(`{"result":[]}`)
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "acme"); len(snapshot.Entities) != 1 || snapshot.Entities[0].DisplayName != "acme.service-now.com" {
		t.Fatalf("entities = %+v", snapshot.Entities)
	}
	// The connection reaches another instance than the integration names.
	other := saastest.NewNango(t, registry, serviceNowRoutes())
	_, err := saastest.Run(t, other, registry, platform, "globex")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied || len(other.Calls()) != 1 || other.Calls()[0].Host != "globex.service-now.com" {
		t.Fatalf("another instance: %v %+v", err, other.Calls())
	}
	// An instance name that is not a ServiceNow host label is refused.
	for _, tenant := range []string{"acme.service-now.com", "Acme", "acme_dev", "a"} {
		if platform.ValidTenant(tenant) {
			t.Fatalf("instance %q accepted", tenant)
		}
	}
}
