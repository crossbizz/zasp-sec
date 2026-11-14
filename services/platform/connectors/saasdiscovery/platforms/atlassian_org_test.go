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
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

const atlassianOrgID = "a1b2c3d4-0000-4111-8222-333344445555"

// The response shapes are the ones atlassian_org.go states, all UNVERIFIED.
// The action ids are invented for the test: the definition reads them from
// the catalog and knows the actions by their display names only.
func atlassianOrgRoutes(t *testing.T) map[string]saastest.Route {
	base := "/admin/v1/orgs/" + atlassianOrgID
	event := func(id, action, at, actor, agentID, name string) string {
		attributes := ""
		if name != "" {
			attributes = fmt.Sprintf(`,"attributes":{"name":%q,"instructions":"do-not-keep-instructions"}`, name)
		}
		return fmt.Sprintf(`{"id":%q,"type":"events","attributes":{"time":%q,"action":%q,"actor":{"id":%q,"name":"Do Not Keep Name","email":"do-not-keep@example.com"},`+
			`"context":[{"id":"site-1","type":"site","attributes":{"name":"acme"}},{"id":%q,"type":"rovo-agent"%s}],"location":{"ip":"203.0.113.9"}}}`, id, at, action, actor, agentID, attributes)
	}
	page := func(next string, events ...string) saastest.Response {
		meta := `{}`
		if next != "" {
			meta = `{"next":"` + next + `"}`
		}
		return saastest.Response{Body: `{"data":[` + strings.Join(events, ",") + `],"meta":` + meta + `}`}
	}
	return map[string]saastest.Route{
		base: saastest.Static(`{"data":{"id":"` + atlassianOrgID + `","type":"orgs","attributes":{"name":"Acme"}}}`),
		base + "/event-actions": saastest.Static(`{"data":[` +
			`{"id":"user_login","type":"event-actions","attributes":{"displayName":"Logged in","groupDisplayName":"Users"}},` +
			`{"id":"x_agent_created","type":"event-actions","attributes":{"displayName":"Created Rovo agent","groupDisplayName":"Atlassian Rovo"}},` +
			`{"id":"x_agent_updated","type":"event-actions","attributes":{"displayName":"Updated Rovo agent","groupDisplayName":"Atlassian Rovo"}},` +
			`{"id":"x_agent_deleted","type":"event-actions","attributes":{"displayName":"Deleted Rovo agent","groupDisplayName":"Atlassian Rovo"}},` +
			`{"id":"x_chat","type":"event-actions","attributes":{"displayName":"Started chat with Rovo agent","groupDisplayName":"Atlassian Rovo"}}]}`),
		base + "/events": func(query url.Values, _ int) saastest.Response {
			switch query.Get("action") + "|" + query.Get("cursor") {
			case "x_agent_deleted|":
				return page("", event("e9", "x_agent_deleted", "2026-11-01T10:00:00.000Z", "712020:deleter", "agent-old", "Retired helper"))
			case "x_agent_created|":
				return page("c2",
					event("e8", "x_agent_created", "2026-10-20T08:30:00+02:00", "712020:aaaa-bbbb", "agent-new", "Release notes writer"),
					// Created, then deleted: the deletion was read first.
					event("e3", "x_agent_created", "2026-09-01T00:00:00Z", "712020:aaaa-bbbb", "agent-old", "Retired helper"))
			case "x_agent_created|c2":
				// An event that names no agent says nothing.
				return page("", `{"id":"e2","type":"events","attributes":{"time":"2026-08-01T00:00:00Z","action":"x_agent_created","actor":{"id":"712020:cccc"},"context":[]}}`)
			case "x_agent_updated|":
				return page("",
					event("e7", "x_agent_updated", "2026-11-10T12:00:00Z", "712020:editor", "agent-new", "Release notes writer v2"),
					// Created before the log begins; changed twice since, and
					// the event states no name.
					event("e6", "x_agent_updated", "2026-11-05T12:00:00Z", "712020:editor", "agent-ancient", ""),
					event("e5", "x_agent_updated", "not a time", "712020:editor", "agent-ancient", ""))
			}
			t.Errorf("events query = %v", query)
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
	}
}

func TestAtlassianStudioAgentsAreReconstructedFromTheOrganizationAuditLog(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian_org")
	standIn := saastest.NewNango(t, registry, atlassianOrgRoutes(t))
	snapshot := saastest.Collect(t, standIn, registry, platform, atlassianOrgID)

	agents := snapshot.Kind("saas_agent")
	if len(agents) != 3 || len(snapshot.Entities) != 4 {
		t.Fatalf("agents=%d: %s", len(agents), snapshot.Raw)
	}
	// A deletion wins over the creation of the same agent.
	retired := snapshot.Named(t, "saas_agent", "Retired helper")
	if retired.SourceNativeID != "saas:atlassian_org:rovo_studio_agent:agent-old" || retired.Attributes["status"] != "deleted" || retired.Attributes["deleted_at"] != "2026-11-01T10:00:00Z" ||
		retired.Attributes["created_by"] != nil || retired.Attributes["posture"].(map[string]any)["credential_active"] != false || retired.ProductKind != "agent" {
		t.Fatalf("deleted agent = %+v", retired)
	}
	// A creation wins over a later update: the agent keeps its creator, the
	// time in UTC, and the name it was created with.
	writer := snapshot.Named(t, "saas_agent", "Release notes writer")
	if writer.Attributes["status"] != "active" || writer.Attributes["created_by"] != "712020:aaaa-bbbb" || writer.Attributes["created_at"] != "2026-10-20T06:30:00Z" || writer.Attributes["updated_at"] != nil ||
		writer.Attributes["agent_type"] != "enterprise_agent" || writer.StableFields["tenant"] != atlassianOrgID || writer.Attributes["posture"].(map[string]any)["credential_active"] != true ||
		!reflect.DeepEqual(writer.Attributes["discovery"], map[string]any{"method": "provider_api", "platform": "atlassian_org", "signals": []any{"surface:rovo"}}) {
		t.Fatalf("created agent = %+v", writer)
	}
	// An agent older than the log is known by its latest change only.
	ancient := snapshot.Named(t, "saas_agent", "Rovo agent agent-ancient")
	if ancient.Attributes["updated_at"] != "2026-11-05T12:00:00Z" || ancient.Attributes["created_by"] != nil || ancient.Attributes["created_at"] != nil {
		t.Fatalf("updated agent = %+v", ancient.Attributes)
	}
	if tenant := snapshot.Kind("saas_tenant"); len(tenant) != 1 || tenant[0].DisplayName != "Acme" {
		t.Fatalf("tenant = %+v", tenant)
	}
	// A person's name, address and IP address, and an agent's instructions,
	// are not kept; the chat action is not read.
	for _, content := range []string{"do-not-keep", "Do Not Keep", "203.0.113.9", "712020:editor", "712020:deleter"} {
		if bytes.Contains(snapshot.Raw, []byte(content)) {
			t.Fatalf("the snapshot holds %q", content)
		}
	}
	// The tenant, then for each action the catalog and the action's events:
	// deleted, created (two pages), updated.
	var got []string
	for _, call := range standIn.Calls() {
		if call.Key != "atlassian-admin" || call.Method != http.MethodGet {
			t.Fatalf("call = %+v", call)
		}
		got = append(got, strings.TrimPrefix(call.Path, "/admin/v1/orgs/"+atlassianOrgID)+"?"+call.Query.Encode())
	}
	want := []string{"?", "/event-actions?", "/events?action=x_agent_deleted", "/event-actions?", "/events?action=x_agent_created", "/events?action=x_agent_created&cursor=c2",
		"/event-actions?", "/events?action=x_agent_updated"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %q", got)
	}
}

func TestAtlassianOrganizationWithoutTheRovoActionsOrTheAuditLogIsHandled(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian_org")
	base := "/admin/v1/orgs/" + atlassianOrgID
	// The catalog has no Rovo agent action: nothing is listed and no event
	// is asked for.
	routes := atlassianOrgRoutes(t)
	routes[base+"/event-actions"] = saastest.Static(`{"data":[{"id":"user_login","type":"event-actions","attributes":{"displayName":"Logged in"}}]}`)
	routes[base+"/events"] = func(query url.Values, _ int) saastest.Response {
		t.Errorf("events were read: %v", query)
		return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
	}
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID); len(snapshot.Entities) != 1 {
		t.Fatalf("without the actions: %s", snapshot.Raw)
	}
	// Only the deletion is in the catalog: that one action is read.
	routes = atlassianOrgRoutes(t)
	routes[base+"/event-actions"] = saastest.Static(`{"data":[{"id":"x_agent_deleted","type":"event-actions","attributes":{"displayName":"  deleted ROVO agent "}}]}`)
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID); len(snapshot.Kind("saas_agent")) != 1 {
		t.Fatalf("one action: %s", snapshot.Raw)
	}
	// An organization whose plan has no audit log is a failed collection,
	// not an organization without agents.
	routes = atlassianOrgRoutes(t)
	routes[base+"/events"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusPaymentRequired, Body: `{"errors":[{"detail":"Audit Log Entitlement validation failed"}]}`}
	}
	if _, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID); err == nil {
		t.Fatal("an organization without the audit log was collected")
	}
	// A key that is refused is a denied collection.
	routes = atlassianOrgRoutes(t)
	routes[base+"/event-actions"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusForbidden, Body: `{}`}
	}
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("refused key: %v", err)
	}
	// The key of another organization answers another id.
	routes = atlassianOrgRoutes(t)
	routes[base] = saastest.Static(`{"data":{"id":"ffffffff-0000-4111-8222-333344445555","type":"orgs","attributes":{"name":"Other"}}}`)
	if _, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID); err == nil {
		t.Fatal("another organization's key was accepted")
	}
	for _, tenant := range []string{"acme", "A1B2C3D4-0000-4111-8222-333344445555", "a1b2c3d4/0000", "a1b2c3d4.atlassian.net"} {
		if platform.ValidTenant(tenant) {
			t.Fatalf("organization id %q accepted", tenant)
		}
	}
}

// More agents than the cursor can remember end the collection: the next page
// could report one twice.
func TestAtlassianOrganizationWithMoreAgentsThanTheCapFails(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "atlassian_org")
	base := "/admin/v1/orgs/" + atlassianOrgID
	routes := atlassianOrgRoutes(t)
	routes[base+"/events"] = func(query url.Values, _ int) saastest.Response {
		if query.Get("action") != "x_agent_deleted" {
			return saastest.Response{Body: `{"data":[],"meta":{}}`}
		}
		events := make([]string, 0, saasdiscovery.MaximumDistinct+1)
		for index := range saasdiscovery.MaximumDistinct + 1 {
			events = append(events, fmt.Sprintf(`{"id":"e%d","type":"events","attributes":{"time":"2026-11-01T10:00:00Z","action":"x_agent_deleted","actor":{"id":"712020:x"},"context":[{"id":"agent-%d","type":"rovo-agent"}]}}`, index, index))
		}
		return saastest.Response{Body: `{"data":[` + strings.Join(events, ",") + `],"meta":{}}`}
	}
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureTerminal {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestSelectedParentAndAgentRelationDefinitionsAreValidated(t *testing.T) {
	t.Parallel()
	if err := AtlassianOrg().Validate(); err != nil {
		t.Fatalf("the definition is refused: %v", err)
	}
	if err := GitLab().Validate(); err != nil {
		t.Fatalf("the definition is refused: %v", err)
	}
	for name, platform := range map[string]func() saasdiscovery.Platform{
		"a selected parent with an id reader": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Parent.ID = func(saasdiscovery.Item) string { return "x" }
			return platform
		},
		"a selected parent that is one object": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Parent.Single = true
			return platform
		},
		"a selected parent list that is paged": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Parent.Paging = saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "cursor", NextPath: []string{"meta", "next"}}
			return platform
		},
		"a parent inside a query value": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Query["action"] = "rovo_" + saasdiscovery.ParentValue
			return platform
		},
		"a parent the request does not name": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Query = nil
			return platform
		},
		"a parent named twice": func() saasdiscovery.Platform {
			platform := AtlassianOrg()
			platform.Lists[0].Path = "/admin/v1/orgs/{tenant}/events/{parent}"
			return platform
		},
		"a parent in the query of a plain list": func() saasdiscovery.Platform {
			platform := GitLab()
			platform.Lists[0].Query["with_projects"] = saasdiscovery.ParentValue
			return platform
		},
		"an agent relation on a list without children": func() saasdiscovery.Platform {
			platform := GitLab()
			platform.Lists[1].ChildUser = func(saasdiscovery.Item) (string, string, bool) { return "duo_agent", "x", true }
			return platform
		},
	} {
		if err := platform().Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An action id that cannot be one value of a request is a malformed
	// answer, not a request.
	registry, platform := registered(t, "atlassian_org")
	routes := atlassianOrgRoutes(t)
	routes["/admin/v1/orgs/"+atlassianOrgID+"/event-actions"] = saastest.Static(`{"data":[{"id":"a/../b","type":"event-actions","attributes":{"displayName":"Deleted Rovo agent"}}]}`)
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, atlassianOrgID)
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
		t.Fatalf("odd action id: %v", err)
	}
}
