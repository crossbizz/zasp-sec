package platforms

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// AtlassianOrg reconstructs the agents people built in Rovo Studio from the
// audit log of one Atlassian organization.
//
// Why the audit log. No API lists Studio-built agents to a credential a
// service can hold: the gateway field agentStudio_getAgents answers a browser
// session only (see Atlassian). What an organization API key can read is the
// organization's audit log, and Atlassian records there that a Rovo agent was
// created, updated or deleted. This definition reads those three kinds of
// event and reports each agent they name once.
//
// What an agent is, here. It is what the newest event about it says:
//   - an agent with a "deleted" event is reported with the status deleted and
//     the time of the deletion;
//   - otherwise an agent with a "created" event is reported active, with the
//     account id of the person who created it and the time;
//   - otherwise (created before the log begins, changed since) it is reported
//     active with the time of its latest change.
//
// The three actions are read in that order and an agent is reported at its
// first event, so a deletion wins over a creation and a creation over an
// update. Of an event only the action, the time, the actor's account id and
// the id and name of the agent are read; an actor's name, email address and
// IP address are not.
//
// Limits, all of which mean "an agent not listed here" is not "no agent":
//   - the log goes back 180 days, 365 with Atlassian Guard (as Atlassian's
//     audit log pages state, per web search). An agent created earlier and
//     not changed since has no event and is not found;
//   - Atlassian lists agent created, updated and deleted among the Rovo
//     activities of the audit log; which plan records them is stated
//     differently by its pages (Guard Standard for "Rovo admin actions",
//     Guard Premium for "Rovo user actions"). An organization whose log does
//     not have the three actions lists nothing;
//   - at most saasdiscovery.MaximumDistinct agents are reported; an
//     organization whose log names more ends the collection as a failure
//     rather than as an incomplete inventory;
//   - the events name an organization, not a site: the agents of every site
//     of the organization are listed under the organization.
//
// How the actions are found. The API filters events by an action id. The
// ids of the Rovo agent actions are not in any page this definition could
// be checked against, so they are not written here: the definition first
// reads the organization's catalog of actions (event-actions) and takes the
// ids of the three whose display name is "Created Rovo agent", "Updated Rovo
// agent" and "Deleted Rovo agent", compared without case.
//
// DOCUMENTED (as returned by web searches; the pages themselves could not be
// opened from where this was written):
//   - https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events :
//     GET /admin/v1/orgs/{orgId}/events lists audit log events and takes the
//     query parameters cursor, action, from and to; GET
//     /admin/v1/orgs/{orgId}/event-actions lists the actions; the credential
//     is an organization API key sent as a Bearer token; the rate limit is
//     10 requests a minute per path;
//   - https://developer.atlassian.com/cloud/admin/organization/event-by-id-deprecation/ :
//     only GET /events/{eventId} is retired (21 December 2026); GET /events
//     stays;
//   - https://support.atlassian.com/security-and-access-policies/docs/audit-log-activities-database/ :
//     the activities "Created Rovo agent", "Updated Rovo agent", "Deleted
//     Rovo agent" and "Started chat with Rovo agent".
//
// UNVERIFIED (from memory of the Organizations REST API; nothing here was
// run against an organization):
//   - GET /admin/v1/orgs/{orgId} answers {"data":{"id":"…","type":"orgs",
//     "attributes":{"name":"…"}}};
//   - GET /admin/v1/orgs/{orgId}/event-actions answers {"data":[{"id":
//     "<action id>","type":"event-actions","attributes":{"displayName":"…",
//     "groupDisplayName":"…"}}]} in one response of less than 1 MiB;
//   - GET /admin/v1/orgs/{orgId}/events answers {"data":[{"id":"…","type":
//     "events","attributes":{"time":"<RFC 3339>","action":"…","actor":
//     {"id":"<account id>"},"context":[{"id":"…","type":"…","attributes":
//     {"name":"…"}}]}}],"meta":{"next":"<cursor>"}} newest first, with at
//     most 1000 events a page, and no meta.next on the last page;
//   - that the agent is the context object whose type contains "agent" (or
//     the only context object), that its id is the agent's id, and that its
//     attributes carry the agent's name. An event without a name is reported
//     as "Rovo agent <id>";
//   - the display names of the three actions in the catalog, and that the
//     catalog lists an action whose events the organization's plan records;
//   - how an organization without the audit log entitlement answers (a
//     community post reports 402, "Audit Log Entitlement validation
//     failed"). Such an answer fails the collection: it is not read as "no
//     agents";
//   - the Nango integration key (atlassian-admin) and that its connection
//     sends the organization API key as a Bearer token to api.atlassian.com.
func AtlassianOrg() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "atlassian_org", DisplayName: "Atlassian organization",
		Description: "Inventory the Rovo agents people built in Rovo Studio, read from the audit log of one Atlassian organization through a Nango connection.",
		Nango: nango.Entry{Key: "atlassian-admin", ProviderHost: "api.atlassian.com", AuthMode: "api_key", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/admin/v1/orgs/", QueryKeys: []string{"action", "cursor"}},
		}},
		RequiredScopes: []string{"organization-admin-api-key"},
		TenantLabel:    "Organization ID", TenantHint: "The organization ID in the address of admin.atlassian.com: admin.atlassian.com/o/<organization id>.",
		TenantPattern:  regexp.MustCompile(`^[0-9a-z][0-9a-z-]{7,63}$`),
		AccessGuidance: "Create the Nango connection with an organization API key (Atlassian Administration, Settings, API keys). The product never receives the key. It reads the audit log events about Rovo agents: the action, the time, the account id of the person and the agent's id and name.",
		Tenant: saasdiscovery.TenantLookup{Path: "/admin/v1/orgs/{tenant}", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			id := document.Text("data", "id")
			return saasdiscovery.Tenant{ID: id, Name: saasdiscovery.CleanText(document.Text("data", "attributes", "name"), 256)}, id != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "studio_agents", Path: "/admin/v1/orgs/{tenant}/events", Query: map[string]string{"action": saasdiscovery.ParentValue}, ItemsPath: []string{"data"}, Distinct: true,
				Paging:   saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "cursor", NextPath: []string{"meta", "next"}},
				Parent:   &saasdiscovery.ParentList{Path: "/admin/v1/orgs/{tenant}/event-actions", ItemsPath: []string{"data"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Select: atlassianRovoAgentActions},
				MapChild: atlassianStudioAgentEvent},
		},
	}
}

// atlassianRovoAgentActionNames are the display names of the three audit log
// activities, by the label of what the event says happened, in the order
// the actions are read: a deletion first.
var atlassianRovoAgentActionNames = []struct{ label, displayName string }{
	{"deleted", "deleted rovo agent"}, {"created", "created rovo agent"}, {"updated", "updated rovo agent"},
}

// atlassianRovoAgentActions picks the three Rovo agent actions out of the
// organization's catalog of audit log actions.
func atlassianRovoAgentActions(actions []saasdiscovery.Item) []saasdiscovery.SelectedParent {
	var selected []saasdiscovery.SelectedParent
	for _, wanted := range atlassianRovoAgentActionNames {
		for _, action := range actions {
			if id := action.Text("id"); id != "" && strings.ToLower(strings.TrimSpace(action.Text("attributes", "displayName"))) == wanted.displayName {
				selected = append(selected, saasdiscovery.SelectedParent{ID: id, Label: wanted.label})
				break
			}
		}
	}
	return selected
}

// atlassianStudioAgentEvent maps one audit log event about a Rovo agent to
// the agent. label is which of the three actions the event was read under.
func atlassianStudioAgentEvent(label string, event saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	attributes := event.Object("attributes")
	contexts := attributes.Objects("context")
	var agent saasdiscovery.Item
	for _, context := range contexts {
		if strings.Contains(strings.ToLower(context.Text("type")), "agent") {
			agent = context
			break
		}
	}
	if agent == nil && len(contexts) == 1 {
		agent = contexts[0]
	}
	id := saasdiscovery.CleanText(agent.Text("id"), 256)
	if id == "" {
		// The event does not say which agent: nothing can be reported.
		return saasdiscovery.Entity{}, false
	}
	name := saasdiscovery.CleanText(agent.Text("attributes", "name"), 256)
	if name == "" {
		name = saasdiscovery.CleanText("Rovo agent "+id, 256)
	}
	// The time of the event, in UTC; a time that does not parse is left out.
	at := ""
	if parsed, err := time.Parse(time.RFC3339, attributes.Text("time")); err == nil {
		at = parsed.UTC().Format(time.RFC3339)
	}
	var evidence agentsignals.Evidence
	evidence.Surface("rovo")
	entity := saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: "rovo_studio_agent", Status: "active", AgentType: "enterprise_agent", Signals: evidence.Signals()}
	switch label {
	case "deleted":
		entity.Status, entity.DeletedAt = "deleted", at
	case "created":
		entity.CreatedAt = at
		// The account id is an opaque id, not a name or an address.
		if actor := attributes.Text("actor", "id"); atlassianAccountIDPattern.MatchString(actor) {
			entity.CreatedBy, entity.CreatedBySource = actor, saasdiscovery.CreatedBySourceAuditLog
		}
		entity.Posture = agentsignals.Posture{CredentialActive: true}
	case "updated":
		entity.UpdatedAt = at
		entity.Posture = agentsignals.Posture{CredentialActive: true}
	default:
		return saasdiscovery.Entity{}, false
	}
	return entity, true
}

var atlassianAccountIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$`)
