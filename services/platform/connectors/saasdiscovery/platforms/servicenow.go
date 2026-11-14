package platforms

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// ServiceNow lists the AI agents of one instance (Now Assist AI Agents) and
// the installed store applications that are AI products (Now Assist,
// generative AI and AI agent applications). It reads through the Table API.
//
// The API host differs per instance: <instance>.service-now.com. The tenant
// id is the instance name and every request is sent to that host only.
//
// UNVERIFIED: the tables, the query syntax and the response members below
// are written from memory of the ServiceNow Table API and have not been run
// against a real instance. Before the first production use, check against an
// instance:
//   - GET /api/now/table/sys_properties?sysparm_query=name=instance_name
//     answers {"result":[{"name":"instance_name","value":"<instance>"}]} for
//     the connection's user (the property may need the admin role to read);
//   - the AI agent table is sn_aia_agent with the fields sys_id, name and
//     active, and an instance without the AI agent application answers 400
//     ("Invalid table") or 404 for it;
//   - installed store applications are in sys_store_app with sys_id, name,
//     scope, version and active, and the AI applications have a scope that
//     starts with sn_now_assist, sn_gen_ai or sn_aia, or a name that
//     contains "Now Assist" or "Generative AI";
//   - the Table API answers booleans as the strings "true" and "false";
//   - sysparm_offset and sysparm_limit page the result;
//   - the Nango integration key (servicenow), its connection parameter
//     (subdomain) and the instance's authorization page (/oauth_auth.do).
func ServiceNow() saasdiscovery.Platform {
	tableKeys := []string{"sysparm_fields", "sysparm_limit", "sysparm_offset", "sysparm_query"}
	paging := saasdiscovery.Paging{Style: saasdiscovery.PagingOffset, OffsetParam: "sysparm_offset", LimitParam: "sysparm_limit", PageSize: 100}
	// An instance without the application answers 400 or 404 for its table.
	notInstalled := []int{http.StatusBadRequest, http.StatusNotFound}
	return saasdiscovery.Platform{
		Token: "servicenow", DisplayName: "ServiceNow",
		Description: "Inventory the Now Assist AI agents and the AI applications installed on one ServiceNow instance.",
		Nango: nango.Entry{Key: "servicenow", AuthMode: "oauth",
			HostPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}\.service-now\.com$`), HostSuffixes: []string{".service-now.com"},
			Rules: []nango.Rule{
				{Method: http.MethodGet, PathPrefix: "/api/now/table/sys_properties", QueryKeys: []string{"sysparm_fields", "sysparm_limit", "sysparm_query"}},
				{Method: http.MethodGet, PathPrefix: "/api/now/table/sn_aia_agent", QueryKeys: tableKeys},
				{Method: http.MethodGet, PathPrefix: "/api/now/table/sys_store_app", QueryKeys: tableKeys},
			}},
		HostTemplate:   "{tenant}.service-now.com",
		RequiredScopes: []string{"useraccount"},
		TenantLabel:    "Instance name", TenantHint: "The first part of the instance address: acme for acme.service-now.com.",
		TenantPattern:  regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}$`),
		AccessGuidance: "Sign in as a user with read access to the sys_properties, sn_aia_agent and sys_store_app tables. No write role is needed.",
		SignIn:         &saasdiscovery.SignIn{AuthorizationPath: "/oauth_auth.do", ConnectionParams: map[string]string{"subdomain": saasdiscovery.TenantValue}},
		Tenant: saasdiscovery.TenantLookup{Path: "/api/now/table/sys_properties",
			Query: map[string]string{"sysparm_query": "name=instance_name", "sysparm_fields": "name,value", "sysparm_limit": "1"},
			Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
				for _, property := range document.Objects("result") {
					if property.Text("name") == "instance_name" && property.Text("value") != "" {
						instance := property.Text("value")
						return saasdiscovery.Tenant{ID: instance, Name: instance + ".service-now.com"}, true
					}
				}
				return saasdiscovery.Tenant{}, false
			}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "ai_agents", Path: "/api/now/table/sn_aia_agent", Query: map[string]string{"sysparm_fields": "sys_id,name,active"},
				ItemsPath: []string{"result"}, Paging: paging, Absent: notInstalled, Map: serviceNowAIAgent},
			{Name: "ai_applications", Path: "/api/now/table/sys_store_app",
				Query:     map[string]string{"sysparm_fields": "sys_id,name,scope,version,active", "sysparm_query": "scopeSTARTSWITHsn_now_assist^ORscopeSTARTSWITHsn_gen_ai^ORscopeSTARTSWITHsn_aia^ORnameLIKENow Assist^ORnameLIKEGenerative AI"},
				ItemsPath: []string{"result"}, Paging: paging, Absent: notInstalled, Map: serviceNowAIApplication},
		},
	}
}

// serviceNowTrue reads a Table API boolean, which is the string "true" (or
// a JSON boolean where the instance answers with typed values).
func serviceNowTrue(item saasdiscovery.Item, field string) bool {
	return item.Bool(field) || strings.EqualFold(item.Text(field), "true")
}

func serviceNowAIAgent(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	id := item.Text("sys_id")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if id == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	active := serviceNowTrue(item, "active")
	status := "inactive"
	if active {
		status = "active"
	}
	return saasdiscovery.Entity{
		Kind: saasdiscovery.KindAgent, NativeID: id, DisplayName: name, ObjectType: "ai_agent", Status: status, AgentType: "now_assist_ai_agent",
		// The one posture fact the table states: the agent is switched on.
		Posture: agentsignals.Posture{CredentialActive: active},
	}, true
}

var serviceNowAIScopes = []string{"sn_now_assist", "sn_gen_ai", "sn_aia"}

func serviceNowAIApplication(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	id := item.Text("sys_id")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if id == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	// The query asks for AI applications; the answer is checked again so a
	// query the instance ignored does not list every installed application.
	var evidence agentsignals.Evidence
	category := evidence.Application(name)
	scope := strings.ToLower(item.Text("scope"))
	lowerName := strings.ToLower(name)
	platformAI := strings.Contains(lowerName, "now assist") || strings.Contains(lowerName, "generative ai")
	for _, prefix := range serviceNowAIScopes {
		platformAI = platformAI || strings.HasPrefix(scope, prefix)
	}
	if platformAI {
		evidence.Surface("now_assist")
		if category == "" {
			category = "customer_agent"
		}
	}
	signals := evidence.Signals()
	if len(signals) == 0 {
		return saasdiscovery.Entity{}, false
	}
	status := "inactive"
	if serviceNowTrue(item, "active") {
		status = "active"
	}
	return saasdiscovery.Entity{Kind: saasdiscovery.KindAIApplication, NativeID: id, DisplayName: name, ObjectType: "store_app", Status: status, AgentType: category, Signals: signals}, true
}
