package platforms

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// Atlassian lists the AI applications installed on one Atlassian Cloud site
// (<site>.atlassian.net): the installed applications whose name is in the
// reviewed application catalog, and the ones whose key says they are Rovo.
//
// The API host differs per site. The tenant id is the site name and every
// request is sent to that site's host only.
//
// Rovo agents themselves are not listed. This definition knows no REST read
// endpoint that lists the agents of a site, and it does not invent one; what
// it reports about Rovo is the installed Rovo applications.
//
// UNVERIFIED: the paths and the response members below are written from
// memory of the Jira Cloud REST API and of the Universal Plugin Manager and
// have not been run against a real site. Before the first production use,
// check against a site:
//   - GET /rest/api/3/serverInfo answers
//     {"baseUrl":"https://<site>.atlassian.net","serverTitle":"…"};
//   - GET /rest/plugins/1.0/ answers {"plugins":[{"key":"…","name":"…",
//     "enabled":true,"userInstalled":true}]} for a site administrator, in
//     one response of less than 1 MiB;
//   - the plugin list is not reachable with an OAuth 2.0 (3LO) token, which
//     is why the connection is an API token of an administrator (the Nango
//     integration jira-basic, with the site as its subdomain) and why this
//     platform has no sign-in from the product.
func Atlassian() saasdiscovery.Platform {
	return saasdiscovery.Platform{
		Token: "atlassian", DisplayName: "Atlassian",
		Description: "Inventory the AI applications and Rovo applications installed on one Atlassian Cloud site through a Nango connection.",
		Nango: nango.Entry{Key: "jira-basic", AuthMode: "api_key",
			HostPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}\.atlassian\.net$`), HostSuffixes: []string{".atlassian.net"},
			Rules: []nango.Rule{
				{Method: http.MethodGet, PathPrefix: "/rest/api/3/serverInfo"},
				{Method: http.MethodGet, PathPrefix: "/rest/plugins/1.0/"},
			}},
		HostTemplate:   "{tenant}.atlassian.net",
		RequiredScopes: []string{"site-administrator"},
		TenantLabel:    "Site name", TenantHint: "The first part of the site address: acme for acme.atlassian.net.",
		TenantPattern:  regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}$`),
		AccessGuidance: "Create the Nango connection with the email address and an API token of a site administrator. The product never receives the token; it reads the list of installed applications only.",
		Tenant: saasdiscovery.TenantLookup{Path: "/rest/api/3/serverInfo", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			base, err := url.Parse(document.Text("baseUrl"))
			if err != nil || base.Scheme != "https" || base.Port() != "" {
				return saasdiscovery.Tenant{}, false
			}
			site, isCloud := strings.CutSuffix(strings.ToLower(base.Hostname()), ".atlassian.net")
			return saasdiscovery.Tenant{ID: site, Name: site + ".atlassian.net"}, isCloud && site != ""
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "apps", Path: "/rest/plugins/1.0/", ItemsPath: []string{"plugins"}, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Map: atlassianApplication},
		},
	}
}

func atlassianApplication(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
	key := item.Text("key")
	name := saasdiscovery.CleanText(item.Text("name"), 256)
	if key == "" || name == "" {
		return saasdiscovery.Entity{}, false
	}
	var evidence agentsignals.Evidence
	category := evidence.Application(name)
	lowerKey := strings.ToLower(key)
	// Atlassian's own Rovo applications carry rovo in their key.
	if strings.Contains(lowerKey, "rovo") {
		evidence.Surface("rovo")
		if category == "" {
			category = "enterprise_agent"
		}
	}
	if len(evidence.Signals()) == 0 {
		// Not an AI application: it stays out of the inventory.
		return saasdiscovery.Entity{}, false
	}
	if item.Bool("userInstalled") {
		evidence.Surface("marketplace_app")
	}
	enabled := item.Bool("enabled")
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return saasdiscovery.Entity{
		Kind: saasdiscovery.KindAIApplication, NativeID: key, DisplayName: name, ObjectType: "app", Status: status, AgentType: category,
		// The one posture fact the list states: the application is enabled.
		Posture: agentsignals.Posture{CredentialActive: enabled},
		Signals: evidence.Signals(),
	}, true
}
