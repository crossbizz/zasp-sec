package platforms

import (
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
)

// GitLabSelfManaged reads one group of a GitLab a customer runs: a
// self-managed instance on the customer's own domain, or a GitLab Dedicated
// instance (<name>.gitlab-dedicated.com). What it reads is what GitLab reads
// of a gitlab.com group; only the host differs.
//
// The host is the customer's, not a domain of the provider, so the platform
// declares itself customer-hosted (Nango.CustomerHosted). The tenant id
// names the host and the group: "<host>_<group id>", for example
// gitlab.example.com_4242 (an underscore cannot be part of a host name).
// Every request of the tenant goes to that host and to no other. The host
// must be a public DNS name; it is refused when it is an address, a
// single-label, cluster, local or internal name, or when any address it
// resolves to is not public. It is part of the integration's subject: it is
// fixed when the integration is created and is what the connection was
// authorized against, so an integration cannot be pointed at another host
// without creating and authorizing another one.
//
// There is no sign-in from the product: an OAuth application belongs to one
// instance, and the product would have to send a browser to a host the
// customer chose. The connection is a token of the instance held by Nango: a
// group access token with the Reporter role and the scope read_api.
//
// What an instance older than the Duo Agent Platform does not know (the AI
// catalog queries) it answers with GraphQL errors; the catalog lists are
// then empty and the group's Duo setting and projects are still read.
//
// UNVERIFIED: the Nango integration key (gitlab-pat) and that Nango sends
// its token to the host named in the Base-Url-Override header for that
// integration. Not run against an instance. The shapes are those of GitLab.
func GitLabSelfManaged() saasdiscovery.Platform {
	platform := GitLab()
	platform.Token, platform.DisplayName = "gitlab_self_managed", "GitLab self-managed"
	platform.Description = "Inventory GitLab Duo, its agents and flows, and the AI projects of one group of a self-managed or Dedicated GitLab through a Nango connection."
	platform.Nango = nango.Entry{Key: "gitlab-pat", AuthMode: "api_key", CustomerHosted: true, HostPattern: regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,198}[a-z0-9])?$`), Rules: platform.Nango.Rules}
	platform.SignIn = nil
	platform.TenantLabel, platform.TenantHint = "Host and group ID", "The instance's host, an underscore and the numeric ID of the group: gitlab.example.com_4242."
	platform.TenantPattern = gitLabSelfManagedTenantPattern
	platform.AccessGuidance = "Create the Nango connection with a group access token of the instance that has the Reporter role and the read_api scope. The instance must be reachable from the internet under the host you enter; the product sends the group's requests to that host only."
	platform.TenantSplit = func(tenantID string) (string, string, bool) {
		host, group, found := strings.Cut(tenantID, "_")
		return host, group, found && gitLabSelfManagedTenantPattern.MatchString(tenantID)
	}
	return platform
}

// A host of lower-case DNS labels, an underscore, a group id.
var gitLabSelfManagedTenantPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,6}_[1-9][0-9]{0,17}$`)
