package platforms

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// A group of a self-managed GitLab is collected from the host the tenant id
// names, with the group id in every path and query, to a typed snapshot.
func TestGitLabSelfManagedGroupIsCollectedFromTheCustomersHost(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab_self_managed")
	routes := gitLabRoutes(`,"duo_features_enabled":true`)
	routes["/api/graphql"] = gitLabCatalogRoute(t)
	standIn := saastest.NewNango(t, registry, routes)
	const tenant = "gitlab.acme-corp.com_4242"
	snapshot := saastest.Collect(t, standIn, registry, platform, tenant)
	if len(snapshot.Kind("saas_agent")) != 4 || len(snapshot.Kind("saas_ai_application")) != 4 || len(snapshot.Kind("saas_mcp_server")) != 3 {
		t.Fatalf("snapshot: %s", snapshot.Raw)
	}
	// The tenant is the host and the group; the name is the group's.
	if entity := snapshot.Kind("saas_tenant")[0]; entity.StableFields["tenant"] != tenant || entity.StableFields["platform"] != "gitlab_self_managed" || entity.DisplayName != "acme/platform" || entity.SourceNativeID != "saas:gitlab_self_managed:tenant:"+tenant {
		t.Fatalf("tenant = %+v", entity)
	}
	if agent := snapshot.Named(t, "saas_agent", "Merge request reviewer"); agent.StableFields["tenant"] != tenant {
		t.Fatalf("agent = %+v", agent.StableFields)
	}
	// Every request went to the customer's host through the token
	// integration, and named the group, not the tenant id.
	calls := standIn.Calls()
	if len(calls) < 6 {
		t.Fatalf("calls = %d", len(calls))
	}
	for _, call := range calls {
		if call.Host != "gitlab.acme-corp.com" || call.Key != "gitlab-pat" || call.Path != "/api/graphql" && call.Path != "/api/v4/groups/4242" && call.Path != "/api/v4/groups/4242/projects" ||
			call.Method == http.MethodPost && call.Query.Get("group") != "gid://gitlab/Group/4242" {
			t.Fatalf("call = %+v", call)
		}
	}
	// The connection reaches another group than the one the tenant id names.
	other := gitLabRoutes(``)
	other["/api/v4/groups/4243"] = other["/api/v4/groups/4242"]
	_, err := saastest.Run(t, saastest.NewNango(t, registry, other), registry, platform, "gitlab.acme-corp.com_4243")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureDenied {
		t.Fatalf("another group: %v", err)
	}
}

// The host is the customer's, so what a host may be is checked before
// anything is sent: a tenant id whose host is not a public DNS name is not a
// tenant of the platform, and no request is made for it.
func TestGitLabSelfManagedRefusesHostsThatAreNotPublicNames(t *testing.T) {
	t.Parallel()
	registry, platform := registered(t, "gitlab_self_managed")
	for _, tenant := range []string{
		"gitlab.acme-corp.com_4242", "git.eu.acme.io_1", "acme.gitlab-dedicated.com_77",
	} {
		host, allowed := platform.TenantHost(tenant)
		if !platform.ValidTenant(tenant) || !allowed || host+"_"+platform.TenantKey(tenant) != tenant {
			t.Errorf("%s refused (host %q)", tenant, host)
		}
	}
	for name, tenant := range map[string]string{
		"an address":                "10.0.0.5_4242",
		"the metadata address":      "169.254.169.254_1",
		"a decimal address":         "2130706433_1",
		"a hex address":             "0x7f.0.0.1_1",
		"a single label":            "gitlab_4242",
		"localhost":                 "localhost_1",
		"a local name":              "gitlab.local_1",
		"an internal name":          "gitlab.corp.internal_1",
		"a cloud metadata name":     "metadata.google.internal_1",
		"a cluster service":         "gitlab.gitlab.svc_1",
		"a cluster name":            "gitlab.gitlab.svc.cluster.local_1",
		"the product's Nango":       "nango.zasp.svc.cluster.local_1",
		"a numeric top level":       "gitlab.acme.123_1",
		"a home network name":       "gitlab.lan_1",
		"a port":                    "gitlab.acme-corp.com:8443_1",
		"a path":                    "gitlab.acme-corp.com/x_1",
		"user information":          "user@gitlab.acme-corp.com_1",
		"upper case":                "GitLab.acme-corp.com_1",
		"a trailing dot":            "gitlab.acme-corp.com._1",
		"no group":                  "gitlab.acme-corp.com",
		"group zero":                "gitlab.acme-corp.com_0",
		"a group that is not an id": "gitlab.acme-corp.com_platform",
		"two separators":            "gitlab.acme-corp.com_1_2",
		"an empty host":             "_4242",
		"a gitlab.com group id":     "4242",
	} {
		if platform.ValidTenant(tenant) {
			t.Errorf("%s: %q is accepted as a tenant", name, tenant)
		}
		standIn := saastest.NewNango(t, registry, gitLabRoutes(``))
		// The tenant lookup, which authorizes an integration and starts every
		// collection, sends nothing for it.
		if _, err := saasdiscovery.LookupTenant(context.Background(), standIn.Proxy(), platform, saastest.ConnectionReference, tenant, time.Now().UTC()); !errors.Is(err, saasdiscovery.ErrInvalid) || len(standIn.Calls()) != 0 {
			t.Errorf("%s: lookup = %v, Nango asked %d times", name, err, len(standIn.Calls()))
		}
	}
	// The gitlab.com platform takes no host, and a customer-hosted platform
	// has no sign-in from the product.
	_, gitlab := registered(t, "gitlab")
	if gitlab.ValidTenant("gitlab.acme-corp.com_4242") || platform.SignIn != nil || gitlab.SignIn == nil {
		t.Fatal("the two GitLab platforms are not kept apart")
	}
}

// A definition is customer-hosted only when it says so in both places, and
// then has neither a host template nor a sign-in.
func TestCustomerHostedDefinitionsAreValidated(t *testing.T) {
	t.Parallel()
	if err := GitLabSelfManaged().Validate(); err != nil {
		t.Fatalf("the definition is refused: %v", err)
	}
	for name, mutate := range map[string]func(*saasdiscovery.Platform){
		"no tenant split":           func(platform *saasdiscovery.Platform) { platform.TenantSplit = nil },
		"not declared on the entry": func(platform *saasdiscovery.Platform) { platform.Nango.CustomerHosted = false },
		"a host template too":       func(platform *saasdiscovery.Platform) { platform.HostTemplate = "{tenant}" },
		"provider suffixes too": func(platform *saasdiscovery.Platform) {
			platform.Nango.HostSuffixes = []string{".gitlab-dedicated.com"}
		},
		"a fixed host too": func(platform *saasdiscovery.Platform) { platform.Nango.ProviderHost = "gitlab.com" },
		"a sign-in on a customer host": func(platform *saasdiscovery.Platform) {
			platform.Nango.AuthMode, platform.SignIn = "oauth", GitLab().SignIn
		},
		"a tenant split on gitlab.com": func(platform *saasdiscovery.Platform) {
			split := platform.TenantSplit
			*platform = GitLab()
			platform.TenantSplit = split
		},
		"customer-hosted on gitlab.com": func(platform *saasdiscovery.Platform) { *platform = GitLab(); platform.Nango.CustomerHosted = true },
	} {
		platform := GitLabSelfManaged()
		mutate(&platform)
		if err := platform.Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Errorf("%s: definition accepted", name)
		}
	}
}
