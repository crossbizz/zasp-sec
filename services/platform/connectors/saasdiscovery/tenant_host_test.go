package saasdiscovery_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

// globex is a platform that exists only in this test. Its API host differs
// per tenant, it names the tenant in a request path, and it uses the list
// shapes the first platforms did not need: one object as a list, a nested
// list read under each object of a parent list, an activity log that repeats
// objects, and a cursor whose last page is told by a separate flag.
func globex() saasdiscovery.Platform {
	keep := func(kind, objectType string) func(saasdiscovery.Item) (saasdiscovery.Entity, bool) {
		return func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
			entity := saasdiscovery.Entity{Kind: kind, NativeID: item.Text("id"), DisplayName: saasdiscovery.CleanText(item.Text("name"), 256), ObjectType: objectType, Status: "enabled"}
			if kind == saasdiscovery.KindAIApplication {
				var evidence agentsignals.Evidence
				evidence.Surface("assistant")
				entity.Signals = evidence.Signals()
			}
			return entity, item.Text("id") != ""
		}
	}
	return saasdiscovery.Platform{
		Token: "globex", DisplayName: "Globex", Description: "Inventory the agents of one Globex site.",
		Nango: nango.Entry{Key: "globex", AuthMode: "oauth", HostPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}\.globex\.example$`), HostSuffixes: []string{".globex.example"}, Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/api/sites/"},
			{Method: http.MethodGet, PathPrefix: "/api/teams", QueryKeys: []string{"after", "limit"}},
			{Method: http.MethodGet, PathPrefix: "/api/teams/", QueryKeys: []string{"after", "limit"}},
			{Method: http.MethodGet, PathPrefix: "/api/activity", QueryKeys: []string{"page", "size"}},
		}},
		HostTemplate:   "{tenant}.globex.example",
		RequiredScopes: []string{"read"}, TenantLabel: "Site", TenantHint: "The first part of the site address.", TenantPattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`),
		AccessGuidance: "Authorize a read-only Globex connection.",
		SignIn:         &saasdiscovery.SignIn{AuthorizationPath: "/oauth/authorize", ConnectionParams: map[string]string{"subdomain": saasdiscovery.TenantValue}},
		Tenant: saasdiscovery.TenantLookup{Path: "/api/sites/{tenant}", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("slug"), Name: document.Text("title")}, document.Has("slug")
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "assistant", Path: "/api/sites/{tenant}/assistant", Single: true, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, Absent: []int{http.StatusBadRequest},
				Map: func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					entity, _ := keep(saasdiscovery.KindAIApplication, "assistant")(item)
					return entity, item.Bool("enabled")
				}},
			{Name: "team_bots", Path: "/api/teams/{parent}/bots", ItemsPath: []string{"data"}, Absent: []int{http.StatusBadRequest},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", NextPath: []string{"last_id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: 2},
				Parent: &saasdiscovery.ParentList{Path: "/api/teams", ItemsPath: []string{"data"}, ID: func(item saasdiscovery.Item) string { return item.Text("id") },
					Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", NextPath: []string{"last_id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: 1}},
				MapChild: func(parent string, item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
					entity, ok := keep(saasdiscovery.KindAgent, "bot")(item)
					entity.AgentType = "team:" + parent
					return entity, ok
				}},
			{Name: "activity", Path: "/api/activity", ItemsPath: []string{"events"}, Distinct: true,
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "page", NextPath: []string{"next"}, LimitParam: "size", PageSize: 3},
				Map:    keep(saasdiscovery.KindAIApplication, "app")},
		},
	}
}

func globexRoutes() map[string]saastest.Route {
	return map[string]saastest.Route{
		"/api/sites/initech":           saastest.Static(`{"slug":"initech","title":"Initech"}`),
		"/api/sites/initech/assistant": saastest.Static(`{"id":"assistant","name":"Globex Assistant","enabled":true}`),
		"/api/teams": func(query url.Values, _ int) saastest.Response {
			// One team per page. last_id is stated on every page, also on
			// the last one; has_more tells the last page.
			switch query.Get("after") {
			case "":
				return saastest.Response{Body: `{"data":[{"id":"team_a"}],"last_id":"team_a","has_more":true}`}
			case "team_a":
				return saastest.Response{Body: `{"data":[{"id":"team_b"}],"last_id":"team_b","has_more":true}`}
			case "team_b":
				return saastest.Response{Body: `{"data":[{"id":"team_c"}],"last_id":"team_c","has_more":false}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/api/teams/team_a/bots": func(query url.Values, _ int) saastest.Response {
			if query.Get("after") == "" {
				return saastest.Response{Body: `{"data":[{"id":"bot_1","name":"Triage"},{"id":"bot_2","name":"Deploy"}],"last_id":"bot_2","has_more":true}`}
			}
			return saastest.Response{Body: `{"data":[{"id":"bot_3","name":"Review"}],"last_id":"bot_3","has_more":false}`}
		},
		// team_b has the feature switched off; team_c has one bot.
		"/api/teams/team_b/bots": func(url.Values, int) saastest.Response {
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
		"/api/teams/team_c/bots": saastest.Static(`{"data":[{"id":"bot_4","name":"Release"}],"last_id":"bot_4","has_more":false}`),
		"/api/activity": func(query url.Values, _ int) saastest.Response {
			switch query.Get("page") {
			case "":
				return saastest.Response{Body: `{"events":[{"id":"app_1","name":"Notes AI"},{"id":"app_2","name":"Mail AI"},{"id":"app_1","name":"Notes AI"}],"next":"2"}`}
			case "2":
				return saastest.Response{Body: `{"events":[{"id":"app_2","name":"Mail AI"},{"id":"app_1","name":"Notes AI"},{"id":"app_3","name":"Sheet AI"}],"next":"3"}`}
			case "3":
				return saastest.Response{Body: `{"events":[{"id":"app_3","name":"Sheet AI"}]}`}
			}
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
	}
}

func globexRegistry(t *testing.T) (*saasdiscovery.Registry, saasdiscovery.Platform) {
	t.Helper()
	platform := globex()
	registry, err := saasdiscovery.NewRegistry(platform)
	if err != nil {
		t.Fatalf("fake platform definition refused: %v", err)
	}
	return registry, platform
}

func TestPerTenantHostPlatformIsCollectedFromTheTenantsOwnHost(t *testing.T) {
	t.Parallel()
	registry, platform := globexRegistry(t)
	standIn := saastest.NewNango(t, registry, globexRoutes())
	snapshot := saastest.Collect(t, standIn, registry, platform, "initech")

	// Every request was pinned to the tenant's host and to no other.
	calls := standIn.Calls()
	for _, call := range calls {
		if call.Host != "initech.globex.example" {
			t.Fatalf("request %s was sent to %q", call.Path, call.Host)
		}
	}
	// The tenant is named in the path of the lookup and of a list.
	if calls[0].Path != "/api/sites/initech" || calls[1].Path != "/api/sites/initech/assistant" {
		t.Fatalf("first calls = %+v", calls[:2])
	}
	// One object as a list.
	if assistant := snapshot.Named(t, "saas_ai_application", "Globex Assistant"); assistant.SourceNativeID != "saas:globex:assistant:assistant" {
		t.Fatalf("assistant = %+v", assistant)
	}
	// The nested list: every bot of every team, each with its parent; the
	// team whose bots are absent contributes nothing and does not stop it.
	bots := snapshot.Kind("saas_agent")
	if len(bots) != 4 {
		t.Fatalf("bots = %d: %s", len(bots), snapshot.Raw)
	}
	for name, team := range map[string]string{"Triage": "team_a", "Deploy": "team_a", "Review": "team_a", "Release": "team_c"} {
		if bot := snapshot.Named(t, "saas_agent", name); bot.Attributes["agent_type"] != "team:"+team {
			t.Fatalf("bot %s = %+v", name, bot.Attributes)
		}
	}
	var teamCalls, botCalls []string
	for _, call := range calls {
		switch {
		case call.Path == "/api/teams":
			teamCalls = append(teamCalls, call.Query.Get("after")+"/"+call.Query.Get("limit"))
		case strings.HasPrefix(call.Path, "/api/teams/"):
			botCalls = append(botCalls, call.Path+"?"+call.Query.Get("after"))
		}
	}
	// The parent list is walked one object at a time and ends on has_more
	// false, without a further request for the id the last page names.
	if fmt.Sprint(teamCalls) != "[/1 team_a/1 team_b/1]" || fmt.Sprint(botCalls) != "[/api/teams/team_a/bots? /api/teams/team_a/bots?bot_2 /api/teams/team_b/bots? /api/teams/team_c/bots?]" {
		t.Fatalf("team calls %v bot calls %v", teamCalls, botCalls)
	}
	// The activity log names three apps seven times on three pages; each
	// is reported once.
	apps := 0
	for _, entity := range snapshot.Kind("saas_ai_application") {
		if entity.StableFields["object_type"] == "app" {
			apps++
		}
	}
	if apps != 3 {
		t.Fatalf("distinct apps = %d: %s", apps, snapshot.Raw)
	}
}

func TestTenantWhoseHostThePlatformDoesNotAllowIsNeverRequested(t *testing.T) {
	t.Parallel()
	registry, platform := globexRegistry(t)
	for _, tenant := range []string{"Initech", "initech.attacker.net", "a", "initech.globex.example", "10.0.0.1", "-initech", "initech_1"} {
		if platform.ValidTenant(tenant) {
			t.Fatalf("tenant %q accepted", tenant)
		}
		standIn := saastest.NewNango(t, registry, globexRoutes())
		if _, err := saasdiscovery.LookupTenant(context.Background(), standIn.Proxy(), platform, saastest.ConnectionReference, tenant, time.Now().UTC()); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Fatalf("tenant %q: lookup error = %v", tenant, err)
		}
		if calls := standIn.Calls(); len(calls) != 0 {
			t.Fatalf("tenant %q: a request was sent: %+v", tenant, calls)
		}
	}
	// A tenant host must be a host of the platform: the template cannot
	// leave the entry's suffix, whatever the tenant pattern admits.
	loose := globex()
	loose.TenantPattern = regexp.MustCompile(`^.+$`)
	if host, ok := loose.TenantHost("evil.example.com"); ok || loose.ValidTenant("evil.example.com") {
		t.Fatalf("host %q accepted", host)
	}
	if host, ok := loose.TenantHost("initech"); !ok || host != "initech.globex.example" {
		t.Fatalf("host = %q, %t", host, ok)
	}
}

func TestAConnectionOfAnotherTenantIsRefusedOnAPerTenantHost(t *testing.T) {
	t.Parallel()
	registry, platform := globexRegistry(t)
	routes := globexRoutes()
	// The host answers, and names another site than the one asked for.
	routes["/api/sites/initech"] = saastest.Static(`{"slug":"umbrella","title":"Umbrella"}`)
	standIn := saastest.NewNango(t, registry, routes)
	_, err := saastest.Run(t, standIn, registry, platform, "initech")
	if got := failureCode(t, err); got != collection.FailureDenied {
		t.Fatalf("failure = %s", got)
	}
	if calls := standIn.Calls(); len(calls) != 1 {
		t.Fatalf("lists of another tenant were read: %+v", calls)
	}
}

func TestTenantLookupCanConfirmATenantTheAPIDoesNotStateAsOneValue(t *testing.T) {
	t.Parallel()
	platform := globex()
	platform.Tenant = saasdiscovery.TenantLookup{Path: "/api/sites/{tenant}", Confirm: func(document saasdiscovery.Item, tenantID string) (string, bool) {
		for _, site := range document.Texts("sites") {
			if site == tenantID {
				return "Site " + tenantID, true
			}
		}
		return "", false
	}}
	registry, err := saasdiscovery.NewRegistry(platform)
	if err != nil {
		t.Fatal(err)
	}
	routes := globexRoutes()
	routes["/api/sites/initech"] = saastest.Static(`{"sites":["umbrella","initech"]}`)
	standIn := saastest.NewNango(t, registry, routes)
	tenant, err := saasdiscovery.LookupTenant(context.Background(), standIn.Proxy(), platform, saastest.ConnectionReference, "initech", time.Now().UTC())
	if err != nil || tenant.ID != "initech" || tenant.Name != "Site initech" {
		t.Fatalf("tenant = %+v, %v", tenant, err)
	}
	routes["/api/sites/initech"] = saastest.Static(`{"sites":["umbrella"]}`)
	_, err = saasdiscovery.LookupTenant(context.Background(), saastest.NewNango(t, registry, routes).Proxy(), platform, saastest.ConnectionReference, "initech", time.Now().UTC())
	if got := failureCode(t, err); got != collection.FailureDenied {
		t.Fatalf("unconfirmed tenant: %s", got)
	}
}

func TestDistinctEndpointStopsWhenItCannotRememberEveryObject(t *testing.T) {
	t.Parallel()
	registry, platform := globexRegistry(t)
	routes := globexRoutes()
	// Each page names three new apps; the log never repeats and never ends.
	routes["/api/activity"] = func(query url.Values, call int) saastest.Response {
		return saastest.Response{Body: fmt.Sprintf(`{"events":[{"id":"a%d","name":"A"},{"id":"b%d","name":"B"},{"id":"c%d","name":"C"}],"next":"%d"}`, call, call, call, call+2)}
	}
	standIn := saastest.NewNango(t, registry, routes)
	_, err := saastest.Run(t, standIn, registry, platform, "initech")
	if got := failureCode(t, err); got != collection.FailureTerminal {
		t.Fatalf("failure = %s", got)
	}
	pages := 0
	for _, call := range standIn.Calls() {
		if call.Path == "/api/activity" {
			pages++
		}
	}
	// 96 objects are remembered, three a page: the 33rd page is refused.
	if pages != saasdiscovery.MaximumDistinct/3+1 {
		t.Fatalf("activity pages = %d", pages)
	}
}

func TestRateLimitWithoutARetryTimeWaitsADefaultTime(t *testing.T) {
	t.Parallel()
	registry, platform := globexRegistry(t)
	for name, retryAfter := range map[string]string{"no header": "", "a header that is not a time": "soon", "a zero wait": "0"} {
		routes := globexRoutes()
		routes["/api/teams"] = func(url.Values, int) saastest.Response {
			return saastest.Response{Status: http.StatusTooManyRequests, RetryAfter: retryAfter, Body: `{}`}
		}
		before := time.Now().UTC()
		_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, "initech")
		var failure *collection.Failure
		if !errors.As(err, &failure) || failure.Code() != collection.FailureRateLimited {
			t.Fatalf("%s: %v", name, err)
		}
		if wait := failure.RetryAt().Sub(before); wait < 55*time.Second || wait > 65*time.Second {
			t.Fatalf("%s: retry in %s", name, wait)
		}
	}
	// A stated wait is still honoured.
	routes := globexRoutes()
	routes["/api/teams"] = func(url.Values, int) saastest.Response {
		return saastest.Response{Status: http.StatusTooManyRequests, RetryAfter: "300", Body: `{}`}
	}
	before := time.Now().UTC()
	_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, "initech")
	var failure *collection.Failure
	if !errors.As(err, &failure) || failure.Code() != collection.FailureRateLimited || failure.RetryAt().Sub(before) < 290*time.Second {
		t.Fatalf("stated wait: %v", err)
	}
}

func TestExtendedPlatformDefinitionsAreValidated(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*saasdiscovery.Platform){
		"a per-tenant entry without a template": func(platform *saasdiscovery.Platform) { platform.HostTemplate = "" },
		"a template that does not name the tenant": func(platform *saasdiscovery.Platform) {
			platform.HostTemplate = "api.globex.example"
		},
		"a template that names the tenant twice": func(platform *saasdiscovery.Platform) {
			platform.HostTemplate = "{tenant}.{tenant}.globex.example"
		},
		"a template with a path": func(platform *saasdiscovery.Platform) { platform.HostTemplate = "{tenant}.globex.example/x" },
		"a template on a fixed host": func(platform *saasdiscovery.Platform) {
			platform.Nango.HostPattern, platform.Nango.HostSuffixes, platform.Nango.ProviderHost = nil, nil, "api.globex.example"
		},
		"a per-tenant entry with a fixed host too": func(platform *saasdiscovery.Platform) { platform.Nango.ProviderHost = "api.globex.example" },
		"a per-tenant entry without a suffix":      func(platform *saasdiscovery.Platform) { platform.Nango.HostSuffixes = nil },
		"both tenant forms": func(platform *saasdiscovery.Platform) {
			platform.Tenant.Confirm = func(saasdiscovery.Item, string) (string, bool) { return "", true }
		},
		"a brace outside a placeholder":       func(platform *saasdiscovery.Platform) { platform.Lists[0].Path = "/api/sites/{site}/assistant" },
		"a parent placeholder with no parent": func(platform *saasdiscovery.Platform) { platform.Lists[0].Path = "/api/sites/{parent}/assistant" },
		"a nested list that does not name its parent": func(platform *saasdiscovery.Platform) {
			platform.Lists[1].Path = "/api/teams/bots"
		},
		"a nested list with Map":         func(platform *saasdiscovery.Platform) { platform.Lists[1].Map = platform.Lists[2].Map },
		"a nested list without MapChild": func(platform *saasdiscovery.Platform) { platform.Lists[1].MapChild = nil },
		"a parent list without an id":    func(platform *saasdiscovery.Platform) { platform.Lists[1].Parent.ID = nil },
		"a parent page of more than one": func(platform *saasdiscovery.Platform) { platform.Lists[1].Parent.Paging.PageSize = 50 },
		"an unpaged parent list": func(platform *saasdiscovery.Platform) {
			platform.Lists[1].Parent.Paging = saasdiscovery.Paging{Style: saasdiscovery.PagingNone}
		},
		"a parent list without a rule":  func(platform *saasdiscovery.Platform) { platform.Lists[1].Parent.Path = "/api/secrets" },
		"MapChild without a parent":     func(platform *saasdiscovery.Platform) { platform.Lists[2].MapChild = platform.Lists[1].MapChild },
		"a paged single object":         func(platform *saasdiscovery.Platform) { platform.Lists[0].Paging = platform.Lists[2].Paging },
		"a single object that is a log": func(platform *saasdiscovery.Platform) { platform.Lists[0].Distinct = true },
		"a more flag on offset paging": func(platform *saasdiscovery.Platform) {
			platform.Lists[2].Paging = saasdiscovery.Paging{Style: saasdiscovery.PagingOffset, OffsetParam: "page", LimitParam: "size", PageSize: 3, MorePath: []string{"has_more"}}
		},
		"sign-in on an API key integration": func(platform *saasdiscovery.Platform) { platform.Nango.AuthMode = "api_key" },
		"sign-in without a path":            func(platform *saasdiscovery.Platform) { platform.SignIn.AuthorizationPath = "" },
		"sign-in to an address":             func(platform *saasdiscovery.Platform) { platform.SignIn.AuthorizationHost = "10.0.0.1" },
		"sign-in to a cluster name":         func(platform *saasdiscovery.Platform) { platform.SignIn.AuthorizationHost = "nango.svc.cluster.local" },
		"a connection parameter with a bad name": func(platform *saasdiscovery.Platform) {
			platform.SignIn.ConnectionParams = map[string]string{"sub domain": "x"}
		},
	} {
		platform := globex()
		mutate(&platform)
		if err := platform.Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Errorf("%s: definition accepted", name)
		}
	}
	// A fixed-host platform must say where its authorization page is.
	fixed := acme()
	fixed.SignIn = &saasdiscovery.SignIn{AuthorizationPath: "/oauth/authorize"}
	if err := fixed.Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
		t.Fatal("sign-in without a host on a fixed-host platform accepted")
	}
	fixed.SignIn.AuthorizationHost = "login.acme.example"
	if err := fixed.Validate(); err != nil {
		t.Fatalf("sign-in on a fixed-host platform: %v", err)
	}
}
