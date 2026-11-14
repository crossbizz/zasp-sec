package saasdiscovery_test

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery/saastest"
)

const initechQuery = `query($site: String!, $first: Int!, $after: String) { agents(site: $site, first: $first, after: $after) { nodes { id name } pageInfo { hasNextPage endCursor } } }`

// initech is a platform that exists only in this test: its agents are read
// with a GraphQL query that names the site by an id only another request
// states, and its bots with a list that states no continuation token and
// needs a version header.
func initech() saasdiscovery.Platform {
	agent := func(objectType string) func(string, saasdiscovery.Item) (saasdiscovery.Entity, bool) {
		return func(_ string, item saasdiscovery.Item) (saasdiscovery.Entity, bool) {
			return saasdiscovery.Entity{Kind: saasdiscovery.KindAgent, NativeID: item.Text("id"), DisplayName: saasdiscovery.CleanText(item.Text("name"), 256), ObjectType: objectType, Status: "enabled"}, item.Text("id") != ""
		}
	}
	return saasdiscovery.Platform{
		Token: "initech", DisplayName: "Initech", Description: "Inventory the agents of one Initech organization.",
		Nango: nango.Entry{Key: "initech", ProviderHost: "api.initech.example", AuthMode: "api_key", Rules: []nango.Rule{
			{Method: http.MethodGet, PathPrefix: "/v1/organization"},
			{Method: http.MethodGet, PathPrefix: "/v1/site"},
			{Method: http.MethodGet, PathPrefix: "/v1/bots", QueryKeys: []string{"after", "limit"}, HeaderKeys: []string{"Initech-Version", "Initech-Organization"}},
			{Method: http.MethodPost, PathPrefix: "/graphql", GraphQLDocuments: []string{initechQuery}},
		}},
		RequiredScopes: []string{"read"}, TenantLabel: "Organization", TenantHint: "The organization id.", TenantPattern: regexp.MustCompile(`^org[0-9]{3}$`),
		AccessGuidance: "Create a read-only key.",
		Tenant: saasdiscovery.TenantLookup{Path: "/v1/organization", Map: func(document saasdiscovery.Item) (saasdiscovery.Tenant, bool) {
			return saasdiscovery.Tenant{ID: document.Text("id"), Name: document.Text("name")}, document.Has("id")
		}},
		Lists: []saasdiscovery.ListEndpoint{
			{Name: "agents", Path: "/graphql", ItemsPath: []string{"data", "agents", "nodes"},
				GraphQL: &saasdiscovery.GraphQL{Document: initechQuery, Variables: map[string]string{"site": "site:" + saasdiscovery.ParentValue}},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LimitParam: "first", PageSize: 2,
					NextPath: []string{"data", "agents", "pageInfo", "endCursor"}, MorePath: []string{"data", "agents", "pageInfo", "hasNextPage"}},
				Parent:   &saasdiscovery.ParentList{Path: "/v1/site", Single: true, Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingNone}, ID: func(item saasdiscovery.Item) string { return item.Text("siteId") }},
				MapChild: agent("agent")},
			{Name: "bots", Path: "/v1/bots", ItemsPath: []string{"data"}, Headers: map[string]string{"Initech-Version": "2026-01", "Initech-Organization": saasdiscovery.TenantValue},
				Paging: saasdiscovery.Paging{Style: saasdiscovery.PagingCursor, CursorParam: "after", LastItemPath: []string{"id"}, MorePath: []string{"has_more"}, LimitParam: "limit", PageSize: 2},
				Map:    func(item saasdiscovery.Item) (saasdiscovery.Entity, bool) { return agent("bot")("", item) }},
		},
	}
}

func initechRoutes(t *testing.T) map[string]saastest.Route {
	return map[string]saastest.Route{
		"/v1/organization": saastest.Static(`{"id":"org001","name":"Initech"}`),
		"/v1/site":         saastest.Static(`{"siteId":"s-77"}`),
		"/graphql": func(query url.Values, _ int) saastest.Response {
			if query.Get("query") != initechQuery || query.Get("site") != "site:s-77" || query.Get("first") != "2" {
				t.Errorf("query = %v", query)
			}
			if query.Get("after") == "" {
				return saastest.Response{Body: `{"data":{"agents":{"nodes":[{"id":"a1","name":"One"},{"id":"a2","name":"Two"}],"pageInfo":{"hasNextPage":true,"endCursor":"c2"}}}}`}
			}
			return saastest.Response{Body: `{"data":{"agents":{"nodes":[{"id":"a3","name":"Three"}],"pageInfo":{"hasNextPage":false,"endCursor":"c3"}}}}`}
		},
		"/v1/bots": func(query url.Values, _ int) saastest.Response {
			switch query.Get("after") {
			case "":
				return saastest.Response{Body: `{"data":[{"id":"b1","name":"Bot one"},{"id":"b2","name":"Bot two"}],"has_more":true}`}
			case "b2":
				// A full last page: only the flag says it is the last.
				return saastest.Response{Body: `{"data":[{"id":"b3","name":"Bot three"},{"id":"b4","name":"Bot four"}],"has_more":false}`}
			}
			t.Errorf("bots continuation = %q", query.Get("after"))
			return saastest.Response{Status: http.StatusBadRequest, Body: `{}`}
		},
	}
}

func initechRegistry(t *testing.T, platform saasdiscovery.Platform) *saasdiscovery.Registry {
	t.Helper()
	registry, err := saasdiscovery.NewRegistry(platform)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// A GraphQL list, a single parent object, a list paged by the id of its last
// item and forwarded headers run a whole collection to a typed snapshot.
func TestGraphQLAndHeaderEndpointsAreCollectedToATypedSnapshot(t *testing.T) {
	t.Parallel()
	platform := initech()
	registry := initechRegistry(t, platform)
	standIn := saastest.NewNango(t, registry, initechRoutes(t))
	snapshot := saastest.Collect(t, standIn, registry, platform, "org001")
	if agents := snapshot.Kind("saas_agent"); len(agents) != 7 || len(snapshot.Entities) != 8 {
		t.Fatalf("agents=%d: %s", len(agents), snapshot.Raw)
	}
	var gets, posts, bots int
	for _, call := range standIn.Calls() {
		switch {
		case call.Method == http.MethodPost && call.Path == "/graphql":
			posts++
		case call.Path == "/v1/bots":
			bots++
			if call.Headers["Initech-Version"] != "2026-01" || call.Headers["Initech-Organization"] != "org001" {
				t.Fatalf("bots headers = %v", call.Headers)
			}
		case call.Method == http.MethodGet:
			gets++
			if len(call.Headers) != 0 {
				t.Fatalf("headers on %s: %v", call.Path, call.Headers)
			}
		}
	}
	// The organization, the site once, two pages of each list.
	if gets != 2 || posts != 2 || bots != 2 {
		t.Fatalf("gets=%d posts=%d bots=%d", gets, posts, bots)
	}
}

// GraphQL errors end the collection unless the endpoint declares them to
// mean "feature absent".
func TestGraphQLErrorsAreMalformedUnlessDeclaredAbsent(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"errors":         `{"errors":[{"message":"Field 'agents' doesn't exist"}]}`,
		"errors beside":  `{"data":{"agents":null},"errors":[{"message":"denied"}]}`,
		"errors object":  `{"errors":{"message":"denied"}}`,
		"not an object":  `[{"data":{}}]`,
		"nodes not list": `{"data":{"agents":{"nodes":{"id":"a1"}}}}`,
	} {
		platform := initech()
		registry := initechRegistry(t, platform)
		routes := initechRoutes(t)
		routes["/graphql"] = saastest.Static(body)
		_, err := saastest.Run(t, saastest.NewNango(t, registry, routes), registry, platform, "org001")
		var failure *collection.Failure
		if !errors.As(err, &failure) || failure.Code() != collection.FailureMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
	platform := initech()
	platform.Lists[0].GraphQL.ErrorsAbsent = true
	registry := initechRegistry(t, platform)
	routes := initechRoutes(t)
	routes["/graphql"] = saastest.Static(`{"errors":[{"message":"Field 'agents' doesn't exist"}]}`)
	if snapshot := saastest.Collect(t, saastest.NewNango(t, registry, routes), registry, platform, "org001"); len(snapshot.Kind("saas_agent")) != 4 {
		t.Fatalf("absent feature: %s", snapshot.Raw)
	}
}

// A definition can only declare reads: a POST rule must be the path of one
// of its GraphQL lists and list that list's document, which must be a single
// query; headers and paging by the last item are checked too.
func TestGraphQLAndHeaderDefinitionsAreValidated(t *testing.T) {
	t.Parallel()
	if err := initech().Validate(); err != nil {
		t.Fatalf("the test platform is refused: %v", err)
	}
	for name, mutate := range map[string]func(*saasdiscovery.Platform){
		"a POST rule no list uses": func(platform *saasdiscovery.Platform) {
			platform.Nango.Rules = append(platform.Nango.Rules, nango.Rule{Method: http.MethodPost, PathPrefix: "/v1/bots/delete", GraphQLDocuments: []string{initechQuery}})
		},
		"a POST rule without documents": func(platform *saasdiscovery.Platform) { platform.Nango.Rules[3].GraphQLDocuments = nil },
		"a document the rule does not list": func(platform *saasdiscovery.Platform) {
			platform.Lists[0].GraphQL.Document = `query($site: String!, $first: Int!, $after: String) { secrets(site: $site, first: $first, after: $after) { nodes { id } } }`
		},
		"a mutation": func(platform *saasdiscovery.Platform) {
			mutation := `mutation($site: String!) { deleteAgents(site: $site) { ok } }`
			platform.Lists[0].GraphQL.Document, platform.Nango.Rules[3].GraphQLDocuments = mutation, []string{mutation}
		},
		"a query that hides a mutation": func(platform *saasdiscovery.Platform) {
			hidden := initechQuery + ` mutation { deleteAgents { ok } }`
			platform.Lists[0].GraphQL.Document, platform.Nango.Rules[3].GraphQLDocuments = hidden, []string{hidden}
		},
		"a GraphQL list with a query string": func(platform *saasdiscovery.Platform) { platform.Lists[0].Query = map[string]string{"x": "1"} },
		"a GraphQL list with offset paging": func(platform *saasdiscovery.Platform) {
			platform.Lists[0].Paging = saasdiscovery.Paging{Style: saasdiscovery.PagingOffset, OffsetParam: "offset", LimitParam: "first", PageSize: 2}
		},
		"a variable with a bad name":         func(platform *saasdiscovery.Platform) { platform.Lists[0].GraphQL.Variables["site id"] = "x" },
		"a variable that shadows the cursor": func(platform *saasdiscovery.Platform) { platform.Lists[0].GraphQL.Variables["after"] = "x" },
		"a parent the query does not name":   func(platform *saasdiscovery.Platform) { platform.Lists[0].GraphQL.Variables["site"] = "fixed" },
		"a single parent that is paged":      func(platform *saasdiscovery.Platform) { platform.Lists[0].Parent.Paging = platform.Lists[1].Paging },
		"a header the rule does not list":    func(platform *saasdiscovery.Platform) { platform.Lists[1].Headers["Initech-Other"] = "x" },
		"a credential header": func(platform *saasdiscovery.Platform) {
			platform.Lists[1].Headers = map[string]string{"Authorization": "Bearer x"}
		},
		"a header value with a placeholder":    func(platform *saasdiscovery.Platform) { platform.Lists[1].Headers["Initech-Version"] = "v{parent}" },
		"last-item paging without a more flag": func(platform *saasdiscovery.Platform) { platform.Lists[1].Paging.MorePath = nil },
		"last-item paging and a token path":    func(platform *saasdiscovery.Platform) { platform.Lists[1].Paging.NextPath = []string{"last_id"} },
		"last-item paging on an offset list":   func(platform *saasdiscovery.Platform) { platform.Lists[1].Paging.Style = saasdiscovery.PagingOffset },
		"a tenant lookup header without a rule": func(platform *saasdiscovery.Platform) {
			platform.Tenant.Headers = map[string]string{"Initech-Version": "2026-01"}
		},
	} {
		platform := initech()
		mutate(&platform)
		if err := platform.Validate(); !errors.Is(err, saasdiscovery.ErrInvalid) {
			t.Errorf("%s: definition accepted", name)
		}
	}
}
