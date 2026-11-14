package nango

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

const testCatalogQuery = `query($group: GroupID!, $after: String) { items(groupId: $group, after: $after) { nodes { id name } pageInfo { hasNextPage endCursor } } }`

func graphQLTestAdapter(t *testing.T, seen *[]*http.Request, bodies *[]string) *Adapter {
	t.Helper()
	resolver := serviceSecretResolverFunc(func(context.Context, string) ([]byte, error) {
		return []byte("00000000-0000-4000-8000-000000000001"), nil
	})
	client, err := NewProxyClientWithHTTP(resolver, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		*seen, *bodies = append(*seen, request), append(*bodies, string(body))
		return saasTestResponse(http.StatusOK, `{"data":{}}`, nil), nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(Config{BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		Entries: []Entry{{Key: "gitlab", ProviderHost: "gitlab.com", AuthMode: "oauth", Rules: []Rule{
			{Method: http.MethodPost, PathPrefix: "/api/graphql", GraphQLDocuments: []string{testCatalogQuery}},
			{Method: http.MethodGet, PathPrefix: "/v1/assistants", QueryKeys: []string{"limit"}, HeaderKeys: []string{"OpenAI-Beta"}},
		}}}}, fixedPublicResolver{}, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

// A rule that lists GraphQL documents admits a POST of exactly one of them
// and nothing else: no other query, no mutation, no further member.
func TestGraphQLRuleAdmitsOnlyItsListedQueryDocuments(t *testing.T) {
	var seen []*http.Request
	var bodies []string
	adapter := graphQLTestAdapter(t, &seen, &bodies)
	post := func(body string) error {
		_, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab", ConnectionReference: saasTestConnection, Method: http.MethodPost, Path: "/api/graphql", Body: []byte(body)})
		return err
	}
	admitted := `{"query":"` + testCatalogQuery + `","variables":{"after":"c2","group":"gid://gitlab/Group/4242","first":50}}`
	if err := post(admitted); err != nil || len(seen) != 1 || seen[0].Method != http.MethodPost || bodies[0] != admitted || seen[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("listed query: %v, %d requests", err, len(seen))
	}
	for name, body := range map[string]string{
		"another query":       `{"query":"query { currentUser { id } }","variables":{}}`,
		"a mutation":          `{"query":"mutation { projectDelete(id: 1) { errors } }","variables":{}}`,
		"query plus mutation": `{"query":"` + testCatalogQuery + ` mutation { x }","variables":{}}`,
		"extra member":        `{"query":"` + testCatalogQuery + `","variables":{},"operationName":"x"}`,
		"batched":             `[{"query":"` + testCatalogQuery + `","variables":{}}]`,
		"trailing document":   `{"query":"` + testCatalogQuery + `","variables":{}}{"query":"mutation { x }"}`,
		"nested variable":     `{"query":"` + testCatalogQuery + `","variables":{"group":{"id":"x"}}}`,
		"no query":            `{"variables":{}}`,
		"not json":            `query { x }`,
		"empty":               ``,
	} {
		if err := post(body); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The path admits no GET and the document no other path.
	if _, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab", ConnectionReference: saasTestConnection, Method: http.MethodGet, Path: "/api/graphql"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("GET of the GraphQL path: %v", err)
	}
	if _, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab", ConnectionReference: saasTestConnection, Method: http.MethodPost, Path: "/v1/assistants", Body: []byte(admitted)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("POST of a GET path: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("a refused request reached Nango: %d", len(seen))
	}
}

func TestReadOnlyGraphQLDocument(t *testing.T) {
	for document, want := range map[string]bool{
		testCatalogQuery:                                    true,
		`query { items { id } }`:                            true,
		`query Items { items { id } }`:                      true,
		`mutation { delete { id } }`:                        false,
		`subscription { events { id } }`:                    false,
		`query { items { id } } mutation { delete { id } }`: false,
		`query { a { id } } query { b { id } }`:             false,
		`{ items { id } }`:                                  false,
		"query { items { id } } # mutation":                 false,
		"query { items {\n id } }":                          false,
		`query { items { id }`:                              false,
		`query { items { id } } }`:                          false,
		`query { doMutation: items { id } }`:                true,
		`query { Mutation { id } }`:                         false,
		`query`:                                             false,
	} {
		if got := ReadOnlyGraphQLDocument(document); got != want {
			t.Errorf("%q = %t, want %t", document, got, want)
		}
	}
	// An entry cannot list a document that is not a single query.
	for _, rule := range []Rule{
		{Method: http.MethodPost, PathPrefix: "/api/graphql", GraphQLDocuments: []string{`mutation { delete { id } }`}},
		{Method: http.MethodGet, PathPrefix: "/api/graphql", GraphQLDocuments: []string{testCatalogQuery}},
		{Method: http.MethodGet, PathPrefix: "/v1/items", HeaderKeys: []string{"Authorization"}},
		{Method: http.MethodGet, PathPrefix: "/v1/items", HeaderKeys: []string{"Base-Url-Override"}},
		{Method: http.MethodGet, PathPrefix: "/v1/items", HeaderKeys: []string{"Nango-Proxy-Authorization"}},
		{Method: http.MethodGet, PathPrefix: "/v1/items", HeaderKeys: []string{"X-Version", "x-version"}},
	} {
		if validEntry(Entry{Key: "example", ProviderHost: "api.example.com", AuthMode: "api_key", Rules: []Rule{rule}}) {
			t.Errorf("entry with rule %+v accepted", rule)
		}
	}
}

// A provider header is forwarded only when the rule lists it, as
// Nango-Proxy-<name>; the proxy's own headers cannot be set through it.
func TestForwardedHeadersAreAllowListedByTheRule(t *testing.T) {
	var seen []*http.Request
	var bodies []string
	adapter := graphQLTestAdapter(t, &seen, &bodies)
	get := func(headers map[string]string) error {
		_, err := adapter.Do(context.Background(), Request{ConnectorKey: "gitlab", ConnectionReference: saasTestConnection, Method: http.MethodGet, Path: "/v1/assistants", Headers: headers})
		return err
	}
	if err := get(map[string]string{"OpenAI-Beta": "assistants=v2"}); err != nil || len(seen) != 1 || seen[0].Header.Get("Nango-Proxy-OpenAI-Beta") != "assistants=v2" || seen[0].Header.Get("OpenAI-Beta") != "" {
		t.Fatalf("listed header: %v", err)
	}
	for name, headers := range map[string]map[string]string{
		"unlisted":       {"OpenAI-Project": "proj_x"},
		"credential":     {"Authorization": "Bearer x"},
		"line break":     {"OpenAI-Beta": "a\r\nX-Other: b"},
		"secret marker":  {"OpenAI-Beta": "access_token=1"},
		"case variation": {"openai-beta": "assistants=v2"},
	} {
		if err := get(headers); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("a refused request reached Nango: %d", len(seen))
	}
}
