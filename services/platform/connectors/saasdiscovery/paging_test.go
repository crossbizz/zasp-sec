package saasdiscovery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func decodeDocument(t *testing.T, body string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestCursorPagingSendsTheTokenBackAndEndsOnAnEmptyOne(t *testing.T) {
	endpoint := ListEndpoint{Path: "/v1/items", Query: map[string]string{"view": TenantQueryValue}, Paging: Paging{Style: PagingCursor, CursorParam: "cursor", NextPath: []string{"response_metadata", "next_cursor"}, LimitParam: "limit", PageSize: 200}}
	query, _, ok := endpoint.requestQuery("", "t-1")
	if !ok || query.Encode() != "limit=200&view=t-1" {
		t.Fatalf("first query = %q, %t", query.Encode(), ok)
	}
	query, _, ok = endpoint.requestQuery("dXNlcjpVMDYxTkZUVDI=", "t-1")
	if !ok || query.Encode() != "cursor=dXNlcjpVMDYxTkZUVDI%3D&limit=200&view=t-1" {
		t.Fatalf("next query = %q, %t", query.Encode(), ok)
	}
	for body, want := range map[string]string{
		`{"response_metadata":{"next_cursor":"abc"}}`: "abc",
		`{"response_metadata":{"next_cursor":""}}`:    "",
		`{"response_metadata":{"next_cursor":null}}`:  "",
		`{"response_metadata":{}}`:                    "",
		`{}`:                                          "",
		`{"response_metadata":{"next_cursor":42}}`:    "42",
	} {
		if next, ok := endpoint.continuation(decodeDocument(t, body), "", "previous", 0, 3); !ok || next != want {
			t.Fatalf("%s: next = %q, %t", body, next, ok)
		}
	}
	// A token that is not text, a token that repeats and a token too long
	// to carry in the collection cursor are refused.
	for _, body := range []string{`{"response_metadata":{"next_cursor":{"a":1}}}`, `{"response_metadata":{"next_cursor":"previous"}}`, `{"response_metadata":{"next_cursor":"` + strings.Repeat("x", maximumContinuation+1) + `"}}`, `[]`} {
		if next, ok := endpoint.continuation(decodeDocument(t, body), "", "previous", 0, 3); ok {
			t.Fatalf("%s: accepted as %q", body[:min(len(body), 60)], next)
		}
	}
}

func TestOffsetPagingAdvancesByTheItemsReceivedAndEndsOnAShortPage(t *testing.T) {
	endpoint := ListEndpoint{Path: "/v1/items", Paging: Paging{Style: PagingOffset, OffsetParam: "sysparm_offset", LimitParam: "sysparm_limit", PageSize: 100}}
	query, offset, ok := endpoint.requestQuery("", "t-1")
	if !ok || offset != 0 || query.Encode() != "sysparm_limit=100&sysparm_offset=0" {
		t.Fatalf("first query = %q, %d, %t", query.Encode(), offset, ok)
	}
	next, ok := endpoint.continuation(nil, "", "", offset, 100)
	if !ok || next != "100" {
		t.Fatalf("after a full page: %q, %t", next, ok)
	}
	query, offset, ok = endpoint.requestQuery(next, "t-1")
	if !ok || offset != 100 || query.Encode() != "sysparm_limit=100&sysparm_offset=100" {
		t.Fatalf("second query = %q, %d, %t", query.Encode(), offset, ok)
	}
	for _, count := range []int{0, 1, 99} {
		if next, ok := endpoint.continuation(nil, "", "100", 100, count); !ok || next != "" {
			t.Fatalf("after %d items: %q, %t", count, next, ok)
		}
	}
	for _, hostile := range []string{"-1", "0", "abc", "0100", "1e3", "100000001"} {
		if _, _, ok := endpoint.requestQuery(hostile, "t-1"); ok {
			t.Fatalf("offset %q accepted", hostile)
		}
	}
}

func TestLinkPagingFollowsOnlyTheEndpointsOwnPath(t *testing.T) {
	endpoint := ListEndpoint{Path: "/api/v4/projects", Query: map[string]string{"archived": "false"}, Paging: Paging{Style: PagingLink, LimitParam: "per_page", PageSize: 50}}
	query, _, ok := endpoint.requestQuery("", "t-1")
	if !ok || query.Encode() != "archived=false&per_page=50" {
		t.Fatalf("first query = %q, %t", query.Encode(), ok)
	}
	for header, want := range map[string]string{
		"": "",
		`<https://gitlab.example/api/v4/projects?page=2&per_page=50>; rel="next", <https://gitlab.example/api/v4/projects?page=9&per_page=50>; rel="last"`: "page=2&per_page=50",
		`<https://gitlab.example/api/v4/projects?page=1&per_page=50>; rel="first"`:                                                                         "",
		`</api/v4/projects?id_after=77&per_page=50>; rel=next`:                                                                                             "id_after=77&per_page=50",
		`</api/v4/projects?page=3>; rel="prev next"`:                                                                                                       "page=3",
		`garbage`: "",
	} {
		next, ok := nextLinkQuery(header, endpoint.Path)
		if !ok || next != want {
			t.Fatalf("%q: next = %q, %t", header, next, ok)
		}
	}
	// A next link that leaves the endpoint is refused: the collector follows
	// no provider-chosen location.
	for _, header := range []string{
		`<https://gitlab.example/api/v4/users?page=2>; rel="next"`,
		`<https://gitlab.example/api/v4/projects/../admin?page=2>; rel="next"`,
		`<https://gitlab.example/api/v4/projects>; rel="next"`,
		`<https://gitlab.example/api/v4/projects?page=2#fragment>; rel="next"`,
	} {
		if next, ok := nextLinkQuery(header, endpoint.Path); ok {
			t.Fatalf("%q accepted as %q", header, next)
		}
	}
	// The next request carries the provider's query, whole.
	query, _, ok = endpoint.requestQuery("page=2&per_page=50", "t-1")
	if !ok || query.Encode() != "page=2&per_page=50" {
		t.Fatalf("next query = %q, %t", query.Encode(), ok)
	}
	for _, hostile := range []string{"page=2&page=3", "%zz"} {
		if _, _, ok := endpoint.requestQuery(hostile, "t-1"); ok {
			t.Fatalf("continuation %q accepted", hostile)
		}
	}
	if next, ok := endpoint.continuation(nil, `</api/v4/projects?page=2>; rel="next"`, "page=2", 0, 50); ok {
		t.Fatalf("a link that repeats the page accepted as %q", next)
	}
}

func TestUnpagedEndpointMakesOneRequest(t *testing.T) {
	endpoint := ListEndpoint{Path: "/v1/items", Paging: Paging{Style: PagingNone}}
	if query, _, ok := endpoint.requestQuery("", "t-1"); !ok || len(query) != 0 {
		t.Fatalf("query = %v, %t", query, ok)
	}
	if _, _, ok := endpoint.requestQuery("anything", "t-1"); ok {
		t.Fatal("an unpaged endpoint accepted a continuation")
	}
	if next, ok := endpoint.continuation(decodeDocument(t, `{"next":"x"}`), `</v1/items?page=2>; rel="next"`, "", 0, 10); !ok || next != "" {
		t.Fatalf("continuation = %q, %t", next, ok)
	}
}

func TestItemsAreFoundAtThePathAndAMissingArrayIsEmpty(t *testing.T) {
	nested := ListEndpoint{ItemsPath: []string{"result", "records"}}
	if items, ok := nested.items(decodeDocument(t, `{"result":{"records":[{"id":1},{"id":2}]}}`)); !ok || len(items) != 2 || items[1].Text("id") != "2" {
		t.Fatalf("items = %v, %t", items, ok)
	}
	for _, body := range []string{`{}`, `{"result":{}}`, `{"result":{"records":null}}`} {
		if items, ok := nested.items(decodeDocument(t, body)); !ok || len(items) != 0 {
			t.Fatalf("%s: items = %v, %t", body, items, ok)
		}
	}
	for _, body := range []string{`{"result":{"records":"x"}}`, `{"result":{"records":[1]}}`, `[]`} {
		if _, ok := nested.items(decodeDocument(t, body)); ok {
			t.Fatalf("%s accepted", body)
		}
	}
	top := ListEndpoint{}
	if items, ok := top.items(decodeDocument(t, `[{"id":"a"}]`)); !ok || len(items) != 1 {
		t.Fatalf("top-level array = %v, %t", items, ok)
	}
	if _, ok := top.items(decodeDocument(t, `{"id":"a"}`)); ok {
		t.Fatal("an object accepted where the response is the array")
	}
}

func TestCollectionCursorIsBoundToTheSubjectAndThePage(t *testing.T) {
	subject := collection.SubjectBinding{Kind: "saas_tenant", ID: "acme/acct-42"}
	platform := Platform{Token: "acme", TenantPattern: tenantIDPattern, Lists: []ListEndpoint{{Name: "agents"}, {Name: "apps"}}}
	api := &SaaSCollectionAPI{registry: &Registry{platforms: map[string]Platform{"acme": platform}}}
	cursor, ok := nextStateCursor(subject, pageState{Phase: "apps", Lineage: 3, Next: "200"})
	if !ok {
		t.Fatal("cursor refused")
	}
	request := CollectionPageRequest{Provider: collection.ProviderSaaS, Subject: subject, Cursor: cursor, Page: 3, RemainingItems: 10, RemainingRelationships: 10, RemainingBytes: 1 << 20}
	if _, tenant, state, ok := api.validPageRequest(request); !ok || tenant != "acct-42" || state != (pageState{Phase: "apps", Lineage: 3, Next: "200"}) {
		t.Fatalf("state = %+v, %t", state, ok)
	}
	other := request
	other.Subject.ID = "acme/acct-43"
	wrongPage := request
	wrongPage.Page = 4
	unknownPlatform := request
	unknownPlatform.Subject.ID = "other/acct-42"
	forged := request
	forged.Cursor.Value = strings.Replace(cursor.Value, "saas:apps:", "saas:agents:", 1)
	anotherProvider := request
	anotherProvider.Cursor.Provider = collection.ProviderOkta
	for name, hostile := range map[string]CollectionPageRequest{"another tenant": other, "another page": wrongPage, "unknown platform": unknownPlatform, "forged phase": forged, "another provider": anotherProvider} {
		if _, _, _, ok := api.validPageRequest(hostile); ok {
			t.Fatalf("%s: cursor accepted", name)
		}
	}
	// A new collection starts at the tenant lookup, also from the complete
	// cursor of the previous one.
	complete := nextCompleteCursor(cursor, subject)
	for _, start := range []collection.Cursor{{}, complete} {
		first := CollectionPageRequest{Provider: collection.ProviderSaaS, Subject: subject, Cursor: start, Page: 1, RemainingItems: 10, RemainingRelationships: 10, RemainingBytes: 1 << 20}
		if _, _, state, ok := api.validPageRequest(first); !ok || state != (pageState{Phase: "tenant", Lineage: 1}) {
			t.Fatalf("first state = %+v, %t", state, ok)
		}
	}
}

func TestCleanTextFitsProviderTextToAnInventoryField(t *testing.T) {
	for input, want := range map[string]string{"  Support\tAgent\n ": "Support Agent", "ok": "ok", "\x00\x01": "", "a\x00b": "ab"} {
		if got := CleanText(input, 256); got != want {
			t.Fatalf("CleanText(%q) = %q, want %q", input, got, want)
		}
	}
	// The cut is on a character boundary and leaves no trailing space.
	for input, want := range map[string]string{"żółw żółw": "żółw", "Support Agent": "Support"} {
		if got := CleanText(input, 8); got != want {
			t.Fatalf("CleanText(%q, 8) = %q, want %q", input, got, want)
		}
	}
}
