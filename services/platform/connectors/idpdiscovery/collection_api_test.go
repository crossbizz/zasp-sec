package idpdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

type oktaRoundTripper struct {
	mu        sync.Mutex
	requests  []*http.Request
	responses []oktaHTTPResponse
}

type oktaHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *oktaRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	roundTripper.requests = append(roundTripper.requests, request.Clone(request.Context()))
	if len(roundTripper.responses) == 0 {
		return nil, errors.New("okta-provider-secret")
	}
	response := roundTripper.responses[0]
	roundTripper.responses = roundTripper.responses[1:]
	return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
}

func TestOktaCollectionAPIPaginatesUsersGroupsAndApplicationsCanonically(t *testing.T) {
	t.Parallel()
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[{"id":"00g1234567890ABCDE1","type":"OKTA_GROUP","profile":{"name":"Administrators"}}]`},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"ACTIVE","signOnMode":"BOOKMARK"}]`},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[]`},
	}}
	api, err := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err != nil {
		t.Fatalf("newOktaCollectionAPI() error = %v", err)
	}
	credential := []byte("okta-access-secret-value")
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 8, RemainingRelationships: 16, RemainingBytes: 1 << 20}
	pages := make([]CollectionPage, 0, 8)
	for pageNumber := 1; pageNumber <= 8; pageNumber++ {
		request.Page = pageNumber
		page, fetchErr := api.FetchCollectionPage(context.Background(), credential, request)
		if fetchErr != nil {
			t.Fatalf("FetchCollectionPage(%d) error = %v", pageNumber, fetchErr)
		}
		if bytes.Contains(page.Raw, credential) || !bytes.Equal(page.Raw, mustOktaCollectionPage(t, page).Raw) {
			t.Fatalf("page %d leaked or noncanonical: %s", pageNumber, page.Raw)
		}
		pages = append(pages, page)
		request.Cursor = page.Cursor
		request.RemainingItems -= len(page.Entities)
		request.RemainingRelationships -= len(page.Relationships)
	}
	if pages[0].Complete || !strings.HasPrefix(pages[0].Cursor.Value, "okta:userroles:") || len(pages[0].Entities) != 2 || len(pages[0].Relationships) != 1 || pages[2].Complete || !strings.HasPrefix(pages[2].Cursor.Value, "okta:groupmembers:") || len(pages[2].Entities) != 1 || !pages[7].Complete || !strings.HasPrefix(pages[7].Cursor.Value, "okta:complete:") || len(pages[5].Entities) != 1 {
		t.Fatalf("pages = %#v", pages)
	}
	wantURLs := []string{
		"https://acme.okta.com/api/v1/users?limit=1",
		"https://acme.okta.com/api/v1/users/00u1234567890ABCDE1/roles",
		"https://acme.okta.com/api/v1/groups?limit=1",
		"https://acme.okta.com/api/v1/groups/00g1234567890ABCDE1/users?limit=14",
		"https://acme.okta.com/api/v1/groups/00g1234567890ABCDE1/roles",
		"https://acme.okta.com/api/v1/apps?limit=1",
		"https://acme.okta.com/api/v1/apps/0oa1234567890ABCDE1/users?limit=13",
		"https://acme.okta.com/api/v1/apps/0oa1234567890ABCDE1/groups?limit=13",
	}
	if len(roundTripper.requests) != len(wantURLs) {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	for index, providerRequest := range roundTripper.requests {
		if providerRequest.Method != http.MethodGet || providerRequest.URL.String() != wantURLs[index] || providerRequest.Header.Get("Authorization") != "Bearer "+string(credential) || providerRequest.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d = %#v", index, providerRequest)
		}
	}
}

func TestOktaCollectionAPICollectsMembershipAssignmentsRolesAndServicePrincipalsBeforeComplete(t *testing.T) {
	t.Parallel()
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		{status: http.StatusOK, body: `[{"id":"ra1234567890ABCDE1","label":"Organization administrator","type":"ORG_ADMIN","status":"ACTIVE","assignmentType":"USER"}]`},
		{status: http.StatusOK, body: `[{"id":"00g1234567890ABCDE1","type":"OKTA_GROUP","profile":{"name":"Administrators"}}]`},
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		{status: http.StatusOK, body: `[{"id":"gra1234567890ABCDE1","label":"Application administrator","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"GROUP"}]`},
		{status: http.StatusOK, body: `[{"id":"0oa1234567890ABCDE1","name":"oidc_client","label":"Portal","status":"ACTIVE","signOnMode":"OPENID_CONNECT","credentials":{"oauthClient":{"client_id":"client1234567890ABCDE1"}}}]`},
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","scope":"USER","status":"ACTIVE"}]`},
		{status: http.StatusOK, body: `[{"id":"00g1234567890ABCDE1"}]`},
		{status: http.StatusOK, body: `[{"id":"cra1234567890ABCDE1","label":"Read-only administrator","type":"READ_ONLY_ADMIN","status":"ACTIVE","assignmentType":"CLIENT"}]`},
	}}
	api, err := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("okta-access-secret-value")
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Page: 1, RemainingItems: 32, RemainingRelationships: 32, RemainingBytes: 1 << 20}
	allKinds, allRelationships := make([]string, 0), make([]string, 0)
	for pageNumber := 1; pageNumber <= 9; pageNumber++ {
		request.Page = pageNumber
		page, fetchErr := api.FetchCollectionPage(context.Background(), credential, request)
		if fetchErr != nil {
			t.Fatalf("page %d error = %v", pageNumber, fetchErr)
		}
		allKinds = append(allKinds, oktaInventoryKinds(page.Entities)...)
		allRelationships = append(allRelationships, oktaInventoryKinds(page.Relationships)...)
		if page.Complete != (pageNumber == 9) {
			t.Fatalf("page %d complete = %t", pageNumber, page.Complete)
		}
		request.Cursor = page.Cursor
		request.RemainingItems -= len(page.Entities)
		request.RemainingRelationships -= len(page.Relationships)
	}
	sort.Strings(allKinds)
	sort.Strings(allRelationships)
	if fmt.Sprint(allKinds) != "[okta_application okta_group okta_role okta_role okta_role okta_service_principal okta_tenant okta_user]" || fmt.Sprint(allRelationships) != "[assigned_to assigned_to assigned_to assigned_to assigned_to assigned_to contains contains contains contains member_of]" {
		t.Fatalf("inventory kinds = %v / %v", allKinds, allRelationships)
	}
	wantURLs := []string{
		"https://acme.okta.com/api/v1/users?limit=1",
		"https://acme.okta.com/api/v1/users/00u1234567890ABCDE1/roles",
		"https://acme.okta.com/api/v1/groups?limit=1",
		"https://acme.okta.com/api/v1/groups/00g1234567890ABCDE1/users?limit=29",
		"https://acme.okta.com/api/v1/groups/00g1234567890ABCDE1/roles",
		"https://acme.okta.com/api/v1/apps?limit=1",
		"https://acme.okta.com/api/v1/apps/0oa1234567890ABCDE1/users?limit=24",
		"https://acme.okta.com/api/v1/apps/0oa1234567890ABCDE1/groups?limit=23",
		"https://acme.okta.com/oauth2/v1/clients/client1234567890ABCDE1/roles",
	}
	if len(roundTripper.requests) != len(wantURLs) {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	for index, providerRequest := range roundTripper.requests {
		if providerRequest.URL.String() != wantURLs[index] {
			t.Fatalf("request %d = %s, want %s", index, providerRequest.URL, wantURLs[index])
		}
	}
}

func TestOktaCollectionAPIAcceptsOnlySameTenantOpaqueNextCursor(t *testing.T) {
	t.Parallel()
	firstHeader := http.Header{"Link": []string{`<https://acme.okta.com/api/v1/users?after=opaque-next&limit=200>; rel="next"`}}
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`, header: firstHeader},
		{status: http.StatusOK, body: `[]`},
		{status: http.StatusOK, body: `[]`},
	}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingRelationships: 8, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request)
	if err != nil || !strings.HasPrefix(first.Cursor.Value, "okta:userroles:") {
		t.Fatalf("first page/cursor = %#v, %v", first, err)
	}
	request.Cursor = first.Cursor
	request.Page = 2
	request.RemainingItems = 2
	roles, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request)
	if err != nil || !strings.HasPrefix(roles.Cursor.Value, "okta:users:") {
		t.Fatalf("second page error = %v", err)
	}
	request.Cursor, request.Page = roles.Cursor, 3
	if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request); err != nil {
		t.Fatalf("third page error = %v", err)
	}
	if len(roundTripper.requests) != 3 || roundTripper.requests[2].URL.String() != "https://acme.okta.com/api/v1/users?after=opaque-next&limit=1" {
		t.Fatalf("provider requests = %#v", roundTripper.requests)
	}
	for name, link := range map[string]string{
		"foreign host":    `<https://evil.example/steal?after=x>; rel="next"`,
		"duplicate after": `<https://acme.okta.com/api/v1/users?after=first&after=second&limit=2>; rel="next"`,
		"duplicate limit": `<https://acme.okta.com/api/v1/users?after=next&limit=2&limit=3>; rel="next"`,
		"invalid limit":   `<https://acme.okta.com/api/v1/users?after=next&limit=0>; rel="next"`,
	} {
		t.Run(name, func(t *testing.T) {
			hostile := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `[]`, header: http.Header{"Link": []string{link}}}}}
			api, _ = newOktaCollectionAPI("https://acme.okta.com", hostile, time.Second)
			if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: request.Subject, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingRelationships: 8, RemainingBytes: 4096}); !oktaFailureHasCode(err, collection.FailureMalformed) || len(hostile.requests) != 1 {
				t.Fatalf("hostile link error/calls = %v / %d", err, len(hostile.requests))
			}
		})
	}
}

func TestOktaCollectionAPIAcceptsTerminalSelfLinkWithoutInventingAnotherProviderCall(t *testing.T) {
	t.Parallel()
	self := http.Header{"Link": []string{`<https://acme.okta.com/api/v1/apps?limit=1>; rel="self"`}}
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"ACTIVE","signOnMode":"BOOKMARK"}]`, header: self}}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	page, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: subject, Cursor: nextOktaPageCursor(subject, "applications", 3, "start"), Page: 3, RemainingItems: 2, RemainingRelationships: 4, RemainingBytes: 4096})
	if err != nil || page.Complete || !strings.HasPrefix(page.Cursor.Value, "okta:appusers:") || len(roundTripper.requests) != 1 {
		t.Fatalf("terminal self-link page/error/calls = %#v / %v / %d", page, err, len(roundTripper.requests))
	}
}

func TestOktaCollectionAPIRejectsCredentialEchoFromProviderData(t *testing.T) {
	t.Parallel()
	const credential = "okta-access-secret-value"
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"okta-access-secret-value"}}]`}}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	_, err := api.FetchCollectionPage(context.Background(), []byte(credential), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingRelationships: 8, RemainingBytes: 4096})
	if !oktaFailureHasCode(err, collection.FailureMalformed) || strings.Contains(err.Error(), credential) || len(roundTripper.requests) != 1 {
		t.Fatalf("credential echo error/calls = %q / %d", err, len(roundTripper.requests))
	}
}

func TestOktaCollectionAPIRejectsCursorTransplantAndClassifiesRateLimit(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: subject, Cursor: nextOktaPageCursor(collection.SubjectBinding{Kind: "okta_tenant", ID: "other.okta.com"}, "groups", 2, "start"), Page: 2, RemainingItems: 2, RemainingRelationships: 4, RemainingBytes: 4096}
	roundTripper := &oktaRoundTripper{}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request); !errors.Is(err, ErrInvalid) || len(roundTripper.requests) != 0 {
		t.Fatalf("foreign cursor error/calls = %v / %d", err, len(roundTripper.requests))
	}
	rateLimited := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"3"}}, body: `{}`}}}
	api, _ = newOktaCollectionAPI("https://acme.okta.com", rateLimited, time.Second)
	request.Cursor = collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}
	request.Page = 1
	if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request); !oktaFailureHasCode(err, collection.FailureRateLimited) {
		t.Fatalf("rate limit failure = %v", err)
	}
}

func TestOktaCollectionAPIReadinessBindsIssuerAndRejectsRedirect(t *testing.T) {
	t.Parallel()
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `{"issuer":"https://acme.okta.com"}`}}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("CheckCollectionReadiness() error = %v", err)
	}
	if len(roundTripper.requests) != 1 || roundTripper.requests[0].URL.String() != "https://acme.okta.com/.well-known/openid-configuration" || roundTripper.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("readiness requests = %#v", roundTripper.requests)
	}
	redirect := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusFound, body: `{}`, header: http.Header{"Location": []string{"https://evil.example"}}}}}
	api, _ = newOktaCollectionAPI("https://acme.okta.com", redirect, time.Second)
	if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) || len(redirect.requests) != 1 {
		t.Fatalf("redirect readiness error/calls = %v / %d", err, len(redirect.requests))
	}
}

func TestOktaNormalizationPreservesOnlyDirectRoleAndApplicationAssignments(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	state := oktaPageState{Phase: "userroles", PrincipalID: "00u1234567890ABCDE1"}
	direct := json.RawMessage(`{"id":"IFIFAX2BIRGUSTQ","label":"Application administrator","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"USER"}`)
	entities, relationships, ok := normalizeOktaRoleAssignments(subject, state, []json.RawMessage{direct})
	if !ok || len(entities) != 1 || len(relationships) != 1 {
		t.Fatalf("direct user role = %d/%d/%t", len(entities), len(relationships), ok)
	}
	inherited := json.RawMessage(`{"id":"IFIFAX2BIRGUSTQ","label":"Application administrator","type":"APP_ADMIN","status":"ACTIVE","assignmentType":"GROUP"}`)
	entities, relationships, ok = normalizeOktaRoleAssignments(subject, state, []json.RawMessage{inherited})
	if !ok || len(entities) != 0 || len(relationships) != 0 {
		t.Fatalf("inherited user role = %d/%d/%t", len(entities), len(relationships), ok)
	}

	appState := oktaPageState{Phase: "appusers", AppID: "0oa1234567890ABCDE1"}
	_, relationships, ok = normalizeOktaAssignmentReferences(subject, appState, []json.RawMessage{json.RawMessage(`{"id":"00u1234567890ABCDE1","scope":"USER"}`)})
	if !ok || len(relationships) != 1 {
		t.Fatalf("direct app user = %d/%t", len(relationships), ok)
	}
	_, relationships, ok = normalizeOktaAssignmentReferences(subject, appState, []json.RawMessage{json.RawMessage(`{"id":"00u1234567890ABCDE1","scope":"GROUP"}`)})
	if !ok || len(relationships) != 0 {
		t.Fatalf("group-derived app user = %d/%t", len(relationships), ok)
	}
	if _, _, ok := normalizeOktaAssignmentReferences(subject, appState, []json.RawMessage{json.RawMessage(`{"id":"00u1234567890ABCDE1","scope":"UNKNOWN"}`)}); ok {
		t.Fatal("unknown app-user assignment scope accepted")
	}
}

func TestOktaNormalizationRequiresExactProviderEnumsAndOIDCIdentity(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}
	for name, test := range map[string]struct {
		phase string
		body  string
	}{
		"unknown user status":  {"users", `[{"id":"00u1234567890ABCDE1","status":"UNKNOWN","profile":{"login":"alice@example.com","displayName":"Alice"}}]`},
		"unknown group type":   {"groups", `[{"id":"00g1234567890ABCDE1","type":"EXTERNAL","profile":{"name":"Administrators"}}]`},
		"unknown app status":   {"applications", `[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"UNKNOWN","signOnMode":"BOOKMARK"}]`},
		"missing sign on mode": {"applications", `[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"ACTIVE"}]`},
		"unknown sign on mode": {"applications", `[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"ACTIVE","signOnMode":"UNKNOWN"}]`},
		"oidc missing client":  {"applications", `[{"id":"0oa1234567890ABCDE1","name":"oidc_client","label":"Portal","status":"ACTIVE","signOnMode":"OPENID_CONNECT"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			var objects []json.RawMessage
			if json.Unmarshal([]byte(test.body), &objects) != nil {
				t.Fatal("invalid test body")
			}
			if _, _, ok := normalizeOktaCollectionPage(subject, test.phase, true, objects); ok {
				t.Fatal("hostile enum/application shape accepted")
			}
		})
	}
	var valid []json.RawMessage
	_ = json.Unmarshal([]byte(`[{"id":"0oa1234567890ABCDE1","name":"bookmark","label":"Portal","status":"INACTIVE","signOnMode":"BOOKMARK"}]`), &valid)
	if _, _, ok := normalizeOktaCollectionPage(subject, "applications", true, valid); !ok {
		t.Fatal("valid non-OIDC application rejected")
	}
}

func mustOktaCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewOktaCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewOktaCollectionPage() error = %v", err)
	}
	return canonical
}

func oktaFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

func oktaInventoryKinds(values []json.RawMessage) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		var item struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(value, &item) != nil {
			result = append(result, "malformed")
			continue
		}
		result = append(result, item.Kind)
	}
	return result
}
