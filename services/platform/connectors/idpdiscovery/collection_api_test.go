package idpdiscovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
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
		{status: http.StatusOK, body: `[{"id":"00g1234567890ABCDE1","type":"OKTA_GROUP","profile":{"name":"Administrators"}}]`},
		{status: http.StatusOK, body: `[{"id":"0oa1234567890ABCDE1","name":"oidc_client","label":"Portal","status":"ACTIVE"}]`},
	}}
	api, err := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	if err != nil {
		t.Fatalf("newOktaCollectionAPI() error = %v", err)
	}
	credential := []byte("okta-access-secret-value")
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 4, RemainingBytes: 1 << 20}
	pages := make([]CollectionPage, 0, 3)
	for pageNumber := 1; pageNumber <= 3; pageNumber++ {
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
	}
	if pages[0].Complete || pages[0].Cursor.Value != "okta:groups:start" || len(pages[0].Entities) != 2 || len(pages[0].Relationships) != 1 || pages[1].Complete || pages[1].Cursor.Value != "okta:applications:start" || len(pages[1].Entities) != 1 || !pages[2].Complete || !strings.HasPrefix(pages[2].Cursor.Value, "okta:complete:") || len(pages[2].Entities) != 1 {
		t.Fatalf("pages = %#v", pages)
	}
	wantURLs := []string{"https://acme.okta.com/api/v1/users?limit=3", "https://acme.okta.com/api/v1/groups?limit=2", "https://acme.okta.com/api/v1/apps?limit=1"}
	if len(roundTripper.requests) != len(wantURLs) {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	for index, providerRequest := range roundTripper.requests {
		if providerRequest.Method != http.MethodGet || providerRequest.URL.String() != wantURLs[index] || providerRequest.Header.Get("Authorization") != "Bearer "+string(credential) || providerRequest.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d = %#v", index, providerRequest)
		}
	}
}

func TestOktaCollectionAPIAcceptsOnlySameTenantOpaqueNextCursor(t *testing.T) {
	t.Parallel()
	firstHeader := http.Header{"Link": []string{`<https://acme.okta.com/api/v1/users?after=opaque-next&limit=200>; rel="next"`}}
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{
		{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"Alice"}}]`, header: firstHeader},
		{status: http.StatusOK, body: `[]`},
	}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request)
	if err != nil || !strings.HasPrefix(first.Cursor.Value, "okta:users:") {
		t.Fatalf("first page/cursor = %#v, %v", first, err)
	}
	request.Cursor = first.Cursor
	request.Page = 2
	request.RemainingItems = 2
	if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), request); err != nil {
		t.Fatalf("second page error = %v", err)
	}
	if len(roundTripper.requests) != 2 || roundTripper.requests[1].URL.String() != "https://acme.okta.com/api/v1/users?after=opaque-next&limit=2" {
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
			if _, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: request.Subject, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingBytes: 4096}); !errors.Is(err, ErrProvider) || len(hostile.requests) != 1 {
				t.Fatalf("hostile link error/calls = %v / %d", err, len(hostile.requests))
			}
		})
	}
}

func TestOktaCollectionAPIAcceptsTerminalSelfLinkWithoutInventingAnotherProviderCall(t *testing.T) {
	t.Parallel()
	self := http.Header{"Link": []string{`<https://acme.okta.com/api/v1/apps?limit=1>; rel="self"`}}
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `[{"id":"0oa1234567890ABCDE1","name":"oidc_client","label":"Portal","status":"ACTIVE"}]`, header: self}}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	page, err := api.FetchCollectionPage(context.Background(), []byte("okta-access-secret-value"), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "okta:applications:start"}, Page: 3, RemainingItems: 1, RemainingBytes: 4096})
	if err != nil || !page.Complete || len(roundTripper.requests) != 1 {
		t.Fatalf("terminal self-link page/error/calls = %#v / %v / %d", page, err, len(roundTripper.requests))
	}
}

func TestOktaCollectionAPIRejectsCredentialEchoFromProviderData(t *testing.T) {
	t.Parallel()
	const credential = "okta-access-secret-value"
	roundTripper := &oktaRoundTripper{responses: []oktaHTTPResponse{{status: http.StatusOK, body: `[{"id":"00u1234567890ABCDE1","status":"ACTIVE","profile":{"login":"alice@example.com","displayName":"okta-access-secret-value"}}]`}}}
	api, _ := newOktaCollectionAPI("https://acme.okta.com", roundTripper, time.Second)
	_, err := api.FetchCollectionPage(context.Background(), []byte(credential), CollectionPageRequest{Provider: collection.ProviderOkta, Subject: collection.SubjectBinding{Kind: "okta_tenant", ID: "acme.okta.com"}, Cursor: collection.Cursor{Provider: collection.ProviderOkta, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingBytes: 4096})
	if !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), credential) || len(roundTripper.requests) != 1 {
		t.Fatalf("credential echo error/calls = %q / %d", err, len(roundTripper.requests))
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

func mustOktaCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewOktaCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewOktaCollectionPage() error = %v", err)
	}
	return canonical
}
