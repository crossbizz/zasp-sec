package githubdiscovery

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

type installationRoundTripper struct {
	mu        sync.Mutex
	requests  []*http.Request
	responses []installationHTTPResponse
	panicCall bool
}

type installationHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *installationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	if roundTripper.panicCall {
		panic("github-provider-secret")
	}
	roundTripper.requests = append(roundTripper.requests, request.Clone(request.Context()))
	if len(roundTripper.responses) == 0 {
		return nil, errors.New("github-provider-secret")
	}
	response := roundTripper.responses[0]
	roundTripper.responses = roundTripper.responses[1:]
	return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
}

func TestInstallationCollectionAPIPaginatesCanonicalRepositoriesWithoutSecrets(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{
		{status: http.StatusOK, body: `{"id":9001,"account":{"id":501,"login":"acme","type":"Organization"}}`},
		{status: http.StatusOK, body: `{"total_count":3,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":false,"default_branch":"main","owner":{"login":"acme"}},{"id":102,"name":"beta","full_name":"acme/beta","private":false,"archived":true,"default_branch":"trunk","owner":{"login":"acme"}}]}`},
		{status: http.StatusOK, body: `{"total_count":3,"repositories":[{"id":103,"name":"gamma","full_name":"acme/gamma","private":false,"archived":false,"default_branch":"main","owner":{"login":"acme"}}]}`},
	}}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatalf("newInstallationCollectionAPI() error = %v", err)
	}
	credential := []byte("ghs_installation_secret_value")
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 3, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(first) error = %v", err)
	}
	if first.Complete || first.Cursor != nextGitHubPageCursor(request.Subject, 2, 1, 0) || len(first.Entities) != 1 || len(first.Relationships) != 0 || !bytes.Contains(first.Entities[0], []byte(`"owner":"acme"`)) || bytes.Contains(first.Raw, credential) || !bytes.Equal(first.Raw, mustGitHubCollectionPage(t, first).Raw) {
		t.Fatalf("first page = %#v / %s", first, first.Raw)
	}
	request.Cursor = first.Cursor
	request.Page = 2
	request.RemainingItems = 2
	second, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(second) error = %v", err)
	}
	if second.Complete || second.Cursor != nextGitHubPageCursor(request.Subject, 3, 2, 2) || len(second.Entities) != 2 || len(second.Relationships) != 2 || bytes.Contains(second.Raw, credential) || !bytes.Equal(second.Raw, mustGitHubCollectionPage(t, second).Raw) {
		t.Fatalf("second page = %#v / %s", second, second.Raw)
	}
	request.Cursor = second.Cursor
	request.Page = 3
	request.RemainingItems = 1
	third, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || !third.Complete || !strings.HasPrefix(third.Cursor.Value, "github:complete:") || len(third.Entities) != 1 || len(third.Relationships) != 1 {
		t.Fatalf("third page = %#v / %v", third, err)
	}
	if len(roundTripper.requests) != 3 {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	for index, providerRequest := range roundTripper.requests {
		wantURL := []string{"https://api.github.com/installation", "https://api.github.com/installation/repositories?page=1&per_page=2", "https://api.github.com/installation/repositories?page=2&per_page=2"}[index]
		if providerRequest.Method != http.MethodGet || providerRequest.URL.String() != wantURL || providerRequest.Header.Get("Authorization") != "Bearer "+string(credential) || providerRequest.Header.Get("Accept") != "application/vnd.github+json" || providerRequest.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatalf("request %d = %#v", index, providerRequest)
		}
	}
}

func TestInstallationCollectionAPIRejectsRedirectMalformedAndOversizedResponses(t *testing.T) {
	t.Parallel()
	const secret = "ghs_installation_secret_value"
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 5, RemainingBytes: 4096}
	for name, response := range map[string]installationHTTPResponse{
		"redirect":        {status: http.StatusFound, header: http.Header{"Location": []string{"https://evil.example/steal"}}, body: `{}`},
		"malformed":       {status: http.StatusOK, body: `{"id":9001,"account":{}}`},
		"oversized":       {status: http.StatusOK, body: strings.Repeat("x", 4097)},
		"credential echo": {status: http.StatusOK, body: `{"id":9001,"account":{"id":501,"login":"ghs_installation_secret_value","type":"Organization"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{response}}
			api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
			_, err := api.FetchCollectionPage(context.Background(), []byte(secret), request)
			if err == nil || strings.Contains(err.Error(), secret) || len(roundTripper.requests) != 1 {
				t.Fatalf("FetchCollectionPage() error/calls = %q / %d", err, len(roundTripper.requests))
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	roundTripper := &installationRoundTripper{}
	api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
	if _, err := api.FetchCollectionPage(cancelled, []byte(secret), request); !githubFailureHasCode(err, collection.FailureCancelled) || len(roundTripper.requests) != 0 {
		t.Fatalf("cancelled error/calls = %v / %d", err, len(roundTripper.requests))
	}
}

func TestInstallationCollectionAPIVerifiesSubjectBeforeRepositoriesAndRejectsCursorTransplant(t *testing.T) {
	t.Parallel()
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 2, RemainingBytes: 4096}
	mismatch := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: `{"id":9002,"account":{"id":501,"login":"acme","type":"Organization"}}`}}}
	api, _ := newInstallationCollectionAPI(mismatch, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureDenied) || len(mismatch.requests) != 1 || mismatch.requests[0].URL.Path != "/installation" {
		t.Fatalf("mismatch error/calls = %v / %d", err, len(mismatch.requests))
	}
	request.Cursor = nextGitHubPageCursor(collection.SubjectBinding{Kind: "github_installation", ID: "9002"}, 2, 1, 0)
	request.Page = 2
	zero := &installationRoundTripper{}
	api, _ = newInstallationCollectionAPI(zero, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !errors.Is(err, ErrInvalid) || len(zero.requests) != 0 {
		t.Fatalf("transplant error/calls = %v / %d", err, len(zero.requests))
	}
}

func TestInstallationCollectionAPIClassifiesRateLimit(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"4"}}, body: `{}`}}}
	api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 2, RemainingBytes: 4096}
	if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureRateLimited) {
		t.Fatalf("rate limit error = %v", err)
	}
}

func TestInstallationCollectionAPIReadinessUsesFixedEndpointOnce(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: `{"verifiable_password_authentication":true}`}}}
	api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("CheckCollectionReadiness() error = %v", err)
	}
	if len(roundTripper.requests) != 1 || roundTripper.requests[0].URL.String() != "https://api.github.com/meta" || roundTripper.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("readiness requests = %#v", roundTripper.requests)
	}
	malformed := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: `{}`}}}
	api, _ = newInstallationCollectionAPI(malformed, time.Second)
	if err := api.CheckCollectionReadiness(context.Background()); !errors.Is(err, ErrProvider) || len(malformed.requests) != 1 {
		t.Fatalf("malformed readiness error/calls = %v / %d", err, len(malformed.requests))
	}
}

func mustGitHubCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewCollectionPage() error = %v", err)
	}
	return canonical
}

func githubFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}
