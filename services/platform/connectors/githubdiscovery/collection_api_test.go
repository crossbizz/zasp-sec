package githubdiscovery

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
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
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
		{status: http.StatusOK, body: `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`},
		{status: http.StatusOK, body: `{"total_count":1,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":false,"default_branch":"main","permissions":{"admin":false,"maintain":false,"pull":true,"push":false,"triage":false},"owner":{"login":"acme"}}]}`},
		{status: http.StatusOK, body: `{"total_count":0,"workflows":[]}`},
		{status: http.StatusOK, body: `{"total_count":0,"environments":[]}`},
	}}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatalf("newInstallationCollectionAPI() error = %v", err)
	}
	credential := []byte("ghs_installation_secret_value")
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 16, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(first) error = %v", err)
	}
	if first.Complete || len(first.Entities) != 6 || len(first.Relationships) != 4 || !bytes.Contains(first.Raw, []byte(`"owner":"acme"`)) || bytes.Contains(first.Raw, credential) || !bytes.Equal(first.Raw, mustGitHubCollectionPage(t, first).Raw) {
		t.Fatalf("first page = %#v / %s", first, first.Raw)
	}
	request.Cursor = first.Cursor
	request.Page = 2
	request.RemainingItems = 10
	second, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(second) error = %v", err)
	}
	if second.Complete || len(second.Entities) != 6 || len(second.Relationships) != 7 || bytes.Contains(second.Raw, credential) || !bytes.Equal(second.Raw, mustGitHubCollectionPage(t, second).Raw) {
		t.Fatalf("second page = %#v / %s", second, second.Raw)
	}
	request.Cursor = second.Cursor
	request.Page = 3
	request.RemainingItems = 4
	third, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || third.Complete || len(third.Entities) != 0 || len(third.Relationships) != 0 {
		t.Fatalf("third page = %#v / %v", third, err)
	}
	request.Cursor, request.Page = third.Cursor, 4
	fourth, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || !fourth.Complete || !strings.HasPrefix(fourth.Cursor.Value, "github:complete:") || len(fourth.Entities) != 0 || len(fourth.Relationships) != 0 {
		t.Fatalf("fourth page = %#v / %v", fourth, err)
	}
	if len(roundTripper.requests) != 4 {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	for index, providerRequest := range roundTripper.requests {
		wantURL := []string{"https://api.github.com/installation", "https://api.github.com/installation/repositories?page=1&per_page=1", "https://api.github.com/repos/acme/alpha/actions/workflows?page=1&per_page=1", "https://api.github.com/repos/acme/alpha/environments?page=1&per_page=1"}[index]
		if providerRequest.Method != http.MethodGet || providerRequest.URL.String() != wantURL || providerRequest.Header.Get("Authorization") != "Bearer "+string(credential) || providerRequest.Header.Get("Accept") != "application/vnd.github+json" || providerRequest.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatalf("request %d = %#v", index, providerRequest)
		}
	}
}

func TestInstallationCollectionAPIRequiresAppPermissionsAndWorkflowPhasesBeforeComplete(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{
		{status: http.StatusOK, body: `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`},
		{status: http.StatusOK, body: `{"total_count":1,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":false,"default_branch":"main","permissions":{"admin":false,"maintain":false,"pull":true,"push":false,"triage":false},"owner":{"login":"acme"}}]}`},
		{status: http.StatusOK, body: `{"total_count":2,"workflows":[{"id":801,"name":"Build and deploy","path":".github/workflows/build-and-deploy.yml","state":"active"}]}`},
		{status: http.StatusOK, body: `{"total_count":2,"workflows":[{"id":802,"name":"Security scan","path":".github/workflows/security-scan.yaml","state":"disabled_manually"}]}`},
		{status: http.StatusOK, body: `{"total_count":2,"environments":[{"id":901,"name":"staging"}]}`},
		{status: http.StatusOK, body: `{"total_count":2,"environments":[{"id":902,"name":"production"}]}`},
	}}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("ghs_installation_secret_value")
	subject := collection.SubjectBinding{Kind: "github_installation", ID: "9001"}
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: subject, Page: 1, RemainingItems: 16, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	installation, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatal(err)
	}
	if installation.Complete || fmt.Sprint(githubInventoryKinds(installation.Entities)) != "[github_app github_installation github_organization github_permission github_permission github_permission]" {
		t.Fatalf("installation page = %#v / %s", installation, installation.Raw)
	}
	request.Cursor, request.Page = installation.Cursor, 2
	repositories, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatal(err)
	}
	if repositories.Complete || fmt.Sprint(githubInventoryKinds(repositories.Entities)) != "[github_permission github_permission github_permission github_permission github_permission github_repository]" {
		t.Fatalf("repository page = %#v / %s", repositories, repositories.Raw)
	}
	request.Cursor, request.Page = repositories.Cursor, 3
	workflows, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatal(err)
	}
	if workflows.Complete || fmt.Sprint(githubInventoryKinds(workflows.Entities)) != "[github_workflow]" || fmt.Sprint(githubInventoryKinds(workflows.Relationships)) != "[contains depends_on uses_identity]" {
		t.Fatalf("workflow page = %#v / %s", workflows, workflows.Raw)
	}
	request.Cursor, request.Page = workflows.Cursor, 4
	secondWorkflow, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || secondWorkflow.Complete || fmt.Sprint(githubInventoryKinds(secondWorkflow.Entities)) != "[github_workflow]" || fmt.Sprint(githubInventoryKinds(secondWorkflow.Relationships)) != "[contains depends_on uses_identity]" {
		t.Fatalf("second workflow page = %#v / %v", secondWorkflow, err)
	}
	request.Cursor, request.Page = secondWorkflow.Cursor, 5
	environments, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatal(err)
	}
	if environments.Complete || fmt.Sprint(githubInventoryKinds(environments.Entities)) != "[github_environment]" || fmt.Sprint(githubInventoryKinds(environments.Relationships)) != "[contains]" {
		t.Fatalf("environment page = %#v / %s", environments, environments.Raw)
	}
	request.Cursor, request.Page = environments.Cursor, 6
	secondEnvironment, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || !secondEnvironment.Complete || fmt.Sprint(githubInventoryKinds(secondEnvironment.Entities)) != "[github_environment]" || fmt.Sprint(githubInventoryKinds(secondEnvironment.Relationships)) != "[contains]" {
		t.Fatalf("second environment page = %#v / %v", secondEnvironment, err)
	}
	wantURLs := []string{
		"https://api.github.com/installation",
		"https://api.github.com/installation/repositories?page=1&per_page=1",
		"https://api.github.com/repos/acme/alpha/actions/workflows?page=1&per_page=1",
		"https://api.github.com/repos/acme/alpha/actions/workflows?page=2&per_page=1",
		"https://api.github.com/repos/acme/alpha/environments?page=1&per_page=1",
		"https://api.github.com/repos/acme/alpha/environments?page=2&per_page=1",
	}
	if len(roundTripper.requests) != len(wantURLs) {
		t.Fatalf("provider calls = %d, want %d", len(roundTripper.requests), len(wantURLs))
	}
	for index, providerRequest := range roundTripper.requests {
		if got := providerRequest.URL.String(); got != wantURLs[index] {
			t.Fatalf("request %d URL = %s, want %s", index, got, wantURLs[index])
		}
	}
}

func TestInstallationCollectionAPIRejectsRedirectMalformedAndOversizedResponses(t *testing.T) {
	t.Parallel()
	const secret = "ghs_installation_secret_value"
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 5, RemainingRelationships: 16, RemainingBytes: 4096}
	for name, response := range map[string]installationHTTPResponse{
		"redirect":        {status: http.StatusFound, header: http.Header{"Location": []string{"https://evil.example/steal"}}, body: `{}`},
		"malformed":       {status: http.StatusOK, body: `{"id":9001,"account":{}}`},
		"oversized":       {status: http.StatusOK, body: strings.Repeat("x", 4097)},
		"credential echo": {status: http.StatusOK, body: `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"ghs_installation_secret_value","type":"Organization"}}`},
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

func TestInstallationCollectionAPIRejectsUserAndPermissionAuthorityDrift(t *testing.T) {
	t.Parallel()
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Page: 1, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
	for name, body := range map[string]string{
		"user installation": `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"alice","type":"User"}}`,
		"missing actions":   `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`,
		"write actions":     `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"write","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`,
		"extra permission":  `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","issues":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: body}}}
			api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
			if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureMalformed) || len(roundTripper.requests) != 1 {
				t.Fatalf("authority error/calls = %v/%d", err, len(roundTripper.requests))
			}
		})
	}
}

func TestInstallationCollectionAPIReportsExactPageCapacityBeforePersistence(t *testing.T) {
	t.Parallel()
	valid := `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`
	for name, mutate := range map[string]func(*CollectionPageRequest){
		"entity capacity":            func(request *CollectionPageRequest) { request.RemainingItems = 5 },
		"relationship capacity":      func(request *CollectionPageRequest) { request.RemainingRelationships = 3 },
		"zero relationship capacity": func(request *CollectionPageRequest) { request.RemainingRelationships = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Page: 1, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
			mutate(&request)
			roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: valid}}}
			api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
			if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !errors.Is(err, providercollection.ErrPageCapacity) || len(roundTripper.requests) != 1 {
				t.Fatalf("capacity error/calls = %v/%d", err, len(roundTripper.requests))
			}
		})
	}
}

func TestInstallationCollectionAPIDoesNotTreatWorkflowNotFoundAsEmpty(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "github_installation", ID: "9001"}
	cursor, ok := nextGitHubCursor(subject, githubPageState{Phase: "workflows", Lineage: 3, ProviderPage: 2, Total: 1, PhasePage: 1, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"})
	if !ok {
		t.Fatal("workflow cursor rejected")
	}
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusNotFound, body: `{}`}}}
	api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: subject, Cursor: cursor, Page: 3, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
	if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureTerminal) || len(roundTripper.requests) != 1 {
		t.Fatalf("not-found error/calls = %v/%d", err, len(roundTripper.requests))
	}
}

func TestInstallationCollectionAPIRejectsFalseCompleteWorkflowAndEnvironmentPages(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "github_installation", ID: "9001"}
	states := map[string]githubPageState{
		"empty workflow first":     {Phase: "workflows", Lineage: 3, ProviderPage: 2, Total: 1, PhasePage: 1, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"},
		"empty workflow final":     {Phase: "workflows", Lineage: 4, ProviderPage: 2, Total: 1, PhasePage: 2, PhaseTotal: 2, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"},
		"empty environment first":  {Phase: "environments", Lineage: 5, ProviderPage: 2, Total: 1, PhasePage: 1, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"},
		"empty environment middle": {Phase: "environments", Lineage: 6, ProviderPage: 2, Total: 1, PhasePage: 2, PhaseTotal: 3, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"},
	}
	for name, state := range states {
		t.Run(name, func(t *testing.T) {
			cursor, ok := nextGitHubCursor(subject, state)
			if !ok {
				t.Fatal("cursor rejected")
			}
			field := "workflows"
			if state.Phase == "environments" {
				field = "environments"
			}
			total := state.PhaseTotal
			if total == 0 {
				total = 2
			}
			roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: fmt.Sprintf(`{"total_count":%d,"%s":[]}`, total, field)}}}
			api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
			request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: subject, Cursor: cursor, Page: state.Lineage, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
			if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureMalformed) || len(roundTripper.requests) != 1 {
				t.Fatalf("false complete error/calls=%v/%d", err, len(roundTripper.requests))
			}
		})
	}
}

func TestInstallationCollectionAPIAcceptsOfficialWorkflowStatesAndSafeUTF8Names(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "github_installation", ID: "9001"}
	state := githubPageState{Phase: "workflows", Lineage: 3, ProviderPage: 2, Total: 1, PhasePage: 1, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"}
	for index, test := range []struct{ path, state string }{
		{path: ".github/workflows/发布 安全检查.yaml", state: "active"},
		{path: ".github/workflows/" + strings.Repeat("é", 480) + ".yml", state: "deleted"},
		{path: ".github/workflows/fork.yml", state: "disabled_fork"},
		{path: ".github/workflows/idle.yaml", state: "disabled_inactivity"},
		{path: ".github/workflows/manual.yml", state: "disabled_manually"},
	} {
		entities, relationships, ok := normalizeRepositoryWorkflows(subject, state, []repositoryWorkflow{{ID: int64(index + 1), Name: "Workflow", Path: test.path, State: test.state}})
		if !ok || len(entities) != 1 || len(relationships) != 3 {
			t.Fatalf("official workflow rejected: %#v %#v", test, entities)
		}
	}
	for _, path := range []string{".github/workflows/nested/build.yml", ".github/workflows/bad.txt", ".github/workflows/ bad.yml"} {
		if _, _, ok := normalizeRepositoryWorkflows(subject, state, []repositoryWorkflow{{ID: 1, Name: "Workflow", Path: path, State: "active"}}); ok {
			t.Fatalf("hostile workflow path accepted: %q", path)
		}
	}
}

func TestInstallationCollectionAPIVerifiesSubjectBeforeRepositoriesAndRejectsCursorTransplant(t *testing.T) {
	t.Parallel()
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 2, RemainingRelationships: 16, RemainingBytes: 4096}
	mismatch := &installationRoundTripper{responses: []installationHTTPResponse{{status: http.StatusOK, body: `{"id":9002,"account":{"id":501,"login":"acme","type":"Organization"}}`}}}
	api, _ := newInstallationCollectionAPI(mismatch, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte("ghs_installation_secret_value"), request); !githubFailureHasCode(err, collection.FailureDenied) || len(mismatch.requests) != 1 || mismatch.requests[0].URL.Path != "/installation" {
		t.Fatalf("mismatch error/calls = %v / %d", err, len(mismatch.requests))
	}
	request.Cursor, _ = nextGitHubCursor(collection.SubjectBinding{Kind: "github_installation", ID: "9002"}, githubPageState{Phase: "repositories", Lineage: 2, ProviderPage: 1, OwnerID: 501, Owner: "acme", AppID: 77})
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
	request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: collection.SubjectBinding{Kind: "github_installation", ID: "9001"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 2, RemainingRelationships: 16, RemainingBytes: 4096}
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

func githubInventoryKinds(values []json.RawMessage) []string {
	kinds := make([]string, 0, len(values))
	for _, raw := range values {
		var value struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &value) == nil {
			kinds = append(kinds, value.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}
