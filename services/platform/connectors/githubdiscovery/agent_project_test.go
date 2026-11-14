package githubdiscovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	agentProjectCredential = "ghs_installation_secret_value"
	agentProjectTreeURL    = "https://api.github.com/repos/acme/alpha/git/trees/main?recursive=1"
	agentProjectPosture    = `{"cicd_write":false,"credential_active":false,"credential_fingerprint":"","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":false,"production_agent":false,"production_credential":false,"production_secret_reach":false,"production_write":false,"runtime_control":false,"runtime_policy_supported":false,"sensitive_data_reach":false,"shell_execution":false,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false}`
)

var agentProjectSubject = collection.SubjectBinding{Kind: "github_installation", ID: "9001"}

func agentProjectState() githubPageState {
	return githubPageState{Phase: "agentproject", Lineage: 3, ProviderPage: 2, Total: 1, PhasePage: 1, OwnerID: 501, Owner: "acme", AppID: 77, RepositoryID: 101, Repository: "alpha", DefaultBranch: "main"}
}

func agentProjectRequest(t *testing.T, state githubPageState) CollectionPageRequest {
	t.Helper()
	cursor, ok := nextGitHubCursor(agentProjectSubject, state)
	if !ok {
		t.Fatal("agent project cursor rejected")
	}
	return CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: agentProjectSubject, Cursor: cursor, Page: state.Lineage, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
}

func agentProjectContentURL(path string) string {
	return "https://api.github.com/repos/acme/alpha/contents/" + path + "?ref=main"
}

// agentProjectContent is a contents response the way GitHub sends it: base64
// broken into 60-character lines.
func agentProjectContent(content string) installationHTTPResponse {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	var wrapped strings.Builder
	for len(encoded) > 60 {
		wrapped.WriteString(encoded[:60] + "\n")
		encoded = encoded[60:]
	}
	wrapped.WriteString(encoded + "\n")
	body, _ := json.Marshal(map[string]any{"type": "file", "encoding": "base64", "size": len(content), "name": "file", "path": "file", "sha": "0123456789abcdef", "content": wrapped.String()})
	return installationHTTPResponse{status: http.StatusOK, body: string(body)}
}

func agentProjectTree(truncated bool, entries ...string) installationHTTPResponse {
	return installationHTTPResponse{status: http.StatusOK, body: fmt.Sprintf(`{"sha":"4b825dc642cb6eb9a060e54bf8d69288fbee4904","url":"https://api.github.com/repos/acme/alpha/git/trees/4b825dc","tree":[%s],"truncated":%t}`, strings.Join(entries, ","), truncated)}
}

func agentProjectBlob(path string, size int) string {
	return fmt.Sprintf(`{"path":%q,"mode":"100644","type":"blob","sha":"0123456789abcdef","size":%d,"url":"https://api.github.com/repos/acme/alpha/git/blobs/0123456789abcdef"}`, path, size)
}

func agentProjectDirectory(path string) string {
	return fmt.Sprintf(`{"path":%q,"mode":"040000","type":"tree","sha":"0123456789abcdef"}`, path)
}

func fetchAgentProjectPage(t *testing.T, responses ...installationHTTPResponse) (CollectionPage, error, []string) {
	t.Helper()
	roundTripper := &installationRoundTripper{responses: responses}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	page, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), agentProjectRequest(t, agentProjectState()))
	urls := make([]string, 0, len(roundTripper.requests))
	for _, providerRequest := range roundTripper.requests {
		if providerRequest.Method != http.MethodGet || providerRequest.Header.Get("Authorization") != "Bearer "+agentProjectCredential || providerRequest.Header.Get("Accept") != "application/vnd.github+json" || providerRequest.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Fatalf("request = %#v", providerRequest)
		}
		urls = append(urls, providerRequest.URL.String())
	}
	return page, err, urls
}

// requireAgentProject checks the whole page: exactly the project entity with
// exactly these signals, its edge from the repository, and the workflows
// cursor of the same repository.
func requireAgentProject(t *testing.T, page CollectionPage, signals string) {
	t.Helper()
	if page.Complete || !bytes.Equal(page.Raw, mustGitHubCollectionPage(t, page).Raw) || len(page.Entities) != 1 || len(page.Relationships) != 1 {
		t.Fatalf("page = %s", page.Raw)
	}
	projectID := deterministicGitHubInventoryID(agentProjectSubject, "github_agent_project", "101")
	wantEntity := `{"id":"` + projectID + `","kind":"github_agent_project","source_native_id":"github:repository:101:agent_project","display_name":"acme/alpha","stable_fields":{"installation_id":9001,"name":"acme/alpha","owner":"acme","repository":"alpha"},"attributes":{"discovery":{"method":"inferred","platform":"github_repository","signals":` + signals + `},"posture":` + agentProjectPosture + `}}`
	if string(page.Entities[0]) != wantEntity {
		t.Fatalf("entity = %s\nwant     %s", page.Entities[0], wantEntity)
	}
	wantRelationship := `{"id":"` + deterministicGitHubInventoryID(agentProjectSubject, "contains", "101:agent_project") + `","kind":"contains","source_native_id":"github:repository:101:agent_project","from_entity_id":"` + deterministicGitHubInventoryID(agentProjectSubject, "github_repository", "101") + `","to_entity_id":"` + projectID + `","attributes":{"type":"repository_agent_project"}}`
	if string(page.Relationships[0]) != wantRelationship {
		t.Fatalf("relationship = %s\nwant         %s", page.Relationships[0], wantRelationship)
	}
	requireWorkflowsCursor(t, page)
}

func requireWorkflowsCursor(t *testing.T, page CollectionPage) {
	t.Helper()
	state := agentProjectState()
	state.Phase, state.Lineage = "workflows", state.Lineage+1
	want, _ := nextGitHubCursor(agentProjectSubject, state)
	if page.Cursor != want {
		t.Fatalf("cursor = %s, want %s", page.Cursor.Value, want.Value)
	}
}

func requireNoAgentProject(t *testing.T, page CollectionPage, err error) {
	t.Helper()
	if err != nil || page.Complete || len(page.Entities) != 0 || len(page.Relationships) != 0 {
		t.Fatalf("page = %s / %v", page.Raw, err)
	}
	requireWorkflowsCursor(t, page)
}

func TestAgentProjectFromMCPManifestNeedsOnlyTheTree(t *testing.T) {
	t.Parallel()
	page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("README.md", 10), agentProjectDirectory("tools"), agentProjectBlob("tools/.mcp.json", 80)))
	if err != nil {
		t.Fatal(err)
	}
	requireAgentProject(t, page, `["manifest:mcp_config"]`)
	if fmt.Sprint(urls) != fmt.Sprint([]string{agentProjectTreeURL}) {
		t.Fatalf("provider calls = %v", urls)
	}
}

func TestAgentProjectFromRequirementsRecordsOnlyCatalogSignals(t *testing.T) {
	t.Parallel()
	requirements := "# SECRET_SENTINEL internal index token\n-r base-SECRET_SENTINEL.txt\n--index-url https://SECRET_SENTINEL@pypi.example/simple\nlanggraph>=0.2\nrequests  # SECRET_SENTINEL\n"
	page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", len(requirements))), agentProjectContent(requirements))
	if err != nil {
		t.Fatal(err)
	}
	requireAgentProject(t, page, `["package:langgraph"]`)
	if bytes.Contains(page.Raw, []byte("SECRET_SENTINEL")) || bytes.Contains(page.Raw, []byte("requests")) || bytes.Contains(page.Raw, []byte("0.2")) || strings.Contains(page.Cursor.Value, "SECRET_SENTINEL") {
		t.Fatalf("file content left the collector: %s", page.Raw)
	}
	if fmt.Sprint(urls) != fmt.Sprint([]string{agentProjectTreeURL, agentProjectContentURL("requirements.txt")}) {
		t.Fatalf("provider calls = %v", urls)
	}
}

func TestAgentProjectNeedsMoreThanOneWeakClass(t *testing.T) {
	t.Parallel()
	manifest := `{"name":"web","dependencies":{"openai":"^4.0.0","react":"^18.0.0"},"devDependencies":{"typescript":"^5.0.0"}}`
	page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("package.json", len(manifest))), agentProjectContent(manifest))
	requireNoAgentProject(t, page, err)
	if len(urls) != 2 || urls[1] != agentProjectContentURL("package.json") {
		t.Fatalf("provider calls = %v", urls)
	}
	// The same file with an agent framework is a project.
	manifest = `{"dependencies":{"openai":"^4.0.0"},"devDependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}`
	page, err, _ = fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("package.json", len(manifest))), agentProjectContent(manifest))
	if err != nil {
		t.Fatal(err)
	}
	requireAgentProject(t, page, `["package:mcp","package:openai"]`)
}

func TestArchivedRepositorySkipsAgentProjectPhase(t *testing.T) {
	t.Parallel()
	for archived, wantPhase := range map[bool]string{true: "github:workflows:3:", false: "github:agentproject:3:"} {
		roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{
			{status: http.StatusOK, body: fmt.Sprintf(`{"total_count":1,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":%t,"default_branch":"main","permissions":{"admin":false,"maintain":false,"pull":true,"push":false,"triage":false},"owner":{"login":"acme"}}]}`, archived)},
			{status: http.StatusOK, body: `{"total_count":0,"workflows":[]}`},
		}}
		api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
		cursor, _ := nextGitHubCursor(agentProjectSubject, githubPageState{Phase: "repositories", Lineage: 2, ProviderPage: 1, OwnerID: 501, Owner: "acme", AppID: 77})
		request := CollectionPageRequest{Provider: collection.ProviderGitHub, Subject: agentProjectSubject, Cursor: cursor, Page: 2, RemainingItems: 16, RemainingRelationships: 16, RemainingBytes: 1 << 20}
		page, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request)
		if err != nil || !strings.HasPrefix(page.Cursor.Value, wantPhase) {
			t.Fatalf("archived=%t cursor = %s / %v", archived, page.Cursor.Value, err)
		}
		if !archived {
			continue
		}
		request.Cursor, request.Page = page.Cursor, 3
		if _, err = api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request); err != nil {
			t.Fatal(err)
		}
		if len(roundTripper.requests) != 2 || roundTripper.requests[1].URL.Path != "/repos/acme/alpha/actions/workflows" {
			t.Fatalf("archived repository calls = %d, last %s", len(roundTripper.requests), roundTripper.requests[len(roundTripper.requests)-1].URL)
		}
	}
}

func TestAgentProjectTreatsEmptyRepositoryAsNoTree(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]installationHTTPResponse{
		"empty repository": {status: http.StatusConflict, body: `{"message":"Git Repository is empty.","status":"409"}`},
		"missing branch":   {status: http.StatusNotFound, body: `{"message":"Not Found","status":"404"}`},
	} {
		t.Run(name, func(t *testing.T) {
			page, err, urls := fetchAgentProjectPage(t, response)
			requireNoAgentProject(t, page, err)
			if len(urls) != 1 {
				t.Fatalf("provider calls = %v", urls)
			}
		})
	}
}

func TestAgentProjectUsesWhatATruncatedTreeReturns(t *testing.T) {
	t.Parallel()
	page, err, urls := fetchAgentProjectPage(t, agentProjectTree(true, agentProjectBlob("services/agent/langgraph.json", 40)))
	if err != nil || len(urls) != 1 {
		t.Fatalf("error/calls = %v / %v", err, urls)
	}
	requireAgentProject(t, page, `["manifest:langgraph"]`)
}

func TestAgentProjectBoundsManifestReads(t *testing.T) {
	t.Parallel()
	langgraph := "langgraph\n"
	t.Run("oversize and deep manifests are not fetched", func(t *testing.T) {
		page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false,
			agentProjectBlob("requirements.txt", 256*1024+1), agentProjectBlob("go.mod", 0), agentProjectBlob("services/api/requirements.txt", len(langgraph)), agentProjectBlob("docs/requirements.txt.md", 10)))
		requireNoAgentProject(t, page, err)
		if len(urls) != 1 {
			t.Fatalf("provider calls = %v", urls)
		}
	})
	t.Run("largest allowed manifest is read", func(t *testing.T) {
		content := langgraph + strings.Repeat("#", 256*1024-len(langgraph))
		page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", len(content))), agentProjectContent(content))
		if err != nil || len(urls) != 2 {
			t.Fatalf("error/calls = %v / %v", err, urls)
		}
		requireAgentProject(t, page, `["package:langgraph"]`)
	})
	t.Run("manifest that grew past the limit after the tree was read is skipped", func(t *testing.T) {
		page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", 10)), agentProjectContent(langgraph+strings.Repeat("#", 512*1024)))
		requireNoAgentProject(t, page, err)
		if len(urls) != 2 {
			t.Fatalf("provider calls = %v", urls)
		}
	})
	t.Run("manifest deleted after the tree was read is skipped", func(t *testing.T) {
		page, err, _ := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", 10)), installationHTTPResponse{status: http.StatusNotFound, body: `{}`})
		requireNoAgentProject(t, page, err)
	})
	t.Run("at most six manifests, root first", func(t *testing.T) {
		harmless := agentProjectContent("requests\n")
		page, err, urls := fetchAgentProjectPage(t, agentProjectTree(false,
			agentProjectBlob("z/requirements.txt", 9), agentProjectBlob("y/package.json", 9), agentProjectBlob("b/go.mod", 9), agentProjectBlob("a/pyproject.toml", 9), agentProjectBlob("a/package.json", 9),
			agentProjectBlob("requirements.txt", 9), agentProjectBlob("package.json", 9), agentProjectBlob("go.mod", 9)),
			harmless, harmless, harmless, harmless, harmless, harmless)
		requireNoAgentProject(t, page, err)
		want := []string{agentProjectTreeURL, agentProjectContentURL("go.mod"), agentProjectContentURL("package.json"), agentProjectContentURL("requirements.txt"), agentProjectContentURL("a/package.json"), agentProjectContentURL("a/pyproject.toml"), agentProjectContentURL("b/go.mod")}
		if fmt.Sprint(urls) != fmt.Sprint(want) {
			t.Fatalf("provider calls = %v\nwant %v", urls, want)
		}
	})
}

func TestAgentProjectEscapesBranchAndManifestPath(t *testing.T) {
	t.Parallel()
	state := agentProjectState()
	state.DefaultBranch = "release/1.0 beta"
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{agentProjectTree(false, agentProjectBlob("my app/go.mod", 9)), agentProjectContent("module example.com/app\n")}}
	api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), agentProjectRequest(t, state)); err != nil {
		t.Fatal(err)
	}
	if len(roundTripper.requests) != 2 || roundTripper.requests[0].URL.String() != "https://api.github.com/repos/acme/alpha/git/trees/release/1.0%20beta?recursive=1" || roundTripper.requests[1].URL.String() != "https://api.github.com/repos/acme/alpha/contents/my%20app/go.mod?ref=release%2F1.0+beta" {
		t.Fatalf("requests = %v / %v", roundTripper.requests[0].URL, roundTripper.requests[len(roundTripper.requests)-1].URL)
	}
}

// A repository the installation cannot read fails the page the way the
// workflows phase fails it, wherever in the page the refusal arrives.
func TestAgentProjectMapsProviderFailuresLikeWorkflows(t *testing.T) {
	t.Parallel()
	failureCode := func(err error) collection.FailureCode {
		var failure *collection.Failure
		if !errors.As(err, &failure) {
			t.Fatalf("not a collection failure: %v", err)
		}
		return failure.Code()
	}
	tree := agentProjectTree(false, agentProjectBlob("requirements.txt", 10))
	for name, response := range map[string]installationHTTPResponse{
		"forbidden":    {status: http.StatusForbidden, body: `{"message":"Resource not accessible by integration"}`},
		"unauthorized": {status: http.StatusUnauthorized, body: `{}`},
		"rate limited": {status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"4"}}, body: `{}`},
		"unavailable":  {status: http.StatusServiceUnavailable, body: `{}`},
		"redirect":     {status: http.StatusFound, header: http.Header{"Location": []string{"https://evil.example/steal"}}, body: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			workflowState := agentProjectState()
			workflowState.Phase = "workflows"
			workflows := &installationRoundTripper{responses: []installationHTTPResponse{response}}
			api, _ := newInstallationCollectionAPI(workflows, time.Second)
			_, workflowErr := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), agentProjectRequest(t, workflowState))
			want := failureCode(workflowErr)

			_, treeErr, treeCalls := fetchAgentProjectPage(t, response)
			if got := failureCode(treeErr); got != want || len(treeCalls) != 1 || strings.Contains(treeErr.Error(), agentProjectCredential) {
				t.Fatalf("tree failure = %v, workflows failure = %v, calls = %v", got, want, treeCalls)
			}
			_, contentErr, contentCalls := fetchAgentProjectPage(t, tree, response)
			if got := failureCode(contentErr); got != want || len(contentCalls) != 2 {
				t.Fatalf("content failure = %v, workflows failure = %v, calls = %v", got, want, contentCalls)
			}
		})
	}
	if _, err, _ := fetchAgentProjectPage(t, installationHTTPResponse{status: http.StatusForbidden, body: `{}`}); failureCode(err) != collection.FailureDenied {
		t.Fatalf("forbidden tree = %v", err)
	}
	if _, err, calls := fetchAgentProjectPage(t); err == nil || strings.Contains(err.Error(), "github-provider-secret") || len(calls) != 1 {
		t.Fatalf("transport failure = %v / %v", err, calls)
	}
}

func TestAgentProjectRejectsMalformedProviderData(t *testing.T) {
	t.Parallel()
	for name, responses := range map[string][]installationHTTPResponse{
		"tree is not a tree":      {{status: http.StatusOK, body: `{"total_count":0,"workflows":[]}`}},
		"tree is not json":        {{status: http.StatusOK, body: `<html>`}},
		"tree has trailing data":  {{status: http.StatusOK, body: `{"tree":[]}{"tree":[]}`}},
		"content is not json":     {agentProjectTree(false, agentProjectBlob("go.mod", 9)), {status: http.StatusOK, body: `module x`}},
		"tree over response size": {{status: http.StatusOK, body: `{"tree":[],"pad":"` + strings.Repeat("x", 8*1024*1024) + `"}`}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err, _ := fetchAgentProjectPage(t, responses...); !githubFailureHasCode(err, collection.FailureMalformed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	// Content that is not a base64 file is skipped, not trusted and not fatal.
	for name, body := range map[string]string{
		"directory listing": `[{"type":"file","name":"go.mod"}]`,
		"symlink":           `{"type":"symlink","encoding":"base64","content":"bGFuZ2dyYXBoCg=="}`,
		"no encoding":       `{"type":"file","encoding":"none","content":""}`,
		"bad base64":        `{"type":"file","encoding":"base64","content":"%%%"}`,
	} {
		t.Run(name, func(t *testing.T) {
			page, err, _ := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", 9)), installationHTTPResponse{status: http.StatusOK, body: body})
			if name == "directory listing" {
				if !githubFailureHasCode(err, collection.FailureMalformed) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			requireNoAgentProject(t, page, err)
		})
	}
}

func TestAgentProjectResumesFromItsCursor(t *testing.T) {
	t.Parallel()
	requirements := "langgraph>=0.2\n"
	pyproject := "[project]\ndependencies = [\"mcp[cli]>=1.2\"]\n"
	tree := agentProjectTree(false, agentProjectBlob("requirements.txt", len(requirements)), agentProjectBlob("pyproject.toml", len(pyproject)), agentProjectBlob(".mcp.json", 20))
	request := agentProjectRequest(t, agentProjectState())

	// First attempt: the second manifest read is refused for now. Nothing is
	// emitted and the cursor does not move.
	interrupted := &installationRoundTripper{responses: []installationHTTPResponse{tree, agentProjectContent(pyproject), {status: http.StatusServiceUnavailable, body: `{}`}}}
	api, _ := newInstallationCollectionAPI(interrupted, time.Second)
	if page, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request); !githubFailureHasCode(err, collection.FailureRetryable) || len(page.Raw) != 0 || len(interrupted.requests) != 3 {
		t.Fatalf("interrupted page = %s / %v / %d calls", page.Raw, err, len(interrupted.requests))
	}
	// Two more attempts in new processes, from the same cursor, agree byte for byte.
	var pages [2]CollectionPage
	for attempt := range pages {
		roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{tree, agentProjectContent(pyproject), agentProjectContent(requirements), {status: http.StatusOK, body: `{"total_count":0,"workflows":[]}`}}}
		api, _ = newInstallationCollectionAPI(roundTripper, time.Second)
		page, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request)
		if err != nil {
			t.Fatal(err)
		}
		requireAgentProject(t, page, `["manifest:mcp_config","package:langgraph","package:mcp"]`)
		pages[attempt] = page
		// The next page is the repository's first workflow page.
		next := request
		next.Cursor, next.Page = page.Cursor, request.Page+1
		workflows, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), next)
		if err != nil || !strings.HasPrefix(workflows.Cursor.Value, "github:environments:5:") || roundTripper.requests[3].URL.String() != "https://api.github.com/repos/acme/alpha/actions/workflows?page=1&per_page=1" {
			t.Fatalf("workflows after agent project = %s / %v", workflows.Cursor.Value, err)
		}
	}
	if !bytes.Equal(pages[0].Raw, pages[1].Raw) {
		t.Fatal("agent project page is not deterministic on retry")
	}
}

func TestAgentProjectRespectsPageBudgetsAndCursorBinding(t *testing.T) {
	t.Parallel()
	tree := agentProjectTree(false, agentProjectBlob(".mcp.json", 20))
	// The project and its edge are counted against the page budgets after
	// they are built, like every other phase.
	limited := agentProjectRequest(t, agentProjectState())
	limited.RemainingRelationships = 0
	limitedAPI, _ := newInstallationCollectionAPI(&installationRoundTripper{responses: []installationHTTPResponse{tree}}, time.Second)
	if _, err := limitedAPI.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), limited); !errors.Is(err, providercollection.ErrPageCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	// A repository with no agent needs no capacity beyond the request minimum.
	request := agentProjectRequest(t, agentProjectState())
	request.RemainingRelationships = 0
	api, _ := newInstallationCollectionAPI(&installationRoundTripper{responses: []installationHTTPResponse{agentProjectTree(false)}}, time.Second)
	if page, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request); err != nil || len(page.Entities) != 0 {
		t.Fatalf("empty tree with no capacity = %v", err)
	}

	for name, mutate := range map[string]func(*githubPageState){
		"second phase page": func(state *githubPageState) { state.PhasePage = 2 },
		"phase total":       func(state *githubPageState) { state.PhaseTotal = 1 },
		"completed total":   func(state *githubPageState) { state.CompletedTotal = 1 },
		"no repository":     func(state *githubPageState) { state.RepositoryID, state.Repository = 0, "" },
		"no branch":         func(state *githubPageState) { state.DefaultBranch = "" },
	} {
		state := agentProjectState()
		mutate(&state)
		if _, ok := nextGitHubCursor(agentProjectSubject, state); ok {
			t.Fatalf("%s: cursor accepted", name)
		}
	}
	// A cursor issued for another installation or another page is refused
	// before any provider call.
	foreign, _ := nextGitHubCursor(collection.SubjectBinding{Kind: "github_installation", ID: "9002"}, agentProjectState())
	for name, mutate := range map[string]func(*CollectionPageRequest){
		"foreign installation": func(request *CollectionPageRequest) { request.Cursor = foreign },
		"wrong page":           func(request *CollectionPageRequest) { request.Page++ },
		"relabelled phase": func(request *CollectionPageRequest) {
			request.Cursor.Value = strings.Replace(request.Cursor.Value, "github:agentproject:", "github:workflows:", 1)
		},
	} {
		request := agentProjectRequest(t, agentProjectState())
		mutate(&request)
		roundTripper := &installationRoundTripper{}
		api, _ := newInstallationCollectionAPI(roundTripper, time.Second)
		if _, err := api.FetchCollectionPage(context.Background(), []byte(agentProjectCredential), request); !errors.Is(err, ErrInvalid) || len(roundTripper.requests) != 0 {
			t.Fatalf("%s: error/calls = %v / %d", name, err, len(roundTripper.requests))
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	roundTripper := &installationRoundTripper{}
	api, _ = newInstallationCollectionAPI(roundTripper, time.Second)
	if _, err := api.FetchCollectionPage(cancelled, []byte(agentProjectCredential), agentProjectRequest(t, agentProjectState())); !githubFailureHasCode(err, collection.FailureCancelled) || len(roundTripper.requests) != 0 {
		t.Fatalf("cancelled error/calls = %v / %d", err, len(roundTripper.requests))
	}
}

func TestAgentProjectRejectsCredentialEcho(t *testing.T) {
	t.Parallel()
	// A hostile manifest cannot place the credential in a page: only catalog
	// tokens are recorded.
	page, err, _ := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("requirements.txt", 60), agentProjectBlob(agentProjectCredential+"/.mcp.json", 5)), agentProjectContent(agentProjectCredential+"\nlanggraph\n"))
	if err != nil || bytes.Contains(page.Raw, []byte(agentProjectCredential)) {
		t.Fatalf("page = %s / %v", page.Raw, err)
	}
	requireAgentProject(t, page, `["manifest:mcp_config","package:langgraph"]`)
}

func TestManifestPackageNames(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		file, content string
		want          []string
	}{
		"requirements":     {"requirements.txt", "# comment\n\n-r other.txt\n-e git+https://example.com/x.git#egg=secretpkg\n--extra-index-url https://example.com\nLangGraph>=0.2,<1 \\\n  --hash=sha256:abc\nmcp[cli]==1.2 ; python_version >= '3.10'\nopenai @ https://example.com/openai.whl\nrequests\t# trailing\n  pydantic_ai~=0.1\r\n", []string{"LangGraph", "mcp", "openai", "pydantic_ai", "requests"}},
		"pyproject pep621": {"pyproject.toml", "[build-system]\nrequires = [\"hatchling\"]\n\n[project]\nname = \"svc\"\ndependencies = [\n  \"langgraph>=0.2\", # ] not the end\n  'mcp[cli] >=1',\n  \"openai ; python_version < '3.13'\",\n]\nkeywords = [\"crewai\"]\n\n[project.optional-dependencies]\ndev = [\"pytest\"]\n", []string{"langgraph", "mcp", "openai"}},
		"pyproject inline": {"pyproject.toml", "[project]\ndependencies = [\"anthropic\", \"httpx\"] # done\nname = \"x\"\n", []string{"anthropic", "httpx"}},
		"pyproject poetry": {"pyproject.toml", "[tool.poetry]\nname = \"svc\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\ncrewai = \"^0.80\"\n\"llama-index\" = { version = \"*\", extras = [\"x\"] }\n\n[tool.poetry.group.dev.dependencies]\npytest = \"*\"\n\n[tool.other]\nlangchain = \"x\"\n", []string{"crewai", "llama-index", "pytest"}},
		"package json":     {"package.json", `{"name":"x","version":"1.0.0","scripts":{"langchain":"x"},"dependencies":{"@langchain/core":"^0.3","ai":"latest"},"devDependencies":{"typescript":"5"},"peerDependencies":{"openai":"*"}}`, []string{"@langchain/core", "ai", "typescript"}},
		"package json bad": {"package.json", `{"dependencies":["openai"]}`, nil},
		"go mod":           {"go.mod", "module example.com/svc // github.com/tmc/langchaingo\n\ngo 1.24\n\nrequire github.com/mark3labs/mcp-go v0.30.0 // indirect\n\nrequire (\n\tgithub.com/openai/openai-go v1.0.0\n\t// github.com/cloudwego/eino v0.1.0\n\tgolang.org/x/sync v0.10.0 // indirect\n)\n\nreplace github.com/a2aproject/a2a-go => ../a2a\n", []string{"github.com/mark3labs/mcp-go", "github.com/openai/openai-go", "golang.org/x/sync"}},
		"unknown file":     {"Pipfile", "langgraph = \"*\"\n", nil},
	} {
		got := manifestPackageNames(test.file, []byte(test.content))
		sort.Strings(got)
		if fmt.Sprint(got) != fmt.Sprint(test.want) {
			t.Errorf("%s: names = %q, want %q", name, got, test.want)
		}
	}
}
