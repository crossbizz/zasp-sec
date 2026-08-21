package githubdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	githubCollectionEndpoint     = "https://api.github.com"
	githubMaximumPageItems       = 100
	githubMaximumResponseBytes   = int64(8 * 1024 * 1024)
	githubMinimumCollectionBytes = int64(4096)
)

var (
	githubCollectionCursorPattern = regexp.MustCompile(`^github:(repositories|workflows|environments):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	githubCompleteCursorPattern   = regexp.MustCompile(`^github:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	githubNamePattern             = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

type githubPageState struct {
	Phase         string `json:"p"`
	Lineage       int    `json:"l"`
	ProviderPage  int    `json:"n,omitempty"`
	Total         int    `json:"t,omitempty"`
	PhasePage     int    `json:"x,omitempty"`
	PhaseTotal    int    `json:"z,omitempty"`
	OwnerID       int64  `json:"o,omitempty"`
	Owner         string `json:"a,omitempty"`
	AppID         int64  `json:"i,omitempty"`
	RepositoryID  int64  `json:"r,omitempty"`
	Repository    string `json:"q,omitempty"`
	DefaultBranch string `json:"b,omitempty"`
}

type InstallationCollectionAPI struct {
	client  *http.Client
	timeout time.Duration
}

var _ CollectionAPI = (*InstallationCollectionAPI)(nil)

func NewInstallationCollectionAPI(timeout time.Duration) (*InstallationCollectionAPI, error) {
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 * 1024,
	}
	return newInstallationCollectionAPI(transport, timeout)
}

func newInstallationCollectionAPI(roundTripper http.RoundTripper, timeout time.Duration) (*InstallationCollectionAPI, error) {
	if roundTripper == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &InstallationCollectionAPI{client: &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: rejectInstallationRedirect}, timeout: timeout}, nil
}

func (api *InstallationCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	state, ok := validInstallationPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.client == nil || ctx == nil || !validInstallationCredential(credential) || !ok {
		return CollectionPage{}, ErrInvalid
	}
	providerURL := githubCollectionEndpoint + "/installation"
	switch state.Phase {
	case "repositories":
		query := url.Values{}
		query.Set("page", strconv.Itoa(state.ProviderPage))
		query.Set("per_page", "1")
		providerURL = githubCollectionEndpoint + "/installation/repositories?" + query.Encode()
	case "workflows":
		query := url.Values{}
		query.Set("page", strconv.Itoa(state.PhasePage))
		query.Set("per_page", "1")
		providerURL = githubCollectionEndpoint + "/repos/" + url.PathEscape(state.Owner) + "/" + url.PathEscape(state.Repository) + "/actions/workflows?" + query.Encode()
	case "environments":
		query := url.Values{}
		query.Set("page", strconv.Itoa(state.PhasePage))
		query.Set("per_page", "1")
		providerURL = githubCollectionEndpoint + "/repos/" + url.PathEscape(state.Owner) + "/" + url.PathEscape(state.Repository) + "/environments?" + query.Encode()
	}
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, providerURL, nil)
	if err != nil {
		return CollectionPage{}, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/vnd.github+json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(credential))
	providerRequest.Header.Set("User-Agent", "zasp-discovery/1")
	providerRequest.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest = providerRequest.WithContext(bounded)
	response, err := doInstallationRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeInstallationResponse(response)
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", time.Now().UTC())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
	}
	body, ok := readInstallationBody(response.Body, githubMaximumResponseBytes)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if state.Phase == "installation" {
		var payload installationResponse
		if !decodeInstallationResponse(body, &payload) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if strconv.FormatInt(payload.ID, 10) != request.Subject.ID {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureDenied)
		}
		if !validGitHubInstallation(payload) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		entities, relationships, normalizeOK := normalizeVerifiedInstallation(request.Subject, payload)
		if !normalizeOK {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		next, cursorOK := nextGitHubCursor(request.Subject, githubPageState{Phase: "repositories", Lineage: state.Lineage + 1, ProviderPage: 1, OwnerID: payload.Account.ID, Owner: payload.Account.Login, AppID: payload.AppID})
		page, pageErr := NewCollectionPage(request.Subject, next, false, entities, relationships)
		if !cursorOK || pageErr != nil || bytes.Contains(page.Raw, credential) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if !githubPageFits(request, page) {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	if state.Phase == "workflows" {
		var payload repositoryWorkflowsResponse
		if !decodeInstallationResponse(body, &payload) || !validGitHubPhasePage(payload.TotalCount, state.PhasePage, state.PhaseTotal, len(payload.Workflows)) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		entities, relationships, normalized := normalizeRepositoryWorkflows(request.Subject, state, payload.Workflows)
		if !normalized {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		nextState := state
		nextState.Lineage++
		nextState.PhaseTotal = payload.TotalCount
		nextState.PhasePage++
		if state.PhasePage >= payload.TotalCount {
			nextState.Phase = "environments"
			nextState.PhasePage = 1
			nextState.PhaseTotal = 0
		}
		next, cursorOK := nextGitHubCursor(request.Subject, nextState)
		page, pageErr := NewCollectionPage(request.Subject, next, false, entities, relationships)
		if !cursorOK || pageErr != nil || bytes.Contains(page.Raw, credential) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if !githubPageFits(request, page) {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	if state.Phase == "environments" {
		var payload repositoryEnvironmentsResponse
		if !decodeInstallationResponse(body, &payload) || !validGitHubPhasePage(payload.TotalCount, state.PhasePage, state.PhaseTotal, len(payload.Environments)) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		entities, relationships, normalized := normalizeRepositoryEnvironments(request.Subject, state, payload.Environments)
		if !normalized {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		completeRepository := state.PhasePage >= payload.TotalCount
		complete := completeRepository && state.ProviderPage > state.Total
		next := nextGitHubCompleteCursor(request.Cursor, request.Subject.ID, state.Total)
		if !complete {
			nextState := state
			nextState.Lineage++
			nextState.PhaseTotal = payload.TotalCount
			nextState.PhasePage++
			if completeRepository {
				nextState = githubPageState{Phase: "repositories", Lineage: state.Lineage + 1, ProviderPage: state.ProviderPage, Total: state.Total, OwnerID: state.OwnerID, Owner: state.Owner, AppID: state.AppID}
			}
			var cursorOK bool
			next, cursorOK = nextGitHubCursor(request.Subject, nextState)
			if !cursorOK {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
		}
		page, pageErr := NewCollectionPage(request.Subject, next, complete, entities, relationships)
		if pageErr != nil || bytes.Contains(page.Raw, credential) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if !githubPageFits(request, page) {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	var payload installationRepositoriesResponse
	if !decodeInstallationResponse(body, &payload) || len(payload.Repositories) > 1 || payload.TotalCount < len(payload.Repositories) || payload.TotalCount < 0 || state.ProviderPage > payload.TotalCount && payload.TotalCount != 0 || state.Total != 0 && state.Total != payload.TotalCount {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	entities, relationships, ok := normalizeInstallationRepositories(request.Subject, state, payload.Repositories)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(payload.Repositories) == 0 {
		if payload.TotalCount != 0 {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		next := nextGitHubCompleteCursor(request.Cursor, request.Subject.ID, payload.TotalCount)
		page, pageErr := NewCollectionPage(request.Subject, next, true, entities, relationships)
		if pageErr != nil || bytes.Contains(page.Raw, credential) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if !githubPageFits(request, page) {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	repository := payload.Repositories[0]
	next, cursorOK := nextGitHubCursor(request.Subject, githubPageState{Phase: "workflows", Lineage: state.Lineage + 1, ProviderPage: state.ProviderPage + 1, Total: payload.TotalCount, PhasePage: 1, OwnerID: state.OwnerID, Owner: state.Owner, AppID: state.AppID, RepositoryID: repository.ID, Repository: repository.Name, DefaultBranch: repository.DefaultBranch})
	if !cursorOK {
		next = nextGitHubCompleteCursor(request.Cursor, request.Subject.ID, payload.TotalCount)
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	page, err := NewCollectionPage(request.Subject, next, false, entities, relationships)
	if err != nil || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if !githubPageFits(request, page) {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

func (api *InstallationCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, githubCollectionEndpoint+"/meta", nil)
	if err != nil {
		return ErrProvider
	}
	request.Close = true
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "zasp-discovery/1")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := doInstallationRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeInstallationResponse(response)
		return ErrProvider
	}
	defer response.Body.Close()
	body, ok := readInstallationBody(response.Body, 64*1024)
	var metadata struct {
		VerifiablePasswordAuthentication *bool `json:"verifiable_password_authentication"`
	}
	if response.StatusCode != http.StatusOK || !ok || !decodeInstallationResponse(body, &metadata) || metadata.VerifiablePasswordAuthentication == nil {
		return ErrProvider
	}
	return nil
}

type installationRepositoriesResponse struct {
	TotalCount   int                      `json:"total_count"`
	Repositories []installationRepository `json:"repositories"`
}

type installationResponse struct {
	ID          int64             `json:"id"`
	AppID       int64             `json:"app_id"`
	AppSlug     string            `json:"app_slug"`
	Permissions map[string]string `json:"permissions"`
	Account     struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

func validGitHubInstallation(installation installationResponse) bool {
	if !validGitHubText(installation.Account.Login, 100) || installation.Account.ID < 1 || installation.Account.ID > 1<<53 || installation.AppID < 1 || installation.AppID > 1<<53 || !githubNamePattern.MatchString(installation.AppSlug) || installation.Account.Type != "Organization" || len(installation.Permissions) != 3 {
		return false
	}
	return installation.Permissions["actions"] == "read" && installation.Permissions["contents"] == "read" && installation.Permissions["metadata"] == "read"
}

func normalizeVerifiedInstallation(subject collection.SubjectBinding, installation installationResponse) ([]json.RawMessage, []json.RawMessage, bool) {
	installationEntityID := deterministicGitHubInventoryID(subject, "github_installation", subject.ID)
	stable, _ := json.Marshal(struct {
		InstallationID int64  `json:"installation_id"`
		Owner          string `json:"owner"`
	}{InstallationID: installation.ID, Owner: installation.Account.Login})
	installationEntity, err := marshalGitHubEntity(installationEntityID, "github_installation", "github:installation:"+subject.ID, "GitHub installation "+installation.Account.Login, stable, json.RawMessage(`{}`))
	if err != nil {
		return nil, nil, false
	}
	appNativeID := strconv.FormatInt(installation.AppID, 10)
	appEntityID := deterministicGitHubInventoryID(subject, "github_app", appNativeID)
	appStable, _ := json.Marshal(struct {
		InstallationID int64  `json:"installation_id"`
		Name           string `json:"name"`
		Owner          string `json:"owner"`
	}{installation.ID, installation.AppSlug, installation.Account.Login})
	appEntity, err := marshalGitHubEntity(appEntityID, "github_app", "github:app:"+appNativeID, installation.AppSlug, appStable, json.RawMessage(`{}`))
	if err != nil {
		return nil, nil, false
	}
	entities := []json.RawMessage{installationEntity, appEntity}
	relationships := make([]json.RawMessage, 0, 3)
	contains, err := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "contains", subject.ID+":app:"+appNativeID), "contains", "github:installation:"+subject.ID+":app:"+appNativeID, installationEntityID, appEntityID, "installation_app")
	if err != nil {
		return nil, nil, false
	}
	relationships = append(relationships, contains)
	organizationNativeID := strconv.FormatInt(installation.Account.ID, 10)
	organizationEntityID := deterministicGitHubInventoryID(subject, "github_organization", organizationNativeID)
	organizationStable, _ := json.Marshal(struct {
		InstallationID int64  `json:"installation_id"`
		Name           string `json:"name"`
		Owner          string `json:"owner"`
	}{installation.ID, installation.Account.Login, installation.Account.Login})
	organizationEntity, marshalErr := marshalGitHubEntity(organizationEntityID, "github_organization", "github:organization:"+organizationNativeID, installation.Account.Login, organizationStable, json.RawMessage(`{}`))
	if marshalErr != nil {
		return nil, nil, false
	}
	entities = append(entities, organizationEntity)
	for _, scope := range []string{"actions", "contents", "metadata"} {
		permission := installation.Permissions[scope]
		permissionNativeID := appNativeID + ":" + scope + ":" + permission
		permissionEntityID := deterministicGitHubInventoryID(subject, "github_permission", permissionNativeID)
		permissionStable, _ := json.Marshal(struct {
			InstallationID int64  `json:"installation_id"`
			Name           string `json:"name"`
			Owner          string `json:"owner"`
			Permission     string `json:"permission"`
			Repository     string `json:"repository"`
			Scope          string `json:"scope"`
		}{installation.ID, scope + ":" + permission, installation.Account.Login, permission, "installation", scope})
		permissionEntity, marshalErr := marshalGitHubEntity(permissionEntityID, "github_permission", "github:app:"+appNativeID+":permission:"+scope, scope+":"+permission, permissionStable, json.RawMessage(`{}`))
		if marshalErr != nil {
			return nil, nil, false
		}
		entities = append(entities, permissionEntity)
		hasPermission, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "has_permission", permissionNativeID), "has_permission", "github:app:"+appNativeID+":permission:"+scope, appEntityID, permissionEntityID, "app_permission")
		if marshalErr != nil {
			return nil, nil, false
		}
		relationships = append(relationships, hasPermission)
	}
	return entities, relationships, true
}

type installationRepository struct {
	ID            int64           `json:"id"`
	Name          string          `json:"name"`
	FullName      string          `json:"full_name"`
	Private       bool            `json:"private"`
	Archived      bool            `json:"archived"`
	DefaultBranch string          `json:"default_branch"`
	Permissions   map[string]bool `json:"permissions"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func normalizeInstallationRepositories(subject collection.SubjectBinding, state githubPageState, repositories []installationRepository) ([]json.RawMessage, []json.RawMessage, bool) {
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	installationEntityID := deterministicGitHubInventoryID(subject, "github_installation", subject.ID)
	entities := make([]json.RawMessage, 0, len(repositories))
	relationships := make([]json.RawMessage, 0, len(repositories))
	seen := make(map[int64]struct{}, len(repositories))
	for _, repository := range repositories {
		if repository.ID < 1 || repository.ID > 1<<53 || !githubNamePattern.MatchString(repository.Name) || !validGitHubText(repository.Owner.Login, 100) || repository.Owner.Login != state.Owner || repository.FullName != repository.Owner.Login+"/"+repository.Name || !validGitHubText(repository.DefaultBranch, 255) || !validRepositoryPermissions(repository.Permissions) {
			return nil, nil, false
		}
		if _, duplicate := seen[repository.ID]; duplicate {
			return nil, nil, false
		}
		seen[repository.ID] = struct{}{}
		nativeID := strconv.FormatInt(repository.ID, 10)
		repositoryEntityID := deterministicGitHubInventoryID(subject, "github_repository", nativeID)
		visibility := "public"
		if repository.Private {
			visibility = "private"
		}
		stable, _ := json.Marshal(struct {
			InstallationID int64  `json:"installation_id"`
			Owner          string `json:"owner"`
			Repository     string `json:"repository"`
			Visibility     string `json:"visibility"`
			Name           string `json:"name"`
		}{installationID, repository.Owner.Login, repository.Name, visibility, repository.Name})
		attributes, _ := json.Marshal(struct {
			Archived      bool   `json:"archived"`
			DefaultBranch string `json:"default_branch"`
		}{repository.Archived, repository.DefaultBranch})
		entity, marshalErr := marshalGitHubEntity(repositoryEntityID, "github_repository", "github:repository:"+nativeID, repository.FullName, stable, attributes)
		if marshalErr != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationship, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "owns", subject.ID+":"+nativeID), "owns", "github:installation:"+subject.ID+":repository:"+nativeID, installationEntityID, repositoryEntityID, "installation_repository")
		if marshalErr != nil {
			return nil, nil, false
		}
		relationships = append(relationships, relationship)
		organizationID := deterministicGitHubInventoryID(subject, "github_organization", strconv.FormatInt(state.OwnerID, 10))
		organizationOwns, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "owns", "organization:"+strconv.FormatInt(state.OwnerID, 10)+":"+nativeID), "owns", "github:organization:"+strconv.FormatInt(state.OwnerID, 10)+":repository:"+nativeID, organizationID, repositoryEntityID, "organization_repository")
		if marshalErr != nil {
			return nil, nil, false
		}
		relationships = append(relationships, organizationOwns)
		permissionValues := []struct {
			name    string
			allowed bool
		}{{"admin", repository.Permissions["admin"]}, {"maintain", repository.Permissions["maintain"]}, {"pull", repository.Permissions["pull"]}, {"push", repository.Permissions["push"]}, {"triage", repository.Permissions["triage"]}}
		for _, value := range permissionValues {
			permissionState := "denied"
			if value.allowed {
				permissionState = "allowed"
			}
			permissionNativeID := nativeID + ":" + value.name + ":" + permissionState
			permissionEntityID := deterministicGitHubInventoryID(subject, "github_permission", permissionNativeID)
			permissionStable, _ := json.Marshal(struct {
				InstallationID int64  `json:"installation_id"`
				Name           string `json:"name"`
				Owner          string `json:"owner"`
				Permission     string `json:"permission"`
				Repository     string `json:"repository"`
				Scope          string `json:"scope"`
			}{installationID, value.name + ":" + permissionState, state.Owner, permissionState, repository.Name, value.name})
			permissionEntity, marshalErr := marshalGitHubEntity(permissionEntityID, "github_permission", "github:repository:"+nativeID+":permission:"+value.name, repository.FullName+":"+value.name, permissionStable, json.RawMessage(`{}`))
			if marshalErr != nil {
				return nil, nil, false
			}
			containsPermission, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "contains", nativeID+":permission:"+value.name), "contains", "github:repository:"+nativeID+":permission:"+value.name, repositoryEntityID, permissionEntityID, "repository_permission")
			if marshalErr != nil {
				return nil, nil, false
			}
			entities = append(entities, permissionEntity)
			relationships = append(relationships, containsPermission)
		}
	}
	return entities, relationships, true
}

func validRepositoryPermissions(permissions map[string]bool) bool {
	if len(permissions) != 5 {
		return false
	}
	for _, name := range []string{"admin", "maintain", "pull", "push", "triage"} {
		if _, ok := permissions[name]; !ok {
			return false
		}
	}
	return true
}

type repositoryWorkflowsResponse struct {
	TotalCount int                  `json:"total_count"`
	Workflows  []repositoryWorkflow `json:"workflows"`
}

type repositoryWorkflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

func normalizeRepositoryWorkflows(subject collection.SubjectBinding, state githubPageState, workflows []repositoryWorkflow) ([]json.RawMessage, []json.RawMessage, bool) {
	if len(workflows) > 1 {
		return nil, nil, false
	}
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	repositoryEntityID := deterministicGitHubInventoryID(subject, "github_repository", strconv.FormatInt(state.RepositoryID, 10))
	entities := make([]json.RawMessage, 0, len(workflows))
	relationships := make([]json.RawMessage, 0, len(workflows)*3)
	seen := make(map[string]struct{}, len(workflows))
	for _, workflow := range workflows {
		if workflow.ID < 1 || workflow.ID > 1<<53 || !validGitHubText(workflow.Name, 256) || !validGitHubWorkflowPath(workflow.Path) || !validGitHubWorkflowState(workflow.State) {
			return nil, nil, false
		}
		if _, duplicate := seen[workflow.Path]; duplicate {
			return nil, nil, false
		}
		seen[workflow.Path] = struct{}{}
		workflowEntityID := deterministicGitHubInventoryID(subject, "github_workflow", strconv.FormatInt(state.RepositoryID, 10)+":"+strconv.FormatInt(workflow.ID, 10))
		stable, _ := json.Marshal(struct {
			InstallationID int64  `json:"installation_id"`
			Name           string `json:"name"`
			Owner          string `json:"owner"`
			Repository     string `json:"repository"`
			Workflow       string `json:"workflow"`
		}{installationID, workflow.Name, state.Owner, state.Repository, workflow.Path})
		attributes, _ := json.Marshal(struct {
			State string `json:"state"`
		}{workflow.State})
		entity, marshalErr := marshalGitHubEntity(workflowEntityID, "github_workflow", "github:workflow:"+strconv.FormatInt(workflow.ID, 10), workflow.Name, stable, attributes)
		if marshalErr != nil {
			return nil, nil, false
		}
		contains, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "contains", strconv.FormatInt(state.RepositoryID, 10)+":"+strconv.FormatInt(workflow.ID, 10)), "contains", "github:repository:"+strconv.FormatInt(state.RepositoryID, 10)+":workflow:"+strconv.FormatInt(workflow.ID, 10), repositoryEntityID, workflowEntityID, "repository_workflow")
		if marshalErr != nil {
			return nil, nil, false
		}
		dependsOn, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "depends_on", strconv.FormatInt(workflow.ID, 10)+":"+strconv.FormatInt(state.RepositoryID, 10)), "depends_on", "github:workflow:"+strconv.FormatInt(workflow.ID, 10)+":repository:"+strconv.FormatInt(state.RepositoryID, 10), workflowEntityID, repositoryEntityID, "workflow_repository")
		if marshalErr != nil {
			return nil, nil, false
		}
		appEntityID := deterministicGitHubInventoryID(subject, "github_app", strconv.FormatInt(state.AppID, 10))
		usesIdentity, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "uses_identity", strconv.FormatInt(workflow.ID, 10)+":"+strconv.FormatInt(state.AppID, 10)), "uses_identity", "github:workflow:"+strconv.FormatInt(workflow.ID, 10)+":app:"+strconv.FormatInt(state.AppID, 10), workflowEntityID, appEntityID, "workflow_app")
		if marshalErr != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, contains, dependsOn, usesIdentity)
	}
	return entities, relationships, true
}

type repositoryEnvironmentsResponse struct {
	TotalCount   int                     `json:"total_count"`
	Environments []repositoryEnvironment `json:"environments"`
}

type repositoryEnvironment struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func normalizeRepositoryEnvironments(subject collection.SubjectBinding, state githubPageState, environments []repositoryEnvironment) ([]json.RawMessage, []json.RawMessage, bool) {
	if len(environments) > 1 {
		return nil, nil, false
	}
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	repositoryEntityID := deterministicGitHubInventoryID(subject, "github_repository", strconv.FormatInt(state.RepositoryID, 10))
	entities := make([]json.RawMessage, 0, len(environments))
	relationships := make([]json.RawMessage, 0, len(environments))
	for _, environment := range environments {
		if environment.ID < 1 || environment.ID > 1<<53 || !validGitHubText(environment.Name, 255) {
			return nil, nil, false
		}
		environmentEntityID := deterministicGitHubInventoryID(subject, "github_environment", strconv.FormatInt(state.RepositoryID, 10)+":"+strconv.FormatInt(environment.ID, 10))
		stable, _ := json.Marshal(struct {
			InstallationID int64  `json:"installation_id"`
			Name           string `json:"name"`
			Owner          string `json:"owner"`
			Repository     string `json:"repository"`
		}{installationID, environment.Name, state.Owner, state.Repository})
		entity, marshalErr := marshalGitHubEntity(environmentEntityID, "github_environment", "github:environment:"+strconv.FormatInt(environment.ID, 10), environment.Name, stable, json.RawMessage(`{}`))
		if marshalErr != nil {
			return nil, nil, false
		}
		contains, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "contains", strconv.FormatInt(state.RepositoryID, 10)+":environment:"+strconv.FormatInt(environment.ID, 10)), "contains", "github:repository:"+strconv.FormatInt(state.RepositoryID, 10)+":environment:"+strconv.FormatInt(environment.ID, 10), repositoryEntityID, environmentEntityID, "repository_environment")
		if marshalErr != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, contains)
	}
	return entities, relationships, true
}

func marshalGitHubEntity(id, kind, sourceNativeID, displayName string, stable, attributes json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stable, attributes})
}

func marshalGitHubRelationship(id, kind, sourceNativeID, from, to, relationshipType string) (json.RawMessage, error) {
	attributes, err := json.Marshal(struct {
		Type string `json:"type"`
	}{relationshipType})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, from, to, attributes})
}

func validInstallationPageRequest(request CollectionPageRequest) (githubPageState, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if request.Provider != collection.ProviderGitHub || request.Subject.Kind != "github_installation" || (!initialCursor && (request.Cursor.Provider != collection.ProviderGitHub || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < githubMinimumCollectionBytes {
		return githubPageState{}, false
	}
	installationID, err := strconv.ParseUint(request.Subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 || strings.HasPrefix(request.Subject.ID, "0") {
		return githubPageState{}, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return githubPageState{Phase: "installation", Lineage: 1}, request.Page == 1
	}
	if match := githubCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return githubPageState{Phase: "installation", Lineage: 1}, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderGitHub, request.Subject)
	}
	match := githubCollectionCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 {
		return githubPageState{}, false
	}
	lineage, lineageErr := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state githubPageState
	if lineageErr != nil || decodeErr != nil || len(payload) < 2 || len(payload) > 1350 || json.Unmarshal(payload, &state) != nil || state.Phase != match[1] || state.Lineage != lineage || request.Page != lineage || match[4] != providercollection.CursorBinding(collection.ProviderGitHub, request.Subject, state.Phase, lineage, match[3]) || !validGitHubCursorState(state) {
		return githubPageState{}, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return githubPageState{}, false
	}
	return state, true
}

func validGitHubCursorState(state githubPageState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || state.ProviderPage < 1 || state.ProviderPage > 1_000_000 || state.Total < 0 || state.Total > 10_000 || state.OwnerID < 1 || state.OwnerID > 1<<53 || state.AppID < 1 || state.AppID > 1<<53 || !validGitHubText(state.Owner, 100) {
		return false
	}
	if state.Phase == "repositories" {
		return state.RepositoryID == 0 && state.Repository == "" && state.DefaultBranch == "" && state.PhasePage == 0 && state.PhaseTotal == 0
	}
	return (state.Phase == "workflows" || state.Phase == "environments") && state.Total >= 1 && state.ProviderPage >= 2 && state.ProviderPage <= state.Total+1 && state.PhasePage >= 1 && state.PhasePage <= 10_000 && state.PhaseTotal >= 0 && state.PhaseTotal <= 10_000 && state.RepositoryID >= 1 && state.RepositoryID <= 1<<53 && githubNamePattern.MatchString(state.Repository) && validGitHubText(state.DefaultBranch, 255)
}

func validInstallationCredential(value []byte) bool {
	if len(value) < 16 || len(value) > 4096 || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func githubPageFits(request CollectionPageRequest, page CollectionPage) bool {
	return len(page.Entities) <= request.RemainingItems && len(page.Relationships) <= request.RemainingRelationships && int64(len(page.Raw)) <= request.RemainingBytes
}

func validGitHubPhasePage(total, page, priorTotal, itemCount int) bool {
	if total < 0 || total > 10_000 || page < 1 || priorTotal != 0 && priorTotal != total {
		return false
	}
	if total == 0 {
		return page == 1 && itemCount == 0
	}
	return page <= total && itemCount == 1
}

func validGitHubWorkflowPath(value string) bool {
	const prefix = ".github/workflows/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimPrefix(value, prefix)
	lower := strings.ToLower(name)
	return validGitHubText(name, 1024) && !strings.Contains(name, "/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"))
}

func validGitHubWorkflowState(value string) bool {
	switch value {
	case "active", "deleted", "disabled_fork", "disabled_inactivity", "disabled_manually":
		return true
	default:
		return false
	}
}

func validGitHubText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func deterministicGitHubInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("github\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func nextGitHubCompleteCursor(prior collection.Cursor, subjectID string, total int) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subjectID + "\x1f" + strconv.Itoa(total)))
	subject := collection.SubjectBinding{Kind: "github_installation", ID: subjectID}
	return collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: fmt.Sprintf("github:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderGitHub, subject), digest[:8])}
}

func nextGitHubCursor(subject collection.SubjectBinding, state githubPageState) (collection.Cursor, bool) {
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 1350 || !validGitHubCursorState(state) {
		return collection.Cursor{}, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderGitHub, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: fmt.Sprintf("github:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, len(cursor.Value) <= 2048
}

func decodeInstallationResponse(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func readInstallationBody(body io.Reader, maximum int64) ([]byte, bool) {
	if maximum < 1 {
		return nil, false
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	return value, err == nil && len(value) > 0 && int64(len(value)) <= maximum
}

func doInstallationRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrProvider
		}
	}()
	return client.Do(request)
}

func closeInstallationResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func rejectInstallationRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
