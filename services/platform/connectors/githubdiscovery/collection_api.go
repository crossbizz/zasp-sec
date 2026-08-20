package githubdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	githubCollectionCursorPattern = regexp.MustCompile(`^github:repositories:([1-9][0-9]{0,5}):([1-9][0-9]{0,5}):([0-9]{1,3}):([0-9a-f]{16})$`)
	githubCompleteCursorPattern   = regexp.MustCompile(`^github:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	githubNamePattern             = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

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
	phase, lineagePage, providerPage, pageLimit, ok := validInstallationPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.client == nil || ctx == nil || !validInstallationCredential(credential) || !ok {
		return CollectionPage{}, ErrInvalid
	}
	providerURL := githubCollectionEndpoint + "/installation"
	if phase == "repositories" {
		if pageLimit == 0 {
			pageLimit = request.RemainingItems
			if pageLimit > githubMaximumPageItems {
				pageLimit = githubMaximumPageItems
			}
		}
		query := url.Values{}
		query.Set("page", strconv.Itoa(providerPage))
		query.Set("per_page", strconv.Itoa(pageLimit))
		providerURL = githubCollectionEndpoint + "/installation/repositories?" + query.Encode()
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
	responseLimit := request.RemainingBytes
	if responseLimit > githubMaximumResponseBytes {
		responseLimit = githubMaximumResponseBytes
	}
	body, ok := readInstallationBody(response.Body, responseLimit)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if phase == "installation" {
		var payload installationResponse
		if !decodeInstallationResponse(body, &payload) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if strconv.FormatInt(payload.ID, 10) != request.Subject.ID {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureDenied)
		}
		if !validGitHubText(payload.Account.Login, 100) || payload.Account.ID < 1 || payload.Account.ID > 1<<53 || payload.Account.Type != "Organization" && payload.Account.Type != "User" {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		entity, normalizeOK := normalizeVerifiedInstallation(request.Subject, payload)
		if !normalizeOK {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		next := nextGitHubPageCursor(request.Subject, lineagePage+1, 1, 0)
		page, pageErr := NewCollectionPage(request.Subject, next, false, []json.RawMessage{entity}, nil)
		if pageErr != nil || int64(len(page.Raw)) > request.RemainingBytes || bytes.Contains(page.Raw, credential) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		return page, nil
	}
	var payload installationRepositoriesResponse
	if !decodeInstallationResponse(body, &payload) || len(payload.Repositories) > pageLimit || len(payload.Repositories) > request.RemainingItems || payload.TotalCount < len(payload.Repositories) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	entities, relationships, ok := normalizeInstallationRepositories(request.Subject, payload.Repositories)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	complete := providerPage*pageLimit >= payload.TotalCount
	next := nextGitHubPageCursor(request.Subject, lineagePage+1, providerPage+1, pageLimit)
	if complete {
		next = nextGitHubCompleteCursor(request.Cursor, request.Subject.ID, payload.TotalCount)
	}
	page, err := NewCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
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
	ID      int64 `json:"id"`
	Account struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

func normalizeVerifiedInstallation(subject collection.SubjectBinding, installation installationResponse) (json.RawMessage, bool) {
	installationEntityID := deterministicGitHubInventoryID(subject, "github_installation", subject.ID)
	stable, _ := json.Marshal(struct {
		InstallationID int64  `json:"installation_id"`
		Owner          string `json:"owner"`
	}{InstallationID: installation.ID, Owner: installation.Account.Login})
	entity, err := marshalGitHubEntity(installationEntityID, "github_installation", "github:installation:"+subject.ID, "GitHub installation "+installation.Account.Login, stable, json.RawMessage(`{}`))
	return entity, err == nil
}

type installationRepository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func normalizeInstallationRepositories(subject collection.SubjectBinding, repositories []installationRepository) ([]json.RawMessage, []json.RawMessage, bool) {
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	installationEntityID := deterministicGitHubInventoryID(subject, "github_installation", subject.ID)
	entities := make([]json.RawMessage, 0, len(repositories))
	relationships := make([]json.RawMessage, 0, len(repositories))
	seen := make(map[int64]struct{}, len(repositories))
	for _, repository := range repositories {
		if repository.ID < 1 || repository.ID > 1<<53 || !githubNamePattern.MatchString(repository.Name) || !validGitHubText(repository.Owner.Login, 100) || repository.FullName != repository.Owner.Login+"/"+repository.Name || !validGitHubText(repository.DefaultBranch, 255) {
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
		relationship, marshalErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "owns", subject.ID+":"+nativeID), "owns", "github:installation:"+subject.ID+":repository:"+nativeID, installationEntityID, repositoryEntityID)
		if marshalErr != nil {
			return nil, nil, false
		}
		relationships = append(relationships, relationship)
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

func marshalGitHubRelationship(id, kind, sourceNativeID, from, to string) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, from, to, json.RawMessage(`{"type":"installation_repository"}`)})
}

func validInstallationPageRequest(request CollectionPageRequest) (string, int, int, int, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if request.Provider != collection.ProviderGitHub || request.Subject.Kind != "github_installation" || (!initialCursor && (request.Cursor.Provider != collection.ProviderGitHub || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < githubMinimumCollectionBytes {
		return "", 0, 0, 0, false
	}
	installationID, err := strconv.ParseUint(request.Subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 || strings.HasPrefix(request.Subject.ID, "0") {
		return "", 0, 0, 0, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return "installation", 1, 0, 0, request.Page == 1
	}
	if match := githubCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return "installation", 1, 0, 0, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderGitHub, request.Subject)
	}
	match := githubCollectionCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 {
		return "", 0, 0, 0, false
	}
	lineage, lineageErr := strconv.Atoi(match[1])
	providerPage, pageErr := strconv.Atoi(match[2])
	pageLimit, limitErr := strconv.Atoi(match[3])
	continuation := match[2] + ":" + match[3]
	return "repositories", lineage, providerPage, pageLimit, lineageErr == nil && pageErr == nil && limitErr == nil && pageLimit >= 0 && pageLimit <= githubMaximumPageItems && request.Page == lineage && match[4] == providercollection.CursorBinding(collection.ProviderGitHub, request.Subject, "repositories", lineage, continuation)
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

func nextGitHubPageCursor(subject collection.SubjectBinding, lineage, providerPage, pageLimit int) collection.Cursor {
	continuation := strconv.Itoa(providerPage) + ":" + strconv.Itoa(pageLimit)
	return collection.Cursor{Provider: collection.ProviderGitHub, Version: "cursor_v1", Value: fmt.Sprintf("github:repositories:%d:%s:%s", lineage, continuation, providercollection.CursorBinding(collection.ProviderGitHub, subject, "repositories", lineage, continuation))}
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
