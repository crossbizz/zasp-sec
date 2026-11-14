package gcpdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// The Google APIs this collector reads, each from Google's own machine-readable
// description of the API (the discovery document). Paths, query parameters and
// response members below are the ones those documents state.
//
// DOCUMENTED: https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v3
//
//	organizations.get, folders.get, projects.get, projects.search (query
//	"state:ACTIVE"; a project's parent is its direct parent only),
//	projects.getIamPolicy (bindings of role and members).
//
// DOCUMENTED: https://aiplatform.googleapis.com/$discovery/rest?version=v1
//
//	projects.locations.list, projects.locations.reasoningEngines.list,
//	projects.locations.endpoints.list, and the regional hosts
//	<location>-aiplatform.googleapis.com.
//
// DOCUMENTED: https://dialogflow.googleapis.com/$discovery/rest?version=v3
//
//	projects.locations.list, projects.locations.agents.list.
//
// DOCUMENTED: https://discoveryengine.googleapis.com/$discovery/rest?version=v1alpha
//
//	projects.locations.collections.engines.list and
//	...engines.assistants.agents.list (Gemini Enterprise agents).
//
// DOCUMENTED: https://run.googleapis.com/$discovery/rest?version=v2
//
//	projects.locations.services.list ("cannot be the - wildcard"), and
//	version=v1 projects.locations.list.
//
// DOCUMENTED: https://cloudfunctions.googleapis.com/$discovery/rest?version=v2
//
//	projects.locations.functions.list ("use - in place of a location").
//
// DOCUMENTED: https://iam.googleapis.com/$discovery/rest?version=v1
//
//	projects.serviceAccounts.list.
//
// DOCUMENTED: https://modelarmor.googleapis.com/$discovery/rest?version=v1
//
//	projects.locations.templates.list, projects.locations.getFloorSetting and
//	the regional hosts modelarmor.<location>.rep.googleapis.com.
//
// DOCUMENTED: https://logging.googleapis.com/$discovery/rest?version=v2
//
//	entries.list (resourceNames, filter, orderBy "timestamp desc", pageSize).
//
// DOCUMENTED: https://raw.githubusercontent.com/googleapis/googleapis/master/google/cloud/audit/audit_log.proto
//
//	(service_name, method_name, resource_name, authentication_info.principal_email)
//	and .../google/api/error_reason.proto (reason SERVICE_DISABLED of domain
//	googleapis.com on a 403).
//
// What is not confirmed by those documents is marked UNVERIFIED where it is used.
const (
	gcpResourceManagerHost = "cloudresourcemanager.googleapis.com"
	gcpAIPlatformHost      = "aiplatform.googleapis.com"
	gcpDialogflowHost      = "dialogflow.googleapis.com"
	gcpDiscoveryEngineHost = "discoveryengine.googleapis.com"
	gcpRunHost             = "run.googleapis.com"
	gcpFunctionsHost       = "cloudfunctions.googleapis.com"
	gcpIAMHost             = "iam.googleapis.com"
	gcpLoggingHost         = "logging.googleapis.com"
	gcpModelArmorHost      = "modelarmor.googleapis.com"

	// The collection makes two passes over the projects of the scope: first
	// the service accounts of every project, then everything else. A
	// workload may run as a service account of another project, and it may
	// refer to an identity only once that identity is part of the snapshot.
	gcpPhaseIdentities = "identities"
	gcpPhaseProjects   = "projects"
	gcpPhaseSummary    = "summary"

	gcpMaximumResponseBytes     = int64(16 << 20)
	gcpMinimumCollectionBytes   = int64(4096)
	gcpMaximumContinuationBytes = 1024
	gcpProjectSearchPageSize    = 100
	// One collection reads at most this many projects; the rest are reported
	// as a coverage gap of the Resource Manager service.
	gcpMaximumProjects = 2000
	// Calls of one project that go to different locations run side by side.
	gcpConcurrentCalls   = 8
	gcpMaximumLocations  = 64
	gcpMaximumFolderHops = 12
)

var (
	gcpScopePattern          = regexp.MustCompile(`^(organizations/[1-9][0-9]{0,18}|folders/[1-9][0-9]{0,18}|projects/[a-z][a-z0-9-]{4,28}[a-z0-9])$`)
	gcpProjectIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpProjectNumberPattern  = regexp.MustCompile(`^projects/([1-9][0-9]{0,18})$`)
	gcpParentPattern         = regexp.MustCompile(`^(organizations|folders)/[1-9][0-9]{0,18}$`)
	gcpLocationPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	gcpPageCursorPattern     = regexp.MustCompile(`^gcp:(identities|projects|summary):([1-9][0-9]{0,6}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	gcpCompleteCursorPattern = regexp.MustCompile(`^gcp:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	gcpCountersPattern       = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){` + strconv.Itoa(gcpServiceCount*3-1) + `}$`)
)

// gcpPageState is the payload of a page cursor. Token is the opaque page
// token of the project search page being read and After the last project of
// that page already read; the request URL is always rebuilt, never taken from
// the provider. Counters holds, per service, how many projects answered,
// refused, or have the API switched off.
type gcpPageState struct {
	Phase    string `json:"p"`
	Lineage  int    `json:"l"`
	Token    string `json:"t,omitempty"`
	After    string `json:"a,omitempty"`
	Read     int    `json:"n,omitempty"`
	Counters string `json:"c,omitempty"`
}

type CollectionAPIConfig struct {
	// Transport replaces the bounded HTTPS transport (tests). Nil selects it.
	Transport http.RoundTripper
	// Timeout bounds every provider call (100ms..30s).
	Timeout time.Duration
	// Clock anchors Retry-After, the audit log window and finding times.
	Clock func() time.Time
}

type GCPCollectionAPI struct {
	client  *http.Client
	timeout time.Duration
	clock   func() time.Time
	// ancestry remembers, per scope, whether a folder lies below it. It
	// holds only resource ids, and only ones a token of that scope read.
	ancestryMutex sync.Mutex
	ancestry      map[string]bool
	// inherited remembers what one folder or organization answered to one
	// token: its parent and the roles its IAM policy binds service accounts
	// to. The key holds a digest of the token, so nothing read with one
	// credential is ever served to another, and an entry lives ten minutes.
	inheritedMutex sync.Mutex
	inherited      map[string]gcpAncestor
	// emitted remembers, per collection, the service account entities its
	// identities pass emitted, so the second pass relates a workload only
	// to an identity that is in the snapshot. A collection is one token and
	// one scope. A process that does not hold the memory (it restarted
	// between the passes) relates nothing, which is always safe.
	emittedMutex sync.Mutex
	emitted      map[string]*gcpEmitted
}

type gcpEmitted struct {
	ids     map[string]struct{}
	startAt time.Time
}

// One collection remembers at most this many identities; beyond it the
// second pass relates no further ones.
const gcpMaximumRememberedIdentities = 500_000

func gcpCollectionKey(token []byte, subject collection.SubjectBinding) string {
	digest := sha256.Sum256(append(append([]byte(subject.ID), 0x1f), token...))
	return string(digest[:16])
}

// remember records identities the identities pass emitted. restart begins a
// new collection: what an earlier one with the same token emitted is not in
// this snapshot.
func (api *GCPCollectionAPI) remember(key string, ids []string, restart bool) {
	api.emittedMutex.Lock()
	defer api.emittedMutex.Unlock()
	now := api.clock()
	for other, entry := range api.emitted {
		if now.Sub(entry.startAt) > 2*time.Hour {
			delete(api.emitted, other)
		}
	}
	entry := api.emitted[key]
	if entry == nil || restart {
		entry = &gcpEmitted{ids: map[string]struct{}{}, startAt: now}
		api.emitted[key] = entry
	}
	for _, id := range ids {
		if len(entry.ids) >= gcpMaximumRememberedIdentities {
			return
		}
		entry.ids[id] = struct{}{}
	}
}

func (api *GCPCollectionAPI) remembered(key, id string) bool {
	api.emittedMutex.Lock()
	defer api.emittedMutex.Unlock()
	entry := api.emitted[key]
	if entry == nil {
		return false
	}
	_, found := entry.ids[id]
	return found
}

func (api *GCPCollectionAPI) forget(key string) {
	api.emittedMutex.Lock()
	defer api.emittedMutex.Unlock()
	delete(api.emitted, key)
}

var _ CollectionAPI = (*GCPCollectionAPI)(nil)

// NewGCPCollectionAPI needs nothing customer-specific: the scope arrives as
// the page request subject and is read with the credential on page 1.
func NewGCPCollectionAPI(config CollectionAPIConfig) (*GCPCollectionAPI, error) {
	if config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	roundTripper := config.Transport
	if roundTripper == nil {
		dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}
		roundTripper = &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: gcpConcurrentCalls, IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 * 1024,
		}
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &GCPCollectionAPI{client: &http.Client{Transport: collection.EffectTransport{Next: roundTripper}, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, timeout: config.Timeout, clock: clock, ancestry: map[string]bool{}, inherited: map[string]gcpAncestor{}, emitted: map[string]*gcpEmitted{}}, nil
}

// callOutcome is what one provider call said, beyond failing the page.
type callOutcome int

const (
	// outcomeOK: 200 and a decoded body.
	outcomeOK callOutcome = iota
	// outcomeDenied: the service account may not make this call.
	outcomeDenied
	// outcomeDisabled: the API is switched off in the project.
	outcomeDisabled
	// outcomeAbsent: the resource or the location does not exist there.
	outcomeAbsent
)

// call makes one request. It returns an error only for what must fail the
// page: a transport failure, a rejected token, throttling, a server error or
// an unreadable body. A refusal or a disabled API is an outcome, because one
// project that refuses must not fail the collection.
func (api *GCPCollectionAPI) call(ctx context.Context, token []byte, method, host, path, query string, body []byte, destination any) (callOutcome, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	target := "https://" + host + path
	if query != "" {
		target += "?" + query
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(bounded, method, target, reader)
	if err != nil {
		return 0, ErrInvalid
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != nil {
		request.Header.Set("Authorization", "Bearer "+string(token))
	}
	response, err := doGCPRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return 0, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, gcpMaximumResponseBytes+1))
		if readErr != nil || len(payload) == 0 || int64(len(payload)) > gcpMaximumResponseBytes || json.Unmarshal(payload, destination) != nil {
			return 0, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		return outcomeOK, nil
	case http.StatusForbidden:
		// Only the machine-readable reason is read from the error body.
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		var failure struct {
			Error struct {
				Details []struct {
					Reason string `json:"reason"`
					Domain string `json:"domain"`
				} `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(payload, &failure)
		for _, detail := range failure.Error.Details {
			if detail.Domain == "googleapis.com" && (detail.Reason == "SERVICE_DISABLED" || detail.Reason == "BILLING_DISABLED") {
				return outcomeDisabled, nil
			}
		}
		return outcomeDenied, nil
	case http.StatusNotFound, http.StatusBadRequest, http.StatusNotImplemented:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return outcomeAbsent, nil
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return 0, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), api.clock())
	}
}

// list reads a paged listing: member holds the items and nextPageToken the
// continuation. It stops after maximumPages pages.
func (api *GCPCollectionAPI) list(ctx context.Context, token []byte, host, path string, query url.Values, member string, maximumPages int, visit func(json.RawMessage)) (callOutcome, error) {
	continuation := ""
	for page := 0; page < maximumPages; page++ {
		values := url.Values{}
		for key, value := range query {
			values[key] = value
		}
		if continuation != "" {
			values.Set("pageToken", continuation)
		}
		var document map[string]json.RawMessage
		outcome, err := api.call(ctx, token, http.MethodGet, host, path, values.Encode(), nil, &document)
		if err != nil || outcome != outcomeOK {
			// A refusal after the first page keeps what was read.
			if err == nil && page > 0 {
				return outcomeOK, nil
			}
			return outcome, err
		}
		var items []json.RawMessage
		if raw, present := document[member]; present && json.Unmarshal(raw, &items) != nil {
			return 0, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		for _, item := range items {
			visit(item)
		}
		next := ""
		if raw, present := document["nextPageToken"]; present && json.Unmarshal(raw, &next) != nil {
			return 0, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		if next == "" || next == continuation || len(next) > 4096 {
			return outcomeOK, nil
		}
		continuation = next
	}
	return outcomeOK, nil
}

// FetchCollectionPage returns one page: the scope, then one project per
// page, then the services summary.
func (api *GCPCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	state, initial, ok := validGCPPageRequest(request)
	token, credentialOK := decodeCredential(credential)
	if api == nil || api.client == nil || ctx == nil || !credentialOK || !ok {
		return CollectionPage{}, ErrInvalid
	}
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	finish := func(entities, relationships, findings []json.RawMessage, next gcpPageState, complete bool) (CollectionPage, error) {
		cursor := gcpCompleteCursor(request.Cursor, request.Subject)
		if !complete {
			var cursorOK bool
			if cursor, cursorOK = gcpStateCursor(request.Subject, next); !cursorOK {
				return CollectionPage{}, malformed
			}
		}
		sortGCPInventory(entities)
		sortGCPInventory(relationships)
		sortGCPInventory(findings)
		page, err := NewGCPCollectionPage(request.Subject, cursor, complete, entities, relationships, findings)
		if err != nil || bytes.Contains(page.Raw, credential) || bytes.Contains(page.Raw, token) {
			return CollectionPage{}, malformed
		}
		if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || len(page.Findings) > request.RemainingFindings || int64(len(page.Raw)) > request.RemainingBytes {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
		return page, nil
	}
	scopeEntityID := gcpInventoryID(request.Subject, "gcp_scope", request.Subject.ID)
	collectionKey := gcpCollectionKey(token, request.Subject)
	if initial {
		name, err := api.readScope(ctx, token, request.Subject.ID)
		if err != nil {
			return CollectionPage{}, err
		}
		entity, entityOK := gcpEntity(scopeEntityID, "gcp_scope", "gcp:scope:"+request.Subject.ID, name, map[string]any{"name": name, "scope": request.Subject.ID}, map[string]any{})
		if !entityOK {
			return CollectionPage{}, malformed
		}
		// A collection starts here: nothing an earlier one emitted counts.
		api.remember(collectionKey, nil, true)
		return finish([]json.RawMessage{entity}, nil, nil, gcpPageState{Phase: gcpPhaseIdentities, Lineage: 2}, false)
	}
	counters, countersOK := decodeGCPCounters(state.Counters)
	if !countersOK {
		return CollectionPage{}, ErrInvalid
	}
	if state.Phase == gcpPhaseSummary {
		entities, relationships, summaryOK := gcpServiceSummary(request.Subject, scopeEntityID, counters)
		if !summaryOK {
			return CollectionPage{}, malformed
		}
		api.forget(collectionKey)
		return finish(entities, relationships, nil, gcpPageState{}, true)
	}
	project, next, refused, err := api.nextProject(ctx, token, request.Subject.ID, state)
	if err != nil {
		return CollectionPage{}, err
	}
	identitiesPass := state.Phase == gcpPhaseIdentities
	if refused && !identitiesPass {
		// The projects below the scope could not be listed.
		counters[serviceResourceManager][outcomeDenied]++
	}
	// nextProject names the phase that follows the projects; after the
	// identities pass that is the second pass over the same projects.
	switch {
	case next.Phase == gcpPhaseSummary && identitiesPass:
		next = gcpPageState{Phase: gcpPhaseProjects}
	case next.Phase != gcpPhaseSummary:
		next.Phase = state.Phase
		next.Read = state.Read
	}
	if next.Phase == gcpPhaseSummary {
		next.Read = state.Read
	}
	next.Lineage, next.Counters = state.Lineage+1, encodeGCPCounters(counters)
	if project == nil {
		return finish(nil, nil, nil, next, false)
	}
	var read projectRead
	if identitiesPass {
		var ids []string
		if read, ids, err = api.readProjectIdentities(ctx, token, request.Subject, scopeEntityID, *project); err != nil {
			return CollectionPage{}, err
		}
		// Each pass counts the coverage of what it alone reads.
		for _, service := range []int{serviceIAM, serviceInheritedIAM} {
			counters[service][read.outcomes[service]]++
		}
		api.remember(collectionKey, ids, false)
	} else {
		known := func(id string) bool { return api.remembered(collectionKey, id) }
		if read, err = api.readProject(ctx, token, request.Subject, scopeEntityID, *project, known); err != nil {
			return CollectionPage{}, err
		}
		for service, outcome := range read.outcomes {
			if service != serviceIAM && service != serviceInheritedIAM {
				counters[service][outcome]++
			}
		}
	}
	next.Read, next.Counters = state.Read+1, encodeGCPCounters(counters)
	if next.Phase == gcpPhaseProjects && identitiesPass {
		// The single project of a project scope ends the identities pass.
		next.Read = 0
	}
	if next.Read >= gcpMaximumProjects {
		if identitiesPass {
			next = gcpPageState{Phase: gcpPhaseProjects, Lineage: next.Lineage, Counters: next.Counters}
		} else {
			// The projects beyond the bound are not read: a gap of the listing.
			counters[serviceResourceManager][outcomeDenied]++
			next = gcpPageState{Phase: gcpPhaseSummary, Lineage: next.Lineage, Read: next.Read, Counters: encodeGCPCounters(counters)}
		}
	}
	return finish(read.entities, read.relationships, read.findings, next, false)
}

// CheckCollectionReadiness proves Resource Manager is reachable and answers
// as Google's API without any credential: an unauthenticated search must be
// refused.
func (api *GCPCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "https://"+gcpResourceManagerHost+"/v3/projects:search?pageSize=1", nil)
	if err != nil {
		return ErrProvider
	}
	request.Header.Set("Accept", "application/json")
	response, err := doGCPRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrProvider
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return ErrProvider
	}
	return nil
}

// ProbeScope reads the organization, folder or project scope with the
// credential and reports whether it may be read. It is how an authorization
// is proven before any collection runs.
func (api *GCPCollectionAPI) ProbeScope(ctx context.Context, credential []byte, scope string) error {
	token, ok := decodeCredential(credential)
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil || !ok || !gcpScopePattern.MatchString(scope) {
		return ErrInvalid
	}
	if _, err := api.readScope(ctx, token, scope); err != nil {
		return ErrProvider
	}
	return nil
}

// readScope reads the organization, folder or project the integration names
// and returns its display name. A scope the token may not read is a denial.
func (api *GCPCollectionAPI) readScope(ctx context.Context, token []byte, scope string) (string, error) {
	var resource struct {
		Name        string `json:"name"`
		ProjectID   string `json:"projectId"`
		DisplayName string `json:"displayName"`
		State       string `json:"state"`
	}
	outcome, err := api.call(ctx, token, http.MethodGet, gcpResourceManagerHost, "/v3/"+scope, "", nil, &resource)
	if err != nil {
		return "", err
	}
	if outcome != outcomeOK || resource.State != "" && resource.State != "ACTIVE" || strings.HasPrefix(scope, "projects/") && "projects/"+resource.ProjectID != scope || !strings.HasPrefix(scope, "projects/") && resource.Name != scope {
		return "", providercollection.StableProviderFailure(collection.FailureDenied)
	}
	if !validGCPText(resource.DisplayName, 256) {
		return scope, nil
	}
	return resource.DisplayName, nil
}

type gcpProject struct {
	ID          string
	Number      string
	DisplayName string
	// Parent is the project's direct parent (folders/<n> or
	// organizations/<n>), "" for a project without one.
	Parent string
}

func decodeGCPProject(raw json.RawMessage) (gcpProject, string, bool) {
	var project struct {
		Name        string `json:"name"`
		ProjectID   string `json:"projectId"`
		Parent      string `json:"parent"`
		State       string `json:"state"`
		DisplayName string `json:"displayName"`
	}
	number := gcpProjectNumberPattern.FindStringSubmatch("")
	if json.Unmarshal(raw, &project) == nil {
		number = gcpProjectNumberPattern.FindStringSubmatch(project.Name)
	}
	if len(number) != 2 || !gcpProjectIDPattern.MatchString(project.ProjectID) || project.State != "ACTIVE" || project.Parent != "" && !gcpParentPattern.MatchString(project.Parent) {
		return gcpProject{}, "", false
	}
	if !validGCPText(project.DisplayName, 256) {
		project.DisplayName = project.ProjectID
	}
	return gcpProject{ID: project.ProjectID, Number: number[1], DisplayName: project.DisplayName, Parent: project.Parent}, project.Parent, true
}

// nextProject finds the next project of the scope after the cursor. It
// returns nil when this call found none to read; the returned state is where
// the next page continues (the summary when the projects are exhausted).
func (api *GCPCollectionAPI) nextProject(ctx context.Context, token []byte, scope string, state gcpPageState) (*gcpProject, gcpPageState, bool, error) {
	summary := gcpPageState{Phase: gcpPhaseSummary}
	if strings.HasPrefix(scope, "projects/") {
		if state.After != "" {
			return nil, summary, false, nil
		}
		var raw json.RawMessage
		outcome, err := api.call(ctx, token, http.MethodGet, gcpResourceManagerHost, "/v3/"+scope, "", nil, &raw)
		if err != nil {
			return nil, gcpPageState{}, false, err
		}
		project, _, ok := decodeGCPProject(raw)
		if outcome != outcomeOK || !ok || "projects/"+project.ID != scope {
			return nil, gcpPageState{}, false, providercollection.StableProviderFailure(collection.FailureDenied)
		}
		return &project, gcpPageState{Phase: gcpPhaseProjects, After: project.ID}, false, nil
	}
	query := url.Values{"query": {"state:ACTIVE"}, "pageSize": {strconv.Itoa(gcpProjectSearchPageSize)}}
	if state.Token != "" {
		query.Set("pageToken", state.Token)
	}
	var listed struct {
		Projects      []json.RawMessage `json:"projects"`
		NextPageToken string            `json:"nextPageToken"`
	}
	outcome, err := api.call(ctx, token, http.MethodGet, gcpResourceManagerHost, "/v3/projects:search", query.Encode(), nil, &listed)
	if err != nil {
		return nil, gcpPageState{}, false, err
	}
	if outcome != outcomeOK {
		// The scope itself was read on page 1; a search that is refused
		// leaves no project to read.
		return nil, summary, true, nil
	}
	type candidate struct {
		project gcpProject
		parent  string
	}
	candidates := make([]candidate, 0, len(listed.Projects))
	for _, raw := range listed.Projects {
		// A project that is being deleted, or one this collector cannot
		// name, is passed over.
		if project, parent, ok := decodeGCPProject(raw); ok && project.ID > state.After {
			candidates = append(candidates, candidate{project, parent})
		}
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].project.ID < candidates[right].project.ID })
	after := state.After
	for _, item := range candidates {
		inside, err := api.projectInScope(ctx, token, scope, item.parent)
		if err != nil {
			return nil, gcpPageState{}, false, err
		}
		after = item.project.ID
		if inside {
			project := item.project
			return &project, gcpPageState{Phase: gcpPhaseProjects, Token: state.Token, After: after}, false, nil
		}
	}
	if listed.NextPageToken == "" {
		return nil, summary, false, nil
	}
	if listed.NextPageToken == state.Token || !validGCPText(listed.NextPageToken, gcpMaximumContinuationBytes) || bytes.Contains([]byte(listed.NextPageToken), token) {
		return nil, gcpPageState{}, false, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return nil, gcpPageState{Phase: gcpPhaseProjects, Token: listed.NextPageToken}, false, nil
}

// projectInScope reports whether a project with this direct parent lies
// below the scope. The search lists every project the service account can
// see, and a project's record names only its direct parent, so the folders
// above it are read until the scope or an organization is reached.
func (api *GCPCollectionAPI) projectInScope(ctx context.Context, token []byte, scope, parent string) (bool, error) {
	visited := []string{}
	verdict := false
	for hop := 0; hop < gcpMaximumFolderHops && parent != ""; hop++ {
		if parent == scope {
			verdict = true
			break
		}
		if strings.HasPrefix(parent, "organizations/") {
			break
		}
		api.ancestryMutex.Lock()
		known, cached := api.ancestry[scope+"\x1f"+parent]
		api.ancestryMutex.Unlock()
		if cached {
			verdict = known
			break
		}
		visited = append(visited, parent)
		var folder struct {
			Parent string `json:"parent"`
		}
		outcome, err := api.call(ctx, token, http.MethodGet, gcpResourceManagerHost, "/v3/"+parent, "", nil, &folder)
		if err != nil {
			return false, err
		}
		if outcome != outcomeOK || !gcpParentPattern.MatchString(folder.Parent) {
			// A folder the token may not read is not below a scope the
			// token was granted.
			break
		}
		parent = folder.Parent
	}
	api.ancestryMutex.Lock()
	if len(api.ancestry) > 16_384 {
		api.ancestry = map[string]bool{}
	}
	for _, folder := range visited {
		api.ancestry[scope+"\x1f"+folder] = verdict
	}
	api.ancestryMutex.Unlock()
	return verdict, nil
}

func validGCPPageRequest(request CollectionPageRequest) (gcpPageState, bool, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if request.Provider != collection.ProviderGCP || request.Subject.Kind != "gcp_scope" || !gcpScopePattern.MatchString(request.Subject.ID) || (!initialCursor && (request.Cursor.Provider != collection.ProviderGCP || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < gcpMinimumCollectionBytes {
		return gcpPageState{}, false, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return gcpPageState{}, true, request.Page == 1
	}
	if match := gcpCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return gcpPageState{}, true, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderGCP, request.Subject)
	}
	match := gcpPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || len(match[3]) > 1800 || request.Page < 1 {
		return gcpPageState{}, false, false
	}
	lineage, err := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state gcpPageState
	if err != nil || decodeErr != nil || lineage != request.Page || len(payload) < 2 || len(payload) > 1350 || json.Unmarshal(payload, &state) != nil || state.Phase != match[1] || state.Lineage != lineage || match[4] != providercollection.CursorBinding(collection.ProviderGCP, request.Subject, match[1], lineage, match[3]) || !validGCPPageState(state) {
		return gcpPageState{}, false, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return gcpPageState{}, false, false
	}
	return state, false, true
}

func validGCPPageState(state gcpPageState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || state.Read < 0 || state.Read > gcpMaximumProjects || state.Counters != "" && !gcpCountersPattern.MatchString(state.Counters) ||
		state.Token != "" && !validGCPText(state.Token, gcpMaximumContinuationBytes) || state.After != "" && !gcpProjectIDPattern.MatchString(state.After) {
		return false
	}
	switch state.Phase {
	case gcpPhaseIdentities, gcpPhaseProjects:
		return true
	case gcpPhaseSummary:
		return state.Token == "" && state.After == ""
	default:
		return false
	}
}

func gcpCompleteCursor(prior collection.Cursor, subject collection.SubjectBinding) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subject.ID + "\x1fcomplete"))
	return collection.Cursor{Provider: collection.ProviderGCP, Version: "cursor_v1", Value: fmt.Sprintf("gcp:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderGCP, subject), digest[:8])}
}

func gcpStateCursor(subject collection.SubjectBinding, state gcpPageState) (collection.Cursor, bool) {
	if !validGCPPageState(state) {
		return collection.Cursor{}, false
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 1350 {
		return collection.Cursor{}, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderGCP, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderGCP, Version: "cursor_v1", Value: fmt.Sprintf("gcp:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, len(cursor.Value) <= 2048
}

// gcpCounters holds, per service, the number of projects by outcome
// (outcomeOK, outcomeDenied, outcomeDisabled).
type gcpCounters [gcpServiceCount][3]int

func decodeGCPCounters(value string) (gcpCounters, bool) {
	var counters gcpCounters
	if value == "" {
		return counters, true
	}
	if !gcpCountersPattern.MatchString(value) {
		return counters, false
	}
	for index, part := range strings.Split(value, ".") {
		counters[index/3][index%3], _ = strconv.Atoi(part)
	}
	return counters, true
}

func encodeGCPCounters(counters gcpCounters) string {
	parts := make([]string, 0, gcpServiceCount*3)
	for _, service := range counters {
		for _, count := range service {
			parts = append(parts, strconv.Itoa(count))
		}
	}
	return strings.Join(parts, ".")
}

// gcpInventoryID is the deterministic product id of an object of the scope.
func gcpInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("gcp\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

// gcpEntity marshals an entity. encoding/json writes map members sorted, the
// canonical form the snapshot contract requires.
func gcpEntity(id, kind, sourceNativeID, displayName string, stable, attributes any) (json.RawMessage, bool) {
	canonical := func(value any) (json.RawMessage, bool) {
		encoded, err := json.Marshal(value)
		var decoded map[string]any
		if err != nil || json.Unmarshal(encoded, &decoded) != nil || decoded == nil {
			return nil, false
		}
		encoded, err = json.Marshal(decoded)
		return encoded, err == nil
	}
	stableFields, stableOK := canonical(stable)
	attributeFields, attributesOK := canonical(attributes)
	if !stableOK || !attributesOK || len(sourceNativeID) > 1024 || !validGCPText(displayName, 256) {
		return nil, false
	}
	encoded, err := json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stableFields, attributeFields})
	return encoded, err == nil
}

func gcpRelationship(subject collection.SubjectBinding, kind, relationshipType, fromNative, toNative, from, to string) json.RawMessage {
	native := fromNative + "|" + kind + "|" + toNative
	if len(native) > 1024 {
		digest := sha256.Sum256([]byte(native))
		native = fmt.Sprintf("gcp:relationship:%x", digest)
	}
	encoded, _ := json.Marshal(struct {
		ID             string            `json:"id"`
		Kind           string            `json:"kind"`
		SourceNativeID string            `json:"source_native_id"`
		FromEntityID   string            `json:"from_entity_id"`
		ToEntityID     string            `json:"to_entity_id"`
		Attributes     map[string]string `json:"attributes"`
	}{gcpInventoryID(subject, "relationship", native), kind, native, from, to, map[string]string{"type": relationshipType}})
	return encoded
}

func gcpFinding(subject collection.SubjectBinding, entityID, entityNative, check string, observedAt time.Time) json.RawMessage {
	encoded, _ := json.Marshal(struct {
		ID         string `json:"id"`
		EntityID   string `json:"entity_id"`
		CheckID    string `json:"check_id"`
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		ObservedAt string `json:"observed_at"`
	}{gcpInventoryID(subject, "finding", check+"\x1f"+entityNative), entityID, check, "high", "FAIL", observedAt.UTC().Truncate(time.Second).Format(time.RFC3339)})
	return encoded
}

func sortGCPInventory(values []json.RawMessage) {
	identity := func(raw json.RawMessage) string {
		var value struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &value)
		return value.ID
	}
	sort.Slice(values, func(left, right int) bool { return identity(values[left]) < identity(values[right]) })
}

func validGCPText(value string, maximum int) bool {
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

func doGCPRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrProvider
		}
	}()
	return client.Do(request)
}

var errGCPFanOut = errors.New("gcp fan out")

// fanOut runs the calls side by side, at most gcpConcurrentCalls at once,
// and returns the first error.
func fanOut(ctx context.Context, count int, call func(context.Context, int) error) error {
	if count == 0 {
		return nil
	}
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, gcpConcurrentCalls)
	failures := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			defer func() {
				if recover() != nil {
					failures <- errGCPFanOut
				}
			}()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-bounded.Done():
				return
			}
			if err := call(bounded, index); err != nil {
				failures <- err
				cancel()
			}
		}(index)
	}
	group.Wait()
	close(failures)
	// The first failure sent is the cause: the others were cancelled by it.
	first := <-failures
	if first == nil && ctx.Err() != nil {
		return providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if errors.Is(first, errGCPFanOut) {
		return providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return first
}
