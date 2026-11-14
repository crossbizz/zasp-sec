package saasdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
)

const (
	// The Nango proxy relays at most this much of a provider response.
	maximumResponseBytes   = int64(1 << 20)
	minimumCollectionBytes = int64(4096)
	maximumPageItems       = 1000
	maximumContinuation    = 1024
	maximumCursorPayload   = 1400
	// A provider that rate-limits inside a 200 response states no retry
	// time; the collection waits this long.
	bodyRateLimitDelay = time.Minute
	// A 429 without a usable Retry-After header is still a rate limit: many
	// SaaS APIs send none, and a proxy in between may drop it. The
	// collection waits this long.
	defaultRateLimitDelay = time.Minute
	// One remembered object of a Distinct endpoint is eight characters of
	// the cursor.
	distinctDigestLength = 8
)

var (
	pageCursorPattern          = regexp.MustCompile(`^saas:([a-z][a-z0-9_]{0,31}):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	completeCursorPattern      = regexp.MustCompile(`^saas:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	connectionReferencePattern = regexp.MustCompile(`^ref:nango/connection/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// Proxy is the allow-listed Nango proxy (*nango.Adapter). It adds the
// provider token on Nango's side; this package never sees it.
type Proxy interface {
	ProxyWithQuery(ctx context.Context, connectorKey, connectionReference, method, path string, query url.Values, body []byte) (nango.ProxyResponse, error)
	// ProxyToHost is the request of a platform with a per-tenant host.
	ProxyToHost(ctx context.Context, connectorKey, connectionReference, host, method, path string, query url.Values, body []byte) (nango.ProxyResponse, error)
}

type CollectionAPIConfig struct {
	Registry *Registry
	Proxy    Proxy
	// Clock is the UTC clock rate-limit retry times are measured from. Nil
	// selects the system clock.
	Clock func() time.Time
}

type SaaSCollectionAPI struct {
	registry *Registry
	proxy    Proxy
	clock    func() time.Time
}

var _ CollectionAPI = (*SaaSCollectionAPI)(nil)

// pageState is the collection cursor's payload. Phase is "tenant" or the
// name of a list endpoint; Next is that endpoint's continuation (a provider
// token, an offset, or the query of a Link header's next page).
//
// A nested endpoint also keeps the parent object it is reading (ParentID)
// and the continuation of the parent list after that object (ParentNext);
// an empty ParentID means the next parent is to be fetched. A Distinct
// endpoint keeps the digests of the objects it has reported (Seen).
type pageState struct {
	Phase      string `json:"p"`
	Lineage    int    `json:"l"`
	Next       string `json:"n,omitempty"`
	ParentID   string `json:"pi,omitempty"`
	ParentNext string `json:"pn,omitempty"`
	Seen       string `json:"s,omitempty"`
}

// NewCollectionAPI builds the collector for every platform of the registry.
// The platform and the tenant arrive in the page request subject and the
// Nango connection reference as the credential.
func NewCollectionAPI(config CollectionAPIConfig) (CollectionAPI, error) {
	if config.Registry == nil || len(config.Registry.platforms) == 0 || nilProxy(config.Proxy) {
		return nil, ErrInvalid
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if now := clock(); now.IsZero() || now.Location() != time.UTC {
		return nil, ErrInvalid
	}
	return &SaaSCollectionAPI{registry: config.Registry, proxy: config.Proxy, clock: clock}, nil
}

// ValidConnectionReference reports whether value names a Nango connection.
func ValidConnectionReference(value string) bool {
	return connectionReferencePattern.MatchString(value)
}

func (api *SaaSCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.registry == nil || nilProxy(api.proxy) || api.clock == nil || ctx == nil || !connectionReferencePattern.Match(credential) {
		return CollectionPage{}, ErrInvalid
	}
	platform, tenantID, state, ok := api.validPageRequest(request)
	if !ok {
		return CollectionPage{}, ErrInvalid
	}
	reference := string(credential)
	var entities, relationships []json.RawMessage
	var next collection.Cursor
	var complete bool
	var err error
	if state.Phase == "tenant" {
		entities, next, err = api.fetchTenant(ctx, reference, platform, tenantID, request, state)
	} else {
		entities, relationships, next, complete, err = api.fetchList(ctx, reference, platform, tenantID, request, state)
	}
	if err != nil {
		return CollectionPage{}, err
	}
	page, err := providercollection.NewPage(collection.ProviderSaaS, request.Subject, next, complete, entities, relationships)
	if err != nil || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || int64(len(page.Raw)) > request.RemainingBytes {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

// CheckCollectionReadiness makes no provider call: the collector is bound to
// no tenant until a page request and its connection reference arrive.
func (api *SaaSCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.registry == nil || nilProxy(api.proxy) || api.clock == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	return nil
}

// LookupTenant asks the platform which tenant the connection reaches. The
// collector runs it as the first page of every collection and the API runs
// it when an integration is authorized. The result is a tenant whose id has
// the platform's grammar, or a classified collection failure.
//
// tenantID is the tenant the integration names. For a platform with a
// per-tenant host it decides the host the request is sent to; for every
// platform the result's id equals it, or the lookup fails as denied: a
// connection that reaches another tenant is refused.
func LookupTenant(ctx context.Context, proxy Proxy, platform Platform, connectionReference, tenantID string, now time.Time) (Tenant, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	if ctx == nil || nilProxy(proxy) || platform.Validate() != nil || !connectionReferencePattern.MatchString(connectionReference) || !platform.ValidTenant(tenantID) {
		return Tenant{}, ErrInvalid
	}
	host, _ := platform.TenantHost(tenantID)
	path, ok := expandPath(platform.Tenant.Path, tenantID, "")
	if !ok {
		return Tenant{}, ErrInvalid
	}
	document, _, _, err := get(ctx, proxy, platform, connectionReference, host, path, fixedQuery(platform.Tenant.Query, ""), maximumResponseBytes, now, nil)
	if err != nil {
		return Tenant{}, err
	}
	object, isObject := document.(map[string]any)
	if !isObject {
		return Tenant{}, malformed
	}
	var tenant Tenant
	if platform.Tenant.Confirm != nil {
		name, confirmed := platform.Tenant.Confirm(Item(object), tenantID)
		if !confirmed {
			return Tenant{}, providercollection.StableProviderFailure(collection.FailureDenied)
		}
		tenant = Tenant{ID: tenantID, Name: name}
	} else {
		var found bool
		if tenant, found = platform.Tenant.Map(Item(object)); !found || !platform.ValidTenant(tenant.ID) {
			return Tenant{}, malformed
		}
		if tenant.ID != tenantID {
			return Tenant{}, providercollection.StableProviderFailure(collection.FailureDenied)
		}
	}
	if tenant.Name = CleanText(tenant.Name, 256); tenant.Name == "" {
		tenant.Name = tenant.ID
	}
	return tenant, nil
}

func (api *SaaSCollectionAPI) fetchTenant(ctx context.Context, reference string, platform Platform, tenantID string, request CollectionPageRequest, state pageState) ([]json.RawMessage, collection.Cursor, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	// The connection must reach exactly the tenant the integration is bound
	// to: the lookup refuses a connection of another tenant as denied.
	tenant, err := LookupTenant(ctx, api.proxy, platform, reference, tenantID, api.clock())
	if errors.Is(err, ErrInvalid) {
		err = malformed
	}
	if err != nil {
		return nil, collection.Cursor{}, err
	}
	entity, err := marshalEntity(deterministicInventoryID(request.Subject, "saas_tenant", request.Subject.ID), "saas_tenant", "saas:"+platform.Token+":tenant:"+tenantID, tenant.Name,
		map[string]any{"name": tenant.Name, "platform": platform.Token, "tenant": tenantID}, map[string]any{})
	if err != nil {
		return nil, collection.Cursor{}, malformed
	}
	next, ok := nextStateCursor(request.Subject, pageState{Phase: platform.Lists[0].Name, Lineage: state.Lineage + 1})
	if !ok {
		return nil, collection.Cursor{}, malformed
	}
	return []json.RawMessage{entity}, next, nil
}

func (api *SaaSCollectionAPI) fetchList(ctx context.Context, reference string, platform Platform, tenantID string, request CollectionPageRequest, state pageState) ([]json.RawMessage, []json.RawMessage, collection.Cursor, bool, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	fail := func(err error) ([]json.RawMessage, []json.RawMessage, collection.Cursor, bool, error) {
		return nil, nil, collection.Cursor{}, false, err
	}
	index := endpointIndex(platform, state.Phase)
	if index < 0 || request.RemainingItems < 1 || request.RemainingRelationships < 1 {
		return fail(providercollection.ErrPageCapacity)
	}
	endpoint := platform.Lists[index]
	host, hostOK := platform.TenantHost(tenantID)
	if !hostOK {
		return fail(malformed)
	}
	limit := min(request.RemainingBytes, maximumResponseBytes)
	parentID, parentNext := state.ParentID, state.ParentNext
	// exhausted: the endpoint has nothing more to read.
	exhausted := false
	if endpoint.Parent != nil && parentID == "" {
		// The next parent object. The parent list is read one object at a
		// time, so the cursor holds one id and one continuation.
		parents := ListEndpoint{Path: endpoint.Parent.Path, Query: endpoint.Parent.Query, ItemsPath: endpoint.Parent.ItemsPath, Paging: endpoint.Parent.Paging}
		query, offset, ok := parents.requestQuery(parentNext, tenantID)
		path, pathOK := expandPath(parents.Path, tenantID, "")
		if !ok || !pathOK {
			return fail(malformed)
		}
		document, link, absent, err := get(ctx, api.proxy, platform, reference, host, path, query, limit, api.clock(), endpoint.Absent)
		if err != nil {
			return fail(err)
		}
		items, ok := parents.items(document)
		switch {
		case absent || ok && len(items) == 0:
			exhausted = true
		case !ok || len(items) != 1:
			return fail(malformed)
		default:
			if parentID = endpoint.Parent.ID(items[0]); !parentIDPattern.MatchString(parentID) || strings.Contains(parentID, "..") {
				return fail(malformed)
			}
			if parentNext, ok = parents.continuation(document, link, state.ParentNext, offset, 1); !ok {
				return fail(malformed)
			}
		}
	}
	var entities, relationships []json.RawMessage
	continuation, seen := "", state.Seen
	if !exhausted {
		query, offset, ok := endpoint.requestQuery(state.Next, tenantID)
		path, pathOK := expandPath(endpoint.Path, tenantID, parentID)
		if !ok || !pathOK {
			return fail(malformed)
		}
		document, link, absent, err := get(ctx, api.proxy, platform, reference, host, path, query, limit, api.clock(), endpoint.Absent)
		if err != nil {
			return fail(err)
		}
		if !absent {
			items, ok := endpoint.items(document)
			if !ok || len(items) > maximumPageItems {
				return fail(malformed)
			}
			if len(items) > request.RemainingItems || len(items) > request.RemainingRelationships {
				return fail(providercollection.ErrPageCapacity)
			}
			if entities, relationships, seen, ok = normalizeItems(request.Subject, platform, tenantID, endpoint, parentID, items, state.Seen); !ok {
				return fail(malformed)
			}
			if len(seen) > MaximumDistinct*distinctDigestLength {
				// More distinct objects than the cursor can remember: the
				// next page could report one twice. The collection stops.
				return fail(providercollection.StableProviderFailure(collection.FailureTerminal))
			}
			if continuation, ok = endpoint.continuation(document, link, state.Next, offset, len(items)); !ok {
				return fail(malformed)
			}
		}
	}
	following := pageState{Phase: endpoint.Name, Lineage: state.Lineage + 1, Seen: seen}
	switch {
	case exhausted:
	case continuation != "":
		// More pages of this list (under this parent).
		following.Next, following.ParentID, following.ParentNext = continuation, parentID, parentNext
	case endpoint.Parent != nil && parentNext != "":
		// This parent is done; the next page fetches the next parent.
		following.ParentNext = parentNext
	default:
		exhausted = true
	}
	if exhausted {
		if index == len(platform.Lists)-1 {
			return entities, relationships, nextCompleteCursor(request.Cursor, request.Subject), true, nil
		}
		following = pageState{Phase: platform.Lists[index+1].Name, Lineage: state.Lineage + 1}
	}
	next, ok := nextStateCursor(request.Subject, following)
	if !ok {
		return fail(malformed)
	}
	return entities, relationships, next, false, nil
}

// requestQuery is the query of the endpoint's next request. For an offset
// endpoint it also returns the offset the request asks for.
func (endpoint ListEndpoint) requestQuery(continuation, tenantID string) (url.Values, int, bool) {
	query := fixedQuery(endpoint.Query, tenantID)
	paging := endpoint.Paging
	if paging.LimitParam != "" {
		query.Set(paging.LimitParam, strconv.Itoa(paging.PageSize))
	}
	switch paging.Style {
	case PagingNone:
		return query, 0, continuation == ""
	case PagingCursor:
		if continuation != "" {
			query.Set(paging.CursorParam, continuation)
		}
		return query, 0, true
	case PagingOffset:
		offset := 0
		if continuation != "" {
			parsed, err := strconv.Atoi(continuation)
			if err != nil || parsed < 1 || parsed > 100_000_000 || strconv.Itoa(parsed) != continuation {
				return nil, 0, false
			}
			offset = parsed
		}
		query.Set(paging.OffsetParam, strconv.Itoa(offset))
		return query, offset, true
	case PagingPage:
		// The continuation is the number of the page to ask for; the
		// second result is that number.
		page := 1
		if continuation != "" {
			parsed, err := strconv.Atoi(continuation)
			if err != nil || parsed < 2 || parsed > 1_000_000 || strconv.Itoa(parsed) != continuation {
				return nil, 0, false
			}
			page = parsed
		}
		query.Set(paging.PageParam, strconv.Itoa(page))
		return query, page, true
	case PagingLink:
		if continuation == "" {
			return query, 0, true
		}
		// The whole query of the provider's next link replaces the first
		// request's: the provider chose it.
		next, err := url.ParseQuery(continuation)
		if err != nil || len(next) == 0 {
			return nil, 0, false
		}
		for _, values := range next {
			if len(values) != 1 {
				return nil, 0, false
			}
		}
		return next, 0, true
	}
	return nil, 0, false
}

// items finds the array of items in a response document. A missing or null
// array is an empty list: several providers omit it when nothing matches.
func (endpoint ListEndpoint) items(document any) ([]Item, bool) {
	var value any = document
	if len(endpoint.ItemsPath) > 0 {
		object, isObject := document.(map[string]any)
		if !isObject {
			return nil, false
		}
		value, _ = Item(object).at(endpoint.ItemsPath)
	}
	if value == nil {
		return nil, true
	}
	if endpoint.Single {
		object, isObject := value.(map[string]any)
		return []Item{Item(object)}, isObject
	}
	list, isList := value.([]any)
	if !isList {
		return nil, false
	}
	items := make([]Item, 0, len(list))
	for _, member := range list {
		object, isObject := member.(map[string]any)
		if !isObject {
			return nil, false
		}
		items = append(items, Item(object))
	}
	return items, true
}

// continuation is the endpoint's next continuation, "" when the page was the
// last. A provider that repeats the continuation it was sent is refused: the
// collection would never end.
func (endpoint ListEndpoint) continuation(document any, link, current string, offset, count int) (string, bool) {
	next := ""
	switch endpoint.Paging.Style {
	case PagingNone:
		return "", true
	case PagingCursor:
		object, isObject := document.(map[string]any)
		if !isObject {
			return "", false
		}
		value, _ := Item(object).at(endpoint.Paging.NextPath)
		switch typed := value.(type) {
		case nil:
		case string:
			next = typed
		case json.Number:
			next = typed.String()
		default:
			return "", false
		}
		if len(endpoint.Paging.MorePath) > 0 {
			more, _ := Item(object).at(endpoint.Paging.MorePath)
			switch typed := more.(type) {
			case nil:
				next = ""
			case bool:
				if !typed {
					next = ""
				}
			default:
				return "", false
			}
		}
	case PagingOffset:
		if count == 0 || count < endpoint.Paging.PageSize {
			return "", true
		}
		next = strconv.Itoa(offset + count)
	case PagingPage:
		// offset is the page number the request asked for.
		if count == 0 || count < endpoint.Paging.PageSize {
			return "", true
		}
		next = strconv.Itoa(offset + 1)
	case PagingLink:
		var ok bool
		if next, ok = nextLinkQuery(link, endpoint.Path); !ok {
			return "", false
		}
	}
	if next == "" {
		return "", true
	}
	if next == current || !validDisplayText(next, maximumContinuation) {
		return "", false
	}
	return next, true
}

// nextLinkQuery reads the rel="next" target of a Link header and returns its
// query. The target must be the endpoint's own path: the collector follows
// no provider-chosen location. The host is never used; requests go through
// the proxy only.
func nextLinkQuery(header, path string) (string, bool) {
	if header == "" {
		return "", true
	}
	for _, part := range strings.Split(header, ",") {
		target, parameters, found := strings.Cut(strings.TrimSpace(part), ";")
		target = strings.TrimSpace(target)
		if !found || len(target) < 3 || target[0] != '<' || target[len(target)-1] != '>' {
			continue
		}
		isNext := false
		for _, parameter := range strings.Split(parameters, ";") {
			name, value, _ := strings.Cut(strings.TrimSpace(parameter), "=")
			if strings.EqualFold(strings.TrimSpace(name), "rel") {
				for _, relation := range strings.Fields(strings.Trim(strings.TrimSpace(value), `"`)) {
					isNext = isNext || strings.EqualFold(relation, "next")
				}
			}
		}
		if !isNext {
			continue
		}
		parsed, err := url.Parse(target[1 : len(target)-1])
		if err != nil || parsed.Path != path || parsed.RawQuery == "" || parsed.Fragment != "" {
			return "", false
		}
		return parsed.RawQuery, true
	}
	return "", true
}

// normalizeItems maps the items of one response to entities and their
// relationships to the tenant. seen holds the digests of the objects a
// Distinct endpoint has reported on earlier pages; the result holds those
// and the ones of this page.
func normalizeItems(subject collection.SubjectBinding, platform Platform, tenantID string, endpoint ListEndpoint, parentID string, items []Item, seenBefore string) ([]json.RawMessage, []json.RawMessage, string, bool) {
	reported := map[string]bool{}
	for start := 0; start+distinctDigestLength <= len(seenBefore); start += distinctDigestLength {
		reported[seenBefore[start:start+distinctDigestLength]] = true
	}
	seenAfter := seenBefore
	tenantEntityID := deterministicInventoryID(subject, "saas_tenant", subject.ID)
	entities := make([]json.RawMessage, 0, len(items))
	relationships := make([]json.RawMessage, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		var mapped Entity
		var keep bool
		if endpoint.Parent != nil {
			mapped, keep = endpoint.MapChild(parentID, item)
		} else {
			mapped, keep = endpoint.Map(item)
		}
		if !keep {
			continue
		}
		if !validEntity(mapped) {
			return nil, nil, "", false
		}
		native := mapped.ObjectType + "/" + mapped.NativeID
		if endpoint.Distinct {
			digest := sha256.Sum256([]byte(mapped.Kind + "\x1f" + native))
			key := base64.RawURLEncoding.EncodeToString(digest[:6])
			if reported[key] {
				continue
			}
			reported[key] = true
			seenAfter += key
		}
		if _, duplicate := seen[mapped.Kind+"\x1f"+native]; duplicate {
			return nil, nil, "", false
		}
		seen[mapped.Kind+"\x1f"+native] = struct{}{}
		attributes := map[string]any{"status": mapped.Status}
		if mapped.Kind == KindMCPServer {
			if mapped.EndpointHost != "" {
				attributes["endpoint_host"] = mapped.EndpointHost
			}
		} else {
			if mapped.AgentType != "" {
				attributes["agent_type"] = mapped.AgentType
			}
			if mapped.Model != "" {
				attributes["model"] = mapped.Model
			}
			// An agent is listed because the platform's API names it one;
			// an AI application because of the signals the API states.
			method := agentsignals.MethodProviderAPI
			if mapped.Kind == KindAIApplication {
				method = agentsignals.MethodInferred
			}
			attributes["posture"] = mapped.Posture
			attributes["discovery"] = agentsignals.NewDiscovery(method, platform.Token, mapped.Signals)
		}
		entityID := deterministicInventoryID(subject, mapped.Kind, native)
		entity, err := marshalEntity(entityID, mapped.Kind, "saas:"+platform.Token+":"+mapped.ObjectType+":"+mapped.NativeID, mapped.DisplayName,
			map[string]any{"name": mapped.DisplayName, "object_type": mapped.ObjectType, "platform": platform.Token, "tenant": tenantID}, attributes)
		if err != nil {
			return nil, nil, "", false
		}
		relationship, err := marshalRelationship(deterministicInventoryID(subject, "contains", mapped.Kind+"/"+native), "saas:"+platform.Token+":tenant:"+tenantID+":"+mapped.ObjectType+":"+mapped.NativeID, tenantEntityID, entityID)
		if err != nil {
			return nil, nil, "", false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
	}
	return entities, relationships, seenAfter, true
}

func validEntity(entity Entity) bool {
	if entity.Kind != KindAgent && entity.Kind != KindAIApplication && entity.Kind != KindMCPServer || !validDisplayText(entity.NativeID, 512) || !validDisplayText(entity.DisplayName, 256) ||
		!objectTypePattern.MatchString(entity.ObjectType) || !validDisplayText(entity.Status, 64) ||
		entity.AgentType != "" && !validDisplayText(entity.AgentType, 128) || entity.Model != "" && !validDisplayText(entity.Model, 128) ||
		entity.EndpointHost != "" && (!hostPattern.MatchString(entity.EndpointHost) || entity.Kind != KindMCPServer) ||
		len(entity.Signals) > agentsignals.MaximumSignals || entity.Kind == KindAIApplication && len(entity.Signals) == 0 || entity.Kind == KindMCPServer && len(entity.Signals) != 0 {
		return false
	}
	if !sort.StringsAreSorted(entity.Signals) {
		return false
	}
	for index, signal := range entity.Signals {
		if !signalPattern.MatchString(signal) || index > 0 && signal == entity.Signals[index-1] {
			return false
		}
	}
	return true
}

// get performs one bounded read through the proxy and decodes the JSON
// response. absent reports that the provider answered one of the statuses
// the endpoint declares as "feature not present". Every other outcome that
// is not a decoded document is a classified collection failure.
func get(ctx context.Context, proxy Proxy, platform Platform, reference, host, path string, query url.Values, limit int64, now time.Time, absentStatuses []int) (document any, link string, absent bool, err error) {
	if boundary := collection.CheckEffectBoundary(ctx); boundary != nil {
		return nil, "", false, providercollection.ClassifyProviderError(ctx, boundary)
	}
	response, proxyErr := callProxy(ctx, proxy, platform.Nango.Key, reference, host, path, query)
	if proxyErr != nil {
		var status *nango.StatusError
		switch {
		case ctx.Err() != nil:
			return nil, "", false, providercollection.ClassifyProviderError(ctx, ctx.Err())
		case errors.As(proxyErr, &status):
			for _, absentStatus := range absentStatuses {
				if status.StatusCode == absentStatus {
					return nil, "", true, nil
				}
			}
			failure := providercollection.ClassifyProviderHTTPFailure(ctx, nil, status.StatusCode, status.RetryAfter, now)
			var classified *collection.Failure
			if status.StatusCode == http.StatusTooManyRequests && ctx.Err() == nil && errors.As(failure, &classified) && classified.Code() == collection.FailureMalformed {
				// The shared classifier calls a 429 without a usable
				// Retry-After malformed, which ends the collection. For
				// a SaaS API read through a proxy it is a rate limit
				// with no stated wait.
				if limited, limitErr := collection.NewFailure(collection.FailureRateLimited, now.Add(defaultRateLimitDelay)); limitErr == nil {
					failure = limited
				}
			}
			return nil, "", false, failure
		case errors.Is(proxyErr, nango.ErrInvalid):
			// The request is outside the platform's own proxy rules: the
			// definition is wrong, and a retry cannot help.
			return nil, "", false, providercollection.StableProviderFailure(collection.FailureTerminal)
		default:
			return nil, "", false, providercollection.ClassifyProviderError(ctx, proxyErr)
		}
	}
	if limit < 1 || int64(len(response.Body)) > limit {
		return nil, "", false, providercollection.ErrPageCapacity
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || document == nil {
		return nil, "", false, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if object, isObject := document.(map[string]any); isObject && platform.Failure != nil {
		if code, failed := platform.Failure(Item(object)); failed {
			if code == collection.FailureRateLimited {
				failure, _ := collection.NewFailure(collection.FailureRateLimited, now.Add(bodyRateLimitDelay))
				return nil, "", false, failure
			}
			return nil, "", false, providercollection.StableProviderFailure(code)
		}
	}
	return document, response.Link, false, nil
}

func callProxy(ctx context.Context, proxy Proxy, key, reference, host, path string, query url.Values) (response nango.ProxyResponse, resultErr error) {
	defer func() {
		if recover() != nil {
			response, resultErr = nango.ProxyResponse{}, nango.ErrProxy
		}
	}()
	if host != "" {
		return proxy.ProxyToHost(ctx, key, reference, host, http.MethodGet, path, query, nil)
	}
	return proxy.ProxyWithQuery(ctx, key, reference, http.MethodGet, path, query, nil)
}

func fixedQuery(values map[string]string, tenantID string) url.Values {
	query := url.Values{}
	for key, value := range values {
		if value == TenantQueryValue {
			value = tenantID
		}
		query.Set(key, value)
	}
	return query
}

func endpointIndex(platform Platform, name string) int {
	for index, endpoint := range platform.Lists {
		if endpoint.Name == name {
			return index
		}
	}
	return -1
}

func marshalEntity(id, kind, sourceNativeID, displayName string, stable, attributes map[string]any) (json.RawMessage, error) {
	// A map is encoded with its members sorted at every depth after one
	// round trip, the canonical form the snapshot contract requires.
	stableJSON, stableErr := canonicalObject(stable)
	attributesJSON, attributesErr := canonicalObject(attributes)
	if stableErr != nil || attributesErr != nil || len(sourceNativeID) > 1024 {
		return nil, ErrInvalid
	}
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stableJSON, attributesJSON})
}

func canonicalObject(value map[string]any) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil || decoded == nil {
		return nil, ErrInvalid
	}
	return json.Marshal(decoded)
}

func marshalRelationship(id, sourceNativeID, from, to string) (json.RawMessage, error) {
	if len(sourceNativeID) > 1024 {
		return nil, ErrInvalid
	}
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, "contains", sourceNativeID, from, to, json.RawMessage(`{"type":"tenant_object"}`)})
}

// splitSubject returns the platform token and the tenant id of a saas
// subject id.
func splitSubject(subjectID string) (string, string, bool) {
	token, tenantID, found := strings.Cut(subjectID, "/")
	return token, tenantID, found && ValidPlatformToken(token) && ValidTenantID(tenantID)
}

func (api *SaaSCollectionAPI) validPageRequest(request CollectionPageRequest) (Platform, string, pageState, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	token, tenantID, subjectOK := splitSubject(request.Subject.ID)
	platform, known := api.registry.Platform(token)
	if request.Provider != collection.ProviderSaaS || request.Subject.Kind != "saas_tenant" || !subjectOK || !known || !platform.ValidTenant(tenantID) ||
		(!initialCursor && (request.Cursor.Provider != collection.ProviderSaaS || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < minimumCollectionBytes {
		return Platform{}, "", pageState{}, false
	}
	first := pageState{Phase: "tenant", Lineage: 1}
	if initialCursor || request.Cursor.Value == "initial" {
		return platform, tenantID, first, request.Page == 1
	}
	if match := completeCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return platform, tenantID, first, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderSaaS, request.Subject)
	}
	match := pageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || request.Page < 1 {
		return Platform{}, "", pageState{}, false
	}
	lineage, err := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state pageState
	if err != nil || decodeErr != nil || lineage != request.Page || len(payload) < 2 || len(payload) > maximumCursorPayload || !decodeCursorState(payload, &state) || state.Phase != match[1] || state.Lineage != lineage ||
		match[4] != providercollection.CursorBinding(collection.ProviderSaaS, request.Subject, match[1], lineage, match[3]) || !validPageState(platform, state) {
		return Platform{}, "", pageState{}, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return Platform{}, "", pageState{}, false
	}
	return platform, tenantID, state, true
}

func validPageState(platform Platform, state pageState) bool {
	index := endpointIndex(platform, state.Phase)
	if index < 0 || state.Lineage < 2 || state.Lineage > 1_000_000 {
		return false
	}
	endpoint := platform.Lists[index]
	// Only a nested endpoint has a parent in its cursor and only a Distinct
	// one a list of reported objects.
	if endpoint.Parent == nil && (state.ParentID != "" || state.ParentNext != "") || !endpoint.Distinct && state.Seen != "" {
		return false
	}
	if state.ParentID != "" && (!parentIDPattern.MatchString(state.ParentID) || strings.Contains(state.ParentID, "..")) || state.ParentID == "" && state.Next != "" && endpoint.Parent != nil {
		return false
	}
	return validStateTexts(state)
}

var distinctSeenPattern = regexp.MustCompile(`^([A-Za-z0-9_-]{8})*$`)

func validStateTexts(state pageState) bool {
	return (state.Next == "" || validDisplayText(state.Next, maximumContinuation)) && (state.ParentNext == "" || validDisplayText(state.ParentNext, maximumContinuation)) &&
		len(state.Seen) <= MaximumDistinct*distinctDigestLength && distinctSeenPattern.MatchString(state.Seen)
}

func nextStateCursor(subject collection.SubjectBinding, state pageState) (collection.Cursor, bool) {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || !validStateTexts(state) {
		return collection.Cursor{}, false
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > maximumCursorPayload {
		return collection.Cursor{}, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderSaaS, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderSaaS, Version: "cursor_v1", Value: fmt.Sprintf("saas:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, len(cursor.Value) <= 2048
}

func nextCompleteCursor(prior collection.Cursor, subject collection.SubjectBinding) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subject.ID + "\x1fcomplete"))
	return collection.Cursor{Provider: collection.ProviderSaaS, Version: "cursor_v1", Value: fmt.Sprintf("saas:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderSaaS, subject), digest[:8])}
}

func decodeCursorState(payload []byte, state *pageState) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(state) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func deterministicInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("saas\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func nilProxy(proxy Proxy) bool {
	if proxy == nil {
		return true
	}
	adapter, isAdapter := proxy.(*nango.Adapter)
	return isAdapter && adapter == nil
}
