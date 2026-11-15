package salesforcediscovery

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

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// salesforceAPIVersion pins the REST API version of every request. The agent
// metadata objects (BotDefinition, BotVersion and the Agentforce fields on
// them) changed between API versions 60 and 68, so the version is pinned and
// the queries in salesforceAgentQueryVariants must be re-checked against a
// real org before the first production use.
const salesforceAPIVersion = "v62.0"

const (
	salesforceQueryPath             = "/services/data/" + salesforceAPIVersion + "/query"
	salesforceOrganizationQuery     = "SELECT Id,Name FROM Organization"
	salesforceMinimumBatchSize      = 200
	salesforceMaximumPageItems      = 2000
	salesforceMaximumResponseBytes  = int64(8 * 1024 * 1024)
	salesforceMaximumErrorBytes     = int64(64 * 1024)
	salesforceMinimumCollectionByte = int64(4096)
	salesforceMaximumCredentialSize = 8192 + 512

	salesforceCredentialPrefix = `{"access_token":"`
	salesforceCredentialMiddle = `","instance_url":"`
	salesforceCredentialSuffix = `"}`
)

// salesforceAgentQueryVariant is one form of the agents query. The first
// agents page tries the variants in order until the org accepts one; the
// accepted index travels in the cursor so later pages parse the same shape.
type salesforceAgentQueryVariant struct {
	soql string
	// activeVersions: the query carries the BotVersions subquery, so the
	// status is known. Without it the status is "UNKNOWN".
	activeVersions bool
	// agentTypes: the query selects Type and AgentType.
	agentTypes bool
}

// The active version's DeveloperName (v1, v2, ...) names the agent's planner,
// from which its topics and actions are read (agentforce.go).
const salesforceActiveVersionSubquery = "(SELECT Id,DeveloperName FROM BotVersions WHERE Status='Active' LIMIT 1)"

// BotUserId, the user the agent runs as, is selected with the Agentforce
// fields Type and AgentType: an org that knows those knows it.
//
// CreatedDate and CreatedBy.Username say when the agent was created and by
// whom: the two audit fields every Salesforce object carries, and the user
// name of the creating user (an address-shaped login). A creator the
// connection may not read comes back null and attributes nothing.
// UNVERIFIED (not run against an org): that BotDefinition exposes the audit
// fields to SOQL like every standard object, and the CreatedDate text form
// (2026-05-01T10:00:00.000+0000).
var salesforceAgentQueryVariants = [...]salesforceAgentQueryVariant{
	{"SELECT Id,DeveloperName,MasterLabel,CreatedDate,CreatedBy.Username,Type,AgentType,BotUserId," + salesforceActiveVersionSubquery + " FROM BotDefinition ORDER BY Id", true, true},
	{"SELECT Id,DeveloperName,MasterLabel,CreatedDate,CreatedBy.Username," + salesforceActiveVersionSubquery + " FROM BotDefinition ORDER BY Id", true, false},
	{"SELECT Id,DeveloperName,MasterLabel,CreatedDate,CreatedBy.Username,Type,AgentType,BotUserId FROM BotDefinition ORDER BY Id", false, true},
	{"SELECT Id,DeveloperName,MasterLabel,CreatedDate,CreatedBy.Username FROM BotDefinition ORDER BY Id", false, false},
}

var salesforceCreatorPattern = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9._%+@:/=-]{0,253}$`)

// salesforceCreator reads the creator of a record from its CreatedBy
// relationship and its CreatedDate. Either may be absent; a creator that is
// not a user name is dropped.
func salesforceCreator(createdBy json.RawMessage, createdDate *string) (string, string) {
	var user struct {
		Username string `json:"Username"`
	}
	if len(createdBy) == 0 || json.Unmarshal(createdBy, &user) != nil || !salesforceCreatorPattern.MatchString(user.Username) {
		return "", ""
	}
	at := ""
	if createdDate != nil {
		for _, layout := range []string{"2006-01-02T15:04:05.000-0700", time.RFC3339} {
			if parsed, err := time.Parse(layout, *createdDate); err == nil {
				at = parsed.UTC().Format(time.RFC3339)
				break
			}
		}
	}
	return user.Username, at
}

// salesforceFirstPlainVariant is the first variant without the subquery.
const salesforceFirstPlainVariant = 2

var (
	salesforcePageCursorPattern     = regexp.MustCompile(`^salesforce:(agents):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	salesforceCompleteCursorPattern = regexp.MustCompile(`^salesforce:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	salesforceOrganizationIDPattern = regexp.MustCompile(`^00D[A-Za-z0-9]{15}$`)
	salesforceRecordIDPattern       = regexp.MustCompile(`^[A-Za-z0-9]{18}$`)
	salesforceLocatorPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	salesforceInstanceURLPattern    = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$`)
)

type salesforcePageState struct {
	Phase   string `json:"p"`
	Lineage int    `json:"l"`
	// Locator is the opaque query locator of the provider's nextRecordsUrl;
	// the host, API version and path around it are never stored.
	Locator string `json:"n,omitempty"`
	// Variant is the accepted salesforceAgentQueryVariants index plus one. It
	// is set exactly when Locator is.
	Variant int `json:"v,omitempty"`
	// Moderation is the org's guardrail level (high, medium, low) the first
	// page read from the Trust Layer switches; "" when they are unknown. It
	// travels with the cursor so that every agents page records it.
	Moderation string `json:"m,omitempty"`
}

type CollectionAPIConfig struct {
	// Transport replaces the bounded HTTPS transport (tests). Nil selects it.
	Transport http.RoundTripper
	Timeout   time.Duration
	// Clock is the UTC clock rate-limit retry times are measured from. Nil
	// selects the system clock.
	Clock func() time.Time
}

type SalesforceCollectionAPI struct {
	client  *http.Client
	timeout time.Duration
	clock   func() time.Time
}

var _ CollectionAPI = (*SalesforceCollectionAPI)(nil)

// NewSalesforceCollectionAPI builds the collector for every Salesforce org:
// the org arrives in the page request subject and the host in the credential
// envelope, and the token is sent to that host only.
func NewSalesforceCollectionAPI(config CollectionAPIConfig) (CollectionAPI, error) {
	if config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	clock := config.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if now := clock(); now.IsZero() || now.Location() != time.UTC {
		return nil, ErrInvalid
	}
	transport := config.Transport
	if transport == nil {
		dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: -1}
		transport = &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 * 1024,
		}
	}
	return &SalesforceCollectionAPI{client: &http.Client{Transport: collection.EffectTransport{Next: transport}, Timeout: config.Timeout, CheckRedirect: rejectSalesforceCollectionRedirect}, timeout: config.Timeout, clock: clock}, nil
}

func (api *SalesforceCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	state, ok := validSalesforcePageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	// token and instanceURL alias the caller's credential, which the caller
	// clears; no decoded copy outlives the request header.
	token, instanceURL, credentialOK := decodeSalesforceCredential(credential)
	if api == nil || api.client == nil || api.clock == nil || ctx == nil || !credentialOK || !ok {
		return CollectionPage{}, ErrInvalid
	}
	var entities, relationships []json.RawMessage
	var next collection.Cursor
	var complete bool
	var err error
	if state.Phase == "org" {
		entities, next, err = api.fetchOrganization(ctx, token, instanceURL, request, state)
	} else {
		entities, relationships, next, complete, err = api.fetchAgents(ctx, token, instanceURL, request, state)
	}
	if err != nil {
		return CollectionPage{}, err
	}
	page, err := NewSalesforceCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || bytes.Contains(page.Raw, credential) || bytes.Contains(page.Raw, token) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || int64(len(page.Raw)) > request.RemainingBytes {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

// CheckCollectionReadiness makes no provider call: the collector is bound to
// no org until a page request and its credential envelope arrive, and the
// token's host is the only host this package ever contacts.
func (api *SalesforceCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || api.clock == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	return nil
}

func (api *SalesforceCollectionAPI) fetchOrganization(ctx context.Context, token []byte, instanceURL string, request CollectionPageRequest, state salesforcePageState) ([]json.RawMessage, collection.Cursor, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	status, body, err := api.get(ctx, token, instanceURL+salesforceQueryPath+"?q="+url.QueryEscape(salesforceOrganizationQuery), 0, salesforceResponseLimit(request))
	if err != nil {
		return nil, collection.Cursor{}, err
	}
	if status != http.StatusOK {
		return nil, collection.Cursor{}, providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, "", api.clock())
	}
	var response salesforceQueryResponse
	if !decodeSalesforceCollectionResponse(body, &response) || response.Done == nil || response.Records == nil {
		return nil, collection.Cursor{}, malformed
	}
	var organization struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	}
	// The token must belong to exactly the org the connection is bound to. A
	// 15-character id is not the 18-character subject id.
	if len(response.Records) != 1 || !*response.Done || response.NextRecordsURL != nil && *response.NextRecordsURL != "" || !decodeSalesforceCollectionResponse(response.Records[0], &organization) || organization.ID != request.Subject.ID {
		return nil, collection.Cursor{}, providercollection.StableProviderFailure(collection.FailureDenied)
	}
	if !validSalesforceCollectionText(organization.Name, 256) {
		return nil, collection.Cursor{}, malformed
	}
	stable, _ := json.Marshal(struct {
		Org  string `json:"org"`
		Name string `json:"name"`
	}{request.Subject.ID, organization.Name})
	// The org's Einstein Trust Layer switches, when the connection may read
	// them (agentforce.go). Unknown switches are simply not recorded.
	trust, err := api.fetchSalesforceTrustSettings(ctx, token, instanceURL)
	if err != nil {
		return nil, collection.Cursor{}, err
	}
	switches := map[string]string{}
	for name, value := range map[string]*bool{"trust_input_toxicity_detection": trust.inputToxicity, "trust_prompt_injection_detection": trust.promptInjection, "trust_pii_masking": trust.piiMasking} {
		if value != nil && *value {
			switches[name] = "enabled"
		} else if value != nil {
			switches[name] = "disabled"
		}
	}
	attributes, _ := json.Marshal(switches)
	entity, err := marshalSalesforceEntity(deterministicSalesforceInventoryID(request.Subject, "salesforce_org", request.Subject.ID), "salesforce_org", "salesforce:org:"+request.Subject.ID, organization.Name, stable, attributes)
	if err != nil {
		return nil, collection.Cursor{}, malformed
	}
	next, ok := nextSalesforceStateCursor(request.Subject, salesforcePageState{Phase: "agents", Lineage: state.Lineage + 1, Moderation: trust.moderation()})
	if !ok {
		return nil, collection.Cursor{}, malformed
	}
	return []json.RawMessage{entity}, next, nil
}

func (api *SalesforceCollectionAPI) fetchAgents(ctx context.Context, token []byte, instanceURL string, request CollectionPageRequest, state salesforcePageState) ([]json.RawMessage, []json.RawMessage, collection.Cursor, bool, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	fail := func(err error) ([]json.RawMessage, []json.RawMessage, collection.Cursor, bool, error) {
		return nil, nil, collection.Cursor{}, false, err
	}
	batch := min(request.RemainingItems, request.RemainingRelationships, salesforceMaximumPageItems)
	if batch < 1 {
		return fail(providercollection.ErrPageCapacity)
	}
	batch = max(batch, salesforceMinimumBatchSize)
	limit := salesforceResponseLimit(request)
	var body []byte
	chosen := -1
	if state.Locator != "" {
		status, continuation, err := api.get(ctx, token, instanceURL+salesforceQueryPath+"/"+state.Locator, batch, limit)
		if err != nil {
			return fail(err)
		}
		if status != http.StatusOK {
			return fail(providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, "", api.clock()))
		}
		body, chosen = continuation, state.Variant-1
	}
	// At most one provider call per variant: every rejection moves forward.
	for index := 0; chosen < 0 && index < len(salesforceAgentQueryVariants); {
		variant := salesforceAgentQueryVariants[index]
		status, attempt, err := api.get(ctx, token, instanceURL+salesforceQueryPath+"?q="+url.QueryEscape(variant.soql), batch, limit)
		if err != nil {
			return fail(err)
		}
		if status == http.StatusOK {
			body, chosen = attempt, index
			break
		}
		code := salesforceErrorCode(attempt)
		switch {
		case variant.activeVersions && (code == "INVALID_TYPE" || code == "MALFORMED_QUERY"):
			// The subquery form is not understood: the fields are not the
			// problem, so go straight to the plain queries.
			index = salesforceFirstPlainVariant
		case code == "INVALID_FIELD":
			index++
		case code == "INVALID_TYPE":
			// BotDefinition itself is unknown: the org has no bots feature.
			return nil, nil, nextSalesforceCompleteCursor(request.Cursor, request.Subject), true, nil
		default:
			return fail(providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, "", api.clock()))
		}
	}
	if chosen < 0 {
		return fail(providercollection.StableProviderFailure(collection.FailureTerminal))
	}
	var response salesforceQueryResponse
	if !decodeSalesforceCollectionResponse(body, &response) || response.Done == nil || response.Records == nil || len(response.Records) > salesforceMaximumPageItems {
		return fail(malformed)
	}
	if len(response.Records) > request.RemainingItems || len(response.Records) > request.RemainingRelationships {
		return fail(providercollection.ErrPageCapacity)
	}
	// The optional reads for the agents of this page: the permission sets of
	// the users they run as, and their topics and actions.
	enrichment := salesforceAgentEnrichment{moderation: state.Moderation}
	if references, valid := salesforceAgentReferences(response.Records); valid && len(references) > 0 {
		var enrichErr error
		if enrichment.permissions, enrichErr = api.fetchSalesforcePermissions(ctx, token, instanceURL, references, limit); enrichErr != nil {
			return fail(enrichErr)
		}
		// Each tool is one entity and one relationship beside its agent's.
		budget := min(request.RemainingItems, request.RemainingRelationships) - len(response.Records)
		if enrichment.tools, enrichment.toolsRead, enrichErr = api.fetchSalesforceAgentTools(ctx, token, instanceURL, references, budget, limit); enrichErr != nil {
			return fail(enrichErr)
		}
	}
	entities, relationships, ok := normalizeSalesforceAgents(request.Subject, salesforceAgentQueryVariants[chosen], response.Records, enrichment)
	if !ok {
		return fail(malformed)
	}
	locator, ok := salesforceNextLocator(response)
	if !ok {
		return fail(malformed)
	}
	if locator == "" {
		return entities, relationships, nextSalesforceCompleteCursor(request.Cursor, request.Subject), true, nil
	}
	next, ok := nextSalesforceStateCursor(request.Subject, salesforcePageState{Phase: "agents", Lineage: state.Lineage + 1, Locator: locator, Variant: chosen + 1, Moderation: state.Moderation})
	if !ok {
		return fail(malformed)
	}
	return entities, relationships, next, false, nil
}

// get performs one bounded GET. It returns the body of a 200 or of a 400
// (whose error code selects a query fallback); every other outcome is
// already classified.
func (api *SalesforceCollectionAPI) get(ctx context.Context, token []byte, providerURL string, batch int, limit int64) (int, []byte, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest, err := http.NewRequestWithContext(bounded, http.MethodGet, providerURL, nil)
	if err != nil {
		return 0, nil, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(token))
	if batch > 0 {
		providerRequest.Header.Set("Sforce-Query-Options", "batchSize="+strconv.Itoa(batch))
	}
	response, err := doSalesforceCollectionRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeSalesforceCollectionResponse(response)
		return 0, nil, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		body, ok := readSalesforceCollectionBody(response.Body, limit)
		if !ok {
			return 0, nil, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		return http.StatusOK, body, nil
	case http.StatusBadRequest:
		body, _ := readSalesforceCollectionBody(response.Body, salesforceMaximumErrorBytes)
		if bounded.Err() != nil {
			return 0, nil, providercollection.ClassifyProviderError(bounded, bounded.Err())
		}
		return http.StatusBadRequest, body, nil
	default:
		return 0, nil, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), api.clock())
	}
}

type salesforceQueryResponse struct {
	Done           *bool             `json:"done"`
	NextRecordsURL *string           `json:"nextRecordsUrl"`
	Records        []json.RawMessage `json:"records"`
}

// salesforceErrorCode is the errorCode of a REST error body
// ([{"message":"…","errorCode":"…"}]). The message is never read.
func salesforceErrorCode(body []byte) string {
	var failures []struct {
		ErrorCode string `json:"errorCode"`
	}
	if !decodeSalesforceCollectionResponse(body, &failures) || len(failures) != 1 {
		return ""
	}
	return failures[0].ErrorCode
}

// salesforceNextLocator accepts a nextRecordsUrl only as a path on the pinned
// API version under the query resource with a bounded opaque locator. An
// absolute URL, another version or another resource is refused, so the token
// never follows a provider-chosen location.
func salesforceNextLocator(response salesforceQueryResponse) (string, bool) {
	next := ""
	if response.NextRecordsURL != nil {
		next = *response.NextRecordsURL
	}
	if *response.Done {
		return "", next == ""
	}
	locator, found := strings.CutPrefix(next, salesforceQueryPath+"/")
	if !found || len(response.Records) == 0 || !salesforceLocatorPattern.MatchString(locator) {
		return "", false
	}
	return locator, true
}

// salesforceAgentReferences reads, of every agent row, what the optional
// reads need: the user it runs as and the name of its active version.
func salesforceAgentReferences(records []json.RawMessage) ([]salesforceAgentReference, bool) {
	references := make([]salesforceAgentReference, 0, len(records))
	for _, raw := range records {
		var bot struct {
			ID            string          `json:"Id"`
			DeveloperName string          `json:"DeveloperName"`
			BotUserID     *string         `json:"BotUserId"`
			BotVersions   json.RawMessage `json:"BotVersions"`
		}
		if !decodeSalesforceCollectionResponse(raw, &bot) {
			return nil, false
		}
		reference := salesforceAgentReference{id: bot.ID, developerName: bot.DeveloperName}
		if bot.BotUserID != nil {
			reference.userID = *bot.BotUserID
		}
		if _, version, ok := salesforceActiveVersion(bot.BotVersions); ok {
			reference.activeVersion = version
		}
		references = append(references, reference)
	}
	return references, true
}

func normalizeSalesforceAgents(subject collection.SubjectBinding, variant salesforceAgentQueryVariant, records []json.RawMessage, enrichment salesforceAgentEnrichment) ([]json.RawMessage, []json.RawMessage, bool) {
	orgEntityID := deterministicSalesforceInventoryID(subject, "salesforce_org", subject.ID)
	entities := make([]json.RawMessage, 0, len(records))
	relationships := make([]json.RawMessage, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, raw := range records {
		var bot struct {
			ID            string          `json:"Id"`
			DeveloperName string          `json:"DeveloperName"`
			MasterLabel   *string         `json:"MasterLabel"`
			Type          *string         `json:"Type"`
			AgentType     *string         `json:"AgentType"`
			BotUserID     *string         `json:"BotUserId"`
			BotVersions   json.RawMessage `json:"BotVersions"`
			CreatedDate   *string         `json:"CreatedDate"`
			CreatedBy     json.RawMessage `json:"CreatedBy"`
		}
		if !decodeSalesforceCollectionResponse(raw, &bot) || !salesforceRecordIDPattern.MatchString(bot.ID) || !validSalesforceCollectionText(bot.DeveloperName, 256) {
			return nil, nil, false
		}
		if _, duplicate := seen[bot.ID]; duplicate {
			return nil, nil, false
		}
		seen[bot.ID] = struct{}{}
		// An empty label falls back to the developer name. Any other label
		// that is not bounded display text (longer than 256 bytes, control
		// characters, surrounding space) refuses the page, as the Okta
		// collector does for an application label.
		name := bot.DeveloperName
		if bot.MasterLabel != nil && *bot.MasterLabel != "" {
			name = *bot.MasterLabel
		}
		if !validSalesforceCollectionText(name, 256) {
			return nil, nil, false
		}
		agentType := ""
		if variant.agentTypes {
			for _, value := range []*string{bot.AgentType, bot.Type} {
				if value == nil || *value == "" {
					continue
				}
				if !validSalesforceCollectionText(*value, 128) {
					return nil, nil, false
				}
				if agentType == "" {
					agentType = *value
				}
			}
		}
		status, active := "UNKNOWN", false
		if variant.activeVersions {
			var ok bool
			if active, _, ok = salesforceActiveVersion(bot.BotVersions); !ok {
				return nil, nil, false
			}
			status = "INACTIVE"
			if active {
				status = "ACTIVE"
			}
		}
		entityID := deterministicSalesforceInventoryID(subject, "salesforce_agent", bot.ID)
		stable, _ := json.Marshal(struct {
			Org        string `json:"org"`
			ObjectType string `json:"object_type"`
			Name       string `json:"name"`
		}{subject.ID, "bot_definition", name})
		// The user the agent runs as and what that user's permission sets
		// allow, when the optional read found them.
		posture := agentsignals.Posture{CredentialActive: active}
		runAsUser, permissionSets := "", ""
		if bot.BotUserID != nil && salesforceUserIDPattern.MatchString(*bot.BotUserID) {
			runAsUser = *bot.BotUserID
			if facts, read := enrichment.permissions[runAsUser]; read {
				// View All Data or Modify All Data: the agent reads every
				// record of the org.
				posture.SensitiveDataReach = facts.viewAll || facts.modifyAll
				permissionSets = salesforcePermissionSetNames(facts.sets)
			}
		}
		createdBy, createdAt := salesforceCreator(bot.CreatedBy, bot.CreatedDate)
		createdBySource := ""
		if createdBy != "" {
			createdBySource = "provider_record"
		}
		attributes, _ := json.Marshal(struct {
			Status    string                 `json:"status"`
			AgentType string                 `json:"agent_type,omitempty"`
			Posture   agentsignals.Posture   `json:"posture"`
			Discovery agentsignals.Discovery `json:"discovery"`
			// Who created the agent and when, from the record's own audit
			// fields.
			CreatedBy       string `json:"created_by,omitempty"`
			CreatedAt       string `json:"created_at,omitempty"`
			CreatedBySource string `json:"created_by_source,omitempty"`
			// RunAsUser is the id of the user the agent runs as and
			// PermissionSets the names of that user's permission sets.
			RunAsUser      string `json:"run_as_user,omitempty"`
			PermissionSets string `json:"permission_sets,omitempty"`
			// Tools says whether the agent's topics and actions were listed.
			Tools string `json:"tools,omitempty"`
			// ContentModeration is the org's guardrail level from the Trust
			// Layer switches, when they could be read.
			ContentModeration string `json:"content_moderation,omitempty"`
		}{status, agentType, posture, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "agentforce", nil), createdBy, createdAt, createdBySource, runAsUser, permissionSets, enrichment.toolsRead[bot.ID], enrichment.moderation})
		entity, err := marshalSalesforceEntity(entityID, "salesforce_agent", "salesforce:bot_definition:"+bot.ID, name, stable, attributes)
		if err != nil {
			return nil, nil, false
		}
		relationship, err := marshalSalesforceRelationship(deterministicSalesforceInventoryID(subject, "contains", bot.ID), "contains", "salesforce:org:"+subject.ID+":"+bot.ID, orgEntityID, entityID, "org_object")
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
		// The agent's topics and actions, each a tool of this agent. The
		// identity of a tool includes its agent, so a topic two agents share
		// is recorded once for each.
		topics := map[string]string{}
		for _, tool := range enrichment.tools[bot.ID] {
			toolID := deterministicSalesforceInventoryID(subject, "salesforce_agent_tool", bot.ID+":"+tool.id)
			toolStable, _ := json.Marshal(struct {
				Org        string `json:"org"`
				ObjectType string `json:"object_type"`
				Name       string `json:"name"`
			}{subject.ID, tool.objectType, tool.name})
			toolAttributes, _ := json.Marshal(struct {
				Status               string `json:"status"`
				TargetType           string `json:"target_type,omitempty"`
				ConfirmationRequired *bool  `json:"confirmation_required,omitempty"`
			}{status, tool.targetType, tool.confirmation})
			toolEntity, err := marshalSalesforceEntity(toolID, "salesforce_agent_tool", "salesforce:"+tool.objectType+":"+bot.ID+":"+tool.id, tool.name, toolStable, toolAttributes)
			if err != nil {
				return nil, nil, false
			}
			// A topic belongs to its agent and an action to its topic.
			owner, relationshipType := entityID, "agent_topic"
			if tool.objectType == "agent_action" {
				var known bool
				if owner, known = topics[tool.parent]; !known {
					return nil, nil, false
				}
				relationshipType = "topic_action"
			} else {
				topics[tool.id] = toolID
			}
			toolRelationship, err := marshalSalesforceRelationship(deterministicSalesforceInventoryID(subject, "contains", bot.ID+":"+tool.id), "contains", "salesforce:"+tool.objectType+":"+bot.ID+":"+tool.id+":owner", owner, toolID, relationshipType)
			if err != nil {
				return nil, nil, false
			}
			entities = append(entities, toolEntity)
			relationships = append(relationships, toolRelationship)
		}
	}
	return entities, relationships, true
}

// salesforceActiveVersion reads the BotVersions subquery result: null when
// the bot has no active version, otherwise a one-record query result. It
// also returns the active version's DeveloperName, "" when the row does not
// state a usable one.
func salesforceActiveVersion(raw json.RawMessage) (bool, string, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, "", true
	}
	var versions struct {
		Done    *bool `json:"done"`
		Records []struct {
			ID            string `json:"Id"`
			DeveloperName string `json:"DeveloperName"`
		} `json:"records"`
	}
	if !decodeSalesforceCollectionResponse(raw, &versions) || versions.Done == nil || !*versions.Done || versions.Records == nil || len(versions.Records) > 1 {
		return false, "", false
	}
	name := ""
	for _, version := range versions.Records {
		if !salesforceRecordIDPattern.MatchString(version.ID) {
			return false, "", false
		}
		if salesforceDeveloperNamePattern.MatchString(version.DeveloperName) {
			name = version.DeveloperName
		}
	}
	return len(versions.Records) == 1, name, true
}

// canonicalSalesforceObject re-encodes a JSON object with its members sorted
// at every depth, the form the snapshot contract requires of stable fields
// and attributes.
func canonicalSalesforceObject(value json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil || decoded == nil {
		return nil, ErrInvalid
	}
	return json.Marshal(decoded)
}

func marshalSalesforceEntity(id, kind, sourceNativeID, displayName string, stable, attributes json.RawMessage) (json.RawMessage, error) {
	stable, stableErr := canonicalSalesforceObject(stable)
	attributes, attributesErr := canonicalSalesforceObject(attributes)
	if stableErr != nil || attributesErr != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stable, attributes})
}

func marshalSalesforceRelationship(id, kind, sourceNativeID, from, to, relationshipType string) (json.RawMessage, error) {
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

func validSalesforcePageRequest(request CollectionPageRequest) (salesforcePageState, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if request.Provider != collection.ProviderSalesforce || request.Subject.Kind != "salesforce_org" || !salesforceOrganizationIDPattern.MatchString(request.Subject.ID) || (!initialCursor && (request.Cursor.Provider != collection.ProviderSalesforce || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < salesforceMinimumCollectionByte {
		return salesforcePageState{}, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return salesforcePageState{Phase: "org", Lineage: 1}, request.Page == 1
	}
	if match := salesforceCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return salesforcePageState{Phase: "org", Lineage: 1}, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderSalesforce, request.Subject)
	}
	match := salesforcePageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || len(match[3]) > 400 || request.Page < 1 {
		return salesforcePageState{}, false
	}
	lineage, err := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state salesforcePageState
	if err != nil || decodeErr != nil || lineage != request.Page || len(payload) < 2 || len(payload) > 300 || !decodeSalesforceCursorState(payload, &state) || state.Phase != match[1] || state.Lineage != lineage || match[4] != providercollection.CursorBinding(collection.ProviderSalesforce, request.Subject, match[1], lineage, match[3]) || !validSalesforcePageState(state) {
		return salesforcePageState{}, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return salesforcePageState{}, false
	}
	return state, true
}

func validSalesforcePageState(state salesforcePageState) bool {
	if state.Phase != "agents" || state.Lineage < 2 || state.Lineage > 1_000_000 || state.Moderation != "" && state.Moderation != "high" && state.Moderation != "medium" && state.Moderation != "low" {
		return false
	}
	if state.Locator == "" {
		return state.Variant == 0
	}
	return salesforceLocatorPattern.MatchString(state.Locator) && state.Variant >= 1 && state.Variant <= len(salesforceAgentQueryVariants)
}

func nextSalesforceStateCursor(subject collection.SubjectBinding, state salesforcePageState) (collection.Cursor, bool) {
	if !validSalesforcePageState(state) {
		return collection.Cursor{}, false
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 300 {
		return collection.Cursor{}, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderSalesforce, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderSalesforce, Version: "cursor_v1", Value: fmt.Sprintf("salesforce:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, len(cursor.Value) <= 2048
}

func nextSalesforceCompleteCursor(prior collection.Cursor, subject collection.SubjectBinding) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subject.ID + "\x1fcomplete"))
	return collection.Cursor{Provider: collection.ProviderSalesforce, Version: "cursor_v1", Value: fmt.Sprintf("salesforce:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderSalesforce, subject), digest[:8])}
}

// decodeSalesforceCredential accepts exactly the worker's compact envelope
// {"access_token":"…","instance_url":"https://….my.salesforce.com"}. Neither
// value may contain a quote or a backslash, so any other member, key order,
// spacing or escape is refused. The results alias credential: nothing is
// copied, so nothing is left to clear.
func decodeSalesforceCredential(credential []byte) ([]byte, string, bool) {
	if len(credential) > salesforceMaximumCredentialSize || !bytes.HasPrefix(credential, []byte(salesforceCredentialPrefix)) || !bytes.HasSuffix(credential, []byte(salesforceCredentialSuffix)) || len(credential) < len(salesforceCredentialPrefix)+len(salesforceCredentialMiddle)+len(salesforceCredentialSuffix) {
		return nil, "", false
	}
	inner := credential[len(salesforceCredentialPrefix) : len(credential)-len(salesforceCredentialSuffix)]
	token, instanceURL, found := bytes.Cut(inner, []byte(salesforceCredentialMiddle))
	if !found || !validSalesforceAccessToken(token) || !salesforceInstanceURLPattern.Match(instanceURL) {
		return nil, "", false
	}
	return token, string(instanceURL), true
}

func validSalesforceAccessToken(value []byte) bool {
	if len(value) < 16 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func validSalesforceCollectionText(value string, maximum int) bool {
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

func deterministicSalesforceInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("salesforce\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func salesforceResponseLimit(request CollectionPageRequest) int64 {
	return min(request.RemainingBytes, salesforceMaximumResponseBytes)
}

func decodeSalesforceCursorState(payload []byte, state *salesforcePageState) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(state) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func decodeSalesforceCollectionResponse(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func readSalesforceCollectionBody(body io.Reader, maximum int64) ([]byte, bool) {
	if maximum < 1 {
		return nil, false
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	return value, err == nil && len(value) > 0 && int64(len(value)) <= maximum
}

func doSalesforceCollectionRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrProvider
		}
	}()
	return client.Do(request)
}

func closeSalesforceCollectionResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func rejectSalesforceCollectionRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
