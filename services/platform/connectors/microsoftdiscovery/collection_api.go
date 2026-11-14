package microsoftdiscovery

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

const (
	microsoftGraphHost              = "graph.microsoft.com"
	microsoftOrganizationPath       = "/v1.0/organization"
	microsoftAgentIdentitiesPath    = "/v1.0/servicePrincipals/microsoft.graph.agentIdentity"
	microsoftServicePrincipalsPath  = "/v1.0/servicePrincipals"
	microsoftCopilotAgentsPath      = "/api/data/v9.2/bots"
	microsoftOrganizationSelect     = "id,displayName"
	microsoftAgentIdentitiesSelect  = "id,appId,displayName,accountEnabled"
	microsoftServicePrincipalSelect = "id,appId,displayName,accountEnabled,servicePrincipalType"
	microsoftCopilotAgentsSelect    = "botid,name,schemaname,statecode,accesscontrolpolicy,authenticationmode"
	microsoftAgentIdentityODataType = "#microsoft.graph.agentIdentity"

	microsoftPhaseTenant            = "tenant"
	microsoftPhaseAgentIdentities   = "agentidentities"
	microsoftPhaseServicePrincipals = "serviceprincipals"
	microsoftPhaseCopilotAgents     = "copilotagents"

	microsoftMaximumPageItems         = 100
	microsoftMaximumResponseBytes     = int64(8 * 1024 * 1024)
	microsoftMinimumCollectionBytes   = int64(4096)
	microsoftMaximumContinuationBytes = 1024
	microsoftMaximumCredentialBytes   = 2*8192 + 512
)

var (
	microsoftPageCursorPattern       = regexp.MustCompile(`^microsoft:(agentidentities|serviceprincipals|copilotagents):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+):([0-9a-f]{16})$`)
	microsoftCompleteCursorPattern   = regexp.MustCompile(`^microsoft:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	microsoftTenantIDPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	microsoftObjectIDPattern         = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	microsoftDataverseURLPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	microsoftDataverseHostPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	microsoftCredentialGraphOnly     = []string{"{", "graph_token", ":", "", "}"}
	microsoftCredentialWithDataverse = []string{"{", "dataverse_token", ":", "", ",", "dataverse_url", ":", "", ",", "graph_token", ":", "", "}"}
)

// microsoftPageState is the payload of a page cursor. The continuation is the
// provider's opaque $skiptoken; the request URL is always rebuilt from the
// phase, never taken from the provider.
type microsoftPageState struct {
	Phase        string `json:"p"`
	Lineage      int    `json:"l"`
	Continuation string `json:"a,omitempty"`
	// Environment is the Dataverse host of the copilotagents phase. A cursor
	// minted for one environment is refused with a credential for another.
	Environment string `json:"e,omitempty"`
}

// microsoftCredential holds the two tokens as views into the caller's
// credential buffer, which the caller clears: no decoded copy of a token
// exists outside the Authorization header of its one request.
type microsoftCredential struct {
	graphToken     []byte
	dataverseToken []byte
	dataverseHost  string
}

type CollectionAPIConfig struct {
	// Transport replaces the bounded HTTPS transport (tests). Nil selects it.
	Transport http.RoundTripper
	// Timeout bounds every provider call (100ms..30s).
	Timeout time.Duration
	// Clock anchors Retry-After. Nil selects the UTC wall clock.
	Clock func() time.Time
}

type MicrosoftCollectionAPI struct {
	client  *http.Client
	timeout time.Duration
	clock   func() time.Time
}

var _ CollectionAPI = (*MicrosoftCollectionAPI)(nil)

// NewMicrosoftCollectionAPI needs nothing tenant-specific: the tenant arrives
// as the page request subject and is attested against Graph on page 1, and
// the Dataverse environment arrives in the credential envelope.
func NewMicrosoftCollectionAPI(config CollectionAPIConfig) (CollectionAPI, error) {
	if config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	roundTripper := config.Transport
	if roundTripper == nil {
		dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: -1}
		roundTripper = &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 * 1024,
		}
	}
	api, err := newMicrosoftCollectionAPI(roundTripper, config.Timeout, config.Clock)
	if err != nil {
		return nil, err
	}
	return api, nil
}

func newMicrosoftCollectionAPI(roundTripper http.RoundTripper, timeout time.Duration, clock func() time.Time) (*MicrosoftCollectionAPI, error) {
	if roundTripper == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &MicrosoftCollectionAPI{client: &http.Client{Transport: collection.EffectTransport{Next: roundTripper}, Timeout: timeout, CheckRedirect: rejectMicrosoftCollectionRedirect}, timeout: timeout, clock: clock}, nil
}

// FetchCollectionPage makes exactly one provider call and returns one page.
func (api *MicrosoftCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	state, ok := validMicrosoftPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	envelope, credentialOK := decodeMicrosoftCredential(credential)
	if api == nil || api.client == nil || ctx == nil || !credentialOK || !ok {
		return CollectionPage{}, ErrInvalid
	}
	if state.Phase == microsoftPhaseCopilotAgents && (envelope.dataverseHost == "" || envelope.dataverseHost != state.Environment) {
		return CollectionPage{}, ErrInvalid
	}
	pageLimit := 1
	if state.Phase != microsoftPhaseTenant {
		// Every listed agent is one entity and one relationship, so the page
		// size is the smaller remaining budget and a page always fits.
		pageLimit = min(microsoftMaximumPageItems, request.RemainingItems, request.RemainingRelationships)
		if pageLimit < 1 {
			return CollectionPage{}, providercollection.ErrPageCapacity
		}
	}
	host, path, token := microsoftGraphHost, "", envelope.graphToken
	query := ""
	switch state.Phase {
	case microsoftPhaseTenant:
		path, query = microsoftOrganizationPath, "$select="+microsoftOrganizationSelect
	case microsoftPhaseAgentIdentities:
		path, query = microsoftAgentIdentitiesPath, "$select="+microsoftAgentIdentitiesSelect+"&$top="+strconv.Itoa(pageLimit)
	case microsoftPhaseServicePrincipals:
		path, query = microsoftServicePrincipalsPath, "$select="+microsoftServicePrincipalSelect+"&$top="+strconv.Itoa(pageLimit)
	case microsoftPhaseCopilotAgents:
		host, path, token = envelope.dataverseHost, microsoftCopilotAgentsPath, envelope.dataverseToken
		query = "$select=" + microsoftCopilotAgentsSelect
	default:
		return CollectionPage{}, ErrInvalid
	}
	if state.Continuation != "" {
		query += "&$skiptoken=" + strings.ReplaceAll(url.QueryEscape(state.Continuation), "+", "%20")
	}
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path+"?"+query, nil)
	if err != nil {
		return CollectionPage{}, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(token))
	if state.Phase == microsoftPhaseCopilotAgents {
		providerRequest.Header.Set("OData-MaxVersion", "4.0")
		providerRequest.Header.Set("OData-Version", "4.0")
		providerRequest.Header.Set("Prefer", "odata.maxpagesize="+strconv.Itoa(pageLimit))
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest = providerRequest.WithContext(bounded)
	response, err := doMicrosoftCollectionRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeMicrosoftCollectionResponse(response)
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	var objects []json.RawMessage
	nextContinuation := ""
	skipped := false
	if response.StatusCode != http.StatusOK {
		// Agent identities are optional. On the FIRST request of that phase a
		// 403 means the application lacks AgentIdentity.Read.All and a 404 or
		// 400 means the tenant's Graph does not serve the Agent ID type cast
		// (the feature is absent): neither says anything about the rest of
		// the tenant, so the phase is skipped with nothing emitted and the
		// collection continues with service principals. The token itself was
		// already proven on the tenant page. The same statuses on a
		// continuation request (the feature evidently exists), and every
		// other status or phase, are failures classified as usual. A 403 on
		// the Copilot Studio phase in particular is a real denial: the
		// customer configured that environment, so its application user must
		// exist.
		skipped = state.Phase == microsoftPhaseAgentIdentities && state.Continuation == "" && (response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusBadRequest)
		if !skipped {
			return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), api.clock())
		}
	} else {
		body, readOK := readMicrosoftCollectionBody(response.Body, microsoftMaximumResponseBytes)
		var document struct {
			NextLink *string            `json:"@odata.nextLink"`
			Value    *[]json.RawMessage `json:"value"`
		}
		if !readOK || !decodeMicrosoftCollectionResponse(body, &document) || document.Value == nil || len(*document.Value) > pageLimit {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		objects = *document.Value
		if document.NextLink != nil {
			nextContinuation, ok = microsoftNextContinuation(*document.NextLink, host, path)
			// A continuation that repeats itself cannot advance, and one that
			// repeats a token would put it in the (encoded) cursor.
			if !ok || state.Phase == microsoftPhaseTenant || nextContinuation == state.Continuation || bytes.Contains([]byte(nextContinuation), envelope.graphToken) || envelope.dataverseToken != nil && bytes.Contains([]byte(nextContinuation), envelope.dataverseToken) {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
		}
	}
	var entities, relationships []json.RawMessage
	switch state.Phase {
	case microsoftPhaseTenant:
		var failure error
		entities, failure = normalizeMicrosoftTenant(request.Subject, objects)
		if failure != nil {
			return CollectionPage{}, failure
		}
	case microsoftPhaseAgentIdentities, microsoftPhaseServicePrincipals:
		entities, relationships, ok = normalizeMicrosoftDirectoryObjects(request.Subject, state.Phase, objects)
	case microsoftPhaseCopilotAgents:
		entities, relationships, ok = normalizeMicrosoftCopilotAgents(request.Subject, envelope.dataverseHost, objects)
	}
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	next, complete, transitionOK := nextMicrosoftCollectionCursor(request.Subject, request.Cursor, state, nextContinuation, envelope.dataverseHost)
	if !transitionOK {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	page, err := NewMicrosoftCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || bytes.Contains(page.Raw, credential) || bytes.Contains(page.Raw, envelope.graphToken) || envelope.dataverseToken != nil && bytes.Contains(page.Raw, envelope.dataverseToken) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || int64(len(page.Raw)) > request.RemainingBytes {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

// CheckCollectionReadiness proves Microsoft Graph is reachable and answers as
// Graph without any credential: an unauthenticated request must be refused
// with a Bearer challenge. The API is not bound to a tenant, so there is no
// issuer to compare.
func (api *MicrosoftCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrProvider
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "https://"+microsoftGraphHost+microsoftOrganizationPath+"?$select=id", nil)
	if err != nil {
		return ErrProvider
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	response, err := doMicrosoftCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeMicrosoftCollectionResponse(response)
		return ErrProvider
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	challenge := response.Header.Get("WWW-Authenticate")
	if response.StatusCode != http.StatusUnauthorized || len(challenge) < 6 || !strings.EqualFold(challenge[:6], "Bearer") {
		return ErrProvider
	}
	return nil
}

// normalizeMicrosoftTenant attests the tenant: the token's own organization
// must be the bound subject. Another tenant's token is a denial, not data.
func normalizeMicrosoftTenant(subject collection.SubjectBinding, objects []json.RawMessage) ([]json.RawMessage, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	if len(objects) != 1 {
		return nil, malformed
	}
	var organization struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if !decodeMicrosoftCollectionResponse(objects[0], &organization) || !microsoftObjectIDPattern.MatchString(organization.ID) {
		return nil, malformed
	}
	if strings.ToLower(organization.ID) != subject.ID {
		return nil, providercollection.StableProviderFailure(collection.FailureDenied)
	}
	if !validMicrosoftCollectionText(organization.DisplayName, 256) {
		return nil, malformed
	}
	stable, _ := json.Marshal(struct {
		Tenant string `json:"tenant"`
		Name   string `json:"name"`
	}{subject.ID, organization.DisplayName})
	entity, err := marshalMicrosoftEntity(deterministicMicrosoftInventoryID(subject, "microsoft_tenant", subject.ID), "microsoft_tenant", "microsoft:tenant:"+subject.ID, organization.DisplayName, stable, json.RawMessage(`{}`))
	if err != nil {
		return nil, malformed
	}
	return []json.RawMessage{entity}, nil
}

type microsoftAgentAttributes struct {
	Status    string                 `json:"status"`
	Posture   agentsignals.Posture   `json:"posture"`
	Discovery agentsignals.Discovery `json:"discovery"`
}

// normalizeMicrosoftDirectoryObjects handles both Graph listings. Every agent
// identity is an agent. A service principal is one only when it is an
// Application principal whose display name is a known AI application; the
// rest of the directory is not inventory of this collector and is dropped
// without its name being judged.
//
// An emitted object needs a usable display name and a boolean accountEnabled;
// one that has neither fails the page (as the Okta collector fails a page on
// an unusable application label) rather than being silently left out.
func normalizeMicrosoftDirectoryObjects(subject collection.SubjectBinding, phase string, objects []json.RawMessage) ([]json.RawMessage, []json.RawMessage, bool) {
	tenantEntityID := deterministicMicrosoftInventoryID(subject, "microsoft_tenant", subject.ID)
	entities := make([]json.RawMessage, 0, len(objects))
	relationships := make([]json.RawMessage, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, raw := range objects {
		var object struct {
			ODataType            string `json:"@odata.type"`
			ID                   string `json:"id"`
			DisplayName          string `json:"displayName"`
			AccountEnabled       *bool  `json:"accountEnabled"`
			ServicePrincipalType string `json:"servicePrincipalType"`
		}
		if !decodeMicrosoftCollectionResponse(raw, &object) || !microsoftObjectIDPattern.MatchString(object.ID) {
			return nil, nil, false
		}
		id := strings.ToLower(object.ID)
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, false
		}
		seen[id] = struct{}{}
		kind, objectType := "microsoft_agent_identity", "agent_identity"
		discovery := agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "entra_agent_identity", nil)
		if phase == microsoftPhaseServicePrincipals {
			// An agent identity is itself a service principal and was already
			// emitted by the previous phase. Graph marks derived types in a
			// base-type listing, so it is recognised here without carrying
			// the earlier IDs in the cursor.
			if object.ServicePrincipalType != "Application" || object.ODataType == microsoftAgentIdentityODataType {
				continue
			}
			var evidence agentsignals.Evidence
			category := evidence.Application(object.DisplayName)
			if category == "" {
				continue
			}
			kind, objectType = "microsoft_ai_application", "service_principal"
			discovery = agentsignals.NewDiscovery(agentsignals.MethodInferred, "saas_"+category, evidence.Signals())
		}
		if !validMicrosoftCollectionText(object.DisplayName, 256) || object.AccountEnabled == nil {
			return nil, nil, false
		}
		status := "INACTIVE"
		if *object.AccountEnabled {
			status = "ACTIVE"
		}
		stable, _ := json.Marshal(struct {
			Tenant     string `json:"tenant"`
			ObjectType string `json:"object_type"`
			Name       string `json:"name"`
		}{subject.ID, objectType, object.DisplayName})
		attributes, _ := json.Marshal(microsoftAgentAttributes{status, agentsignals.Posture{CredentialActive: *object.AccountEnabled}, discovery})
		entityID := deterministicMicrosoftInventoryID(subject, kind, id)
		entity, err := marshalMicrosoftEntity(entityID, kind, "microsoft:"+objectType+":"+id, object.DisplayName, stable, attributes)
		if err != nil {
			return nil, nil, false
		}
		relationship, err := marshalMicrosoftRelationship(deterministicMicrosoftInventoryID(subject, "contains", objectType+":"+id), "microsoft:tenant:"+subject.ID+":"+objectType+":"+id, tenantEntityID, entityID)
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
	}
	return entities, relationships, true
}

func normalizeMicrosoftCopilotAgents(subject collection.SubjectBinding, environment string, objects []json.RawMessage) ([]json.RawMessage, []json.RawMessage, bool) {
	tenantEntityID := deterministicMicrosoftInventoryID(subject, "microsoft_tenant", subject.ID)
	entities := make([]json.RawMessage, 0, len(objects))
	relationships := make([]json.RawMessage, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, raw := range objects {
		var bot struct {
			ID                 string `json:"botid"`
			Name               string `json:"name"`
			StateCode          *int   `json:"statecode"`
			AuthenticationMode *int   `json:"authenticationmode"`
		}
		if !decodeMicrosoftCollectionResponse(raw, &bot) || !microsoftObjectIDPattern.MatchString(bot.ID) || !validMicrosoftCollectionText(bot.Name, 256) || bot.StateCode == nil {
			return nil, nil, false
		}
		id := strings.ToLower(bot.ID)
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, false
		}
		seen[id] = struct{}{}
		active := *bot.StateCode == 0
		status := "INACTIVE"
		if active {
			status = "ACTIVE"
		}
		stable, _ := json.Marshal(struct {
			Environment string `json:"environment"`
			Tenant      string `json:"tenant"`
			ObjectType  string `json:"object_type"`
			Name        string `json:"name"`
		}{environment, subject.ID, "copilot_studio_agent", bot.Name})
		// authenticationmode 1 is "None": anyone who can reach the agent can
		// talk to it, so its input is untrusted.
		posture := agentsignals.Posture{CredentialActive: active, UntrustedInput: bot.AuthenticationMode != nil && *bot.AuthenticationMode == 1}
		attributes, _ := json.Marshal(microsoftAgentAttributes{status, posture, agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "copilot_studio", nil)})
		nativeID := environment + ":" + id
		entityID := deterministicMicrosoftInventoryID(subject, "microsoft_copilot_agent", nativeID)
		entity, err := marshalMicrosoftEntity(entityID, "microsoft_copilot_agent", "microsoft:copilot_studio:"+nativeID, bot.Name, stable, attributes)
		if err != nil {
			return nil, nil, false
		}
		relationship, err := marshalMicrosoftRelationship(deterministicMicrosoftInventoryID(subject, "contains", "copilot_studio:"+nativeID), "microsoft:tenant:"+subject.ID+":copilot_studio:"+nativeID, tenantEntityID, entityID)
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
	}
	return entities, relationships, true
}

// canonicalMicrosoftObject re-encodes a JSON object with its members sorted
// at every depth, the form the snapshot contract requires of stable fields
// and attributes.
func canonicalMicrosoftObject(value json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil || decoded == nil {
		return nil, ErrInvalid
	}
	return json.Marshal(decoded)
}

func marshalMicrosoftEntity(id, kind, sourceNativeID, displayName string, stable, attributes json.RawMessage) (json.RawMessage, error) {
	stable, stableErr := canonicalMicrosoftObject(stable)
	attributes, attributesErr := canonicalMicrosoftObject(attributes)
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

func marshalMicrosoftRelationship(id, sourceNativeID, from, to string) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, "contains", sourceNativeID, from, to, json.RawMessage(`{"type":"tenant_object"}`)})
}

func validMicrosoftPageRequest(request CollectionPageRequest) (microsoftPageState, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if request.Provider != collection.ProviderMicrosoft || request.Subject.Kind != "microsoft_tenant" || !microsoftTenantIDPattern.MatchString(request.Subject.ID) || (!initialCursor && (request.Cursor.Provider != collection.ProviderMicrosoft || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < microsoftMinimumCollectionBytes {
		return microsoftPageState{}, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return microsoftPageState{Phase: microsoftPhaseTenant, Lineage: 1}, request.Page == 1
	}
	if match := microsoftCompleteCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return microsoftPageState{Phase: microsoftPhaseTenant, Lineage: 1}, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderMicrosoft, request.Subject)
	}
	match := microsoftPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 5 || len(match[3]) > 1800 || request.Page < 1 {
		return microsoftPageState{}, false
	}
	lineage, err := strconv.Atoi(match[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(match[3])
	var state microsoftPageState
	if err != nil || decodeErr != nil || lineage != request.Page || len(payload) < 2 || len(payload) > 1350 || json.Unmarshal(payload, &state) != nil || state.Phase != match[1] || state.Lineage != lineage || match[4] != providercollection.CursorBinding(collection.ProviderMicrosoft, request.Subject, match[1], lineage, match[3]) || !validMicrosoftPageState(state) {
		return microsoftPageState{}, false
	}
	canonical, marshalErr := json.Marshal(state)
	if marshalErr != nil || !bytes.Equal(canonical, payload) {
		return microsoftPageState{}, false
	}
	return state, true
}

func validMicrosoftPageState(state microsoftPageState) bool {
	if state.Lineage < 2 || state.Lineage > 1_000_000 || state.Continuation != "" && !validMicrosoftContinuation(state.Continuation) {
		return false
	}
	switch state.Phase {
	case microsoftPhaseAgentIdentities, microsoftPhaseServicePrincipals:
		return state.Environment == ""
	case microsoftPhaseCopilotAgents:
		return microsoftDataverseHostPattern.MatchString(state.Environment)
	default:
		return false
	}
}

// microsoftNextContinuation accepts an @odata.nextLink only when it names the
// same HTTPS host and the same path as the request that produced it, and
// carries exactly one $skiptoken beside (at most) the $select and $top the
// request sent. Only the opaque token is kept.
func microsoftNextContinuation(link, expectedHost, expectedPath string) (string, bool) {
	if len(link) < 1 || len(link) > 4096 {
		return "", false
	}
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme != "https" || parsed.Host != expectedHost || parsed.User != nil || parsed.Opaque != "" || parsed.Path != expectedPath || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query["$skiptoken"]) != 1 {
		return "", false
	}
	for key, values := range query {
		if key != "$skiptoken" && key != "$select" && key != "$top" || len(values) != 1 {
			return "", false
		}
	}
	next := query.Get("$skiptoken")
	return next, validMicrosoftContinuation(next)
}

func nextMicrosoftCollectionCursor(subject collection.SubjectBinding, prior collection.Cursor, state microsoftPageState, nextContinuation, dataverseHost string) (collection.Cursor, bool, bool) {
	nextLineage := state.Lineage + 1
	if nextContinuation != "" {
		if state.Phase == microsoftPhaseTenant {
			return collection.Cursor{}, false, false
		}
		return nextMicrosoftStateCursor(subject, microsoftPageState{Phase: state.Phase, Lineage: nextLineage, Continuation: nextContinuation, Environment: state.Environment})
	}
	switch state.Phase {
	case microsoftPhaseTenant:
		return nextMicrosoftStateCursor(subject, microsoftPageState{Phase: microsoftPhaseAgentIdentities, Lineage: nextLineage})
	case microsoftPhaseAgentIdentities:
		return nextMicrosoftStateCursor(subject, microsoftPageState{Phase: microsoftPhaseServicePrincipals, Lineage: nextLineage})
	case microsoftPhaseServicePrincipals:
		if dataverseHost != "" {
			return nextMicrosoftStateCursor(subject, microsoftPageState{Phase: microsoftPhaseCopilotAgents, Lineage: nextLineage, Environment: dataverseHost})
		}
		return nextMicrosoftCompleteCursor(prior, subject), true, true
	case microsoftPhaseCopilotAgents:
		return nextMicrosoftCompleteCursor(prior, subject), true, true
	default:
		return collection.Cursor{}, false, false
	}
}

func nextMicrosoftCompleteCursor(prior collection.Cursor, subject collection.SubjectBinding) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subject.ID + "\x1fcomplete"))
	return collection.Cursor{Provider: collection.ProviderMicrosoft, Version: "cursor_v1", Value: fmt.Sprintf("microsoft:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderMicrosoft, subject), digest[:8])}
}

func nextMicrosoftStateCursor(subject collection.SubjectBinding, state microsoftPageState) (collection.Cursor, bool, bool) {
	if !validMicrosoftPageState(state) {
		return collection.Cursor{}, false, false
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) > 1350 {
		return collection.Cursor{}, false, false
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	binding := providercollection.CursorBinding(collection.ProviderMicrosoft, subject, state.Phase, state.Lineage, encoded)
	cursor := collection.Cursor{Provider: collection.ProviderMicrosoft, Version: "cursor_v1", Value: fmt.Sprintf("microsoft:%s:%d:%s:%s", state.Phase, state.Lineage, encoded, binding)}
	return cursor, false, len(cursor.Value) <= 2048
}

// decodeMicrosoftCredential reads the credential envelope byte-exactly:
// compact JSON, members sorted, {"graph_token"} alone or with both Dataverse
// members. Values hold no quote or backslash, so the structure is the split
// on quotes and nothing is unescaped or copied.
func decodeMicrosoftCredential(credential []byte) (microsoftCredential, bool) {
	if len(credential) < 16 || len(credential) > microsoftMaximumCredentialBytes {
		return microsoftCredential{}, false
	}
	parts := bytes.Split(credential, []byte{'"'})
	shape := microsoftCredentialGraphOnly
	if len(parts) == len(microsoftCredentialWithDataverse) {
		shape = microsoftCredentialWithDataverse
	}
	if len(parts) != len(shape) {
		return microsoftCredential{}, false
	}
	for index, want := range shape {
		if want != "" && string(parts[index]) != want {
			return microsoftCredential{}, false
		}
	}
	result := microsoftCredential{graphToken: parts[len(parts)-2]}
	if len(shape) == len(microsoftCredentialWithDataverse) {
		result.dataverseToken = parts[3]
		if !validMicrosoftToken(result.dataverseToken) || !microsoftDataverseURLPattern.Match(parts[7]) {
			return microsoftCredential{}, false
		}
		result.dataverseHost = strings.TrimPrefix(string(parts[7]), "https://")
	}
	return result, validMicrosoftToken(result.graphToken)
}

func validMicrosoftToken(value []byte) bool {
	if len(value) < 16 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '\\' {
			return false
		}
	}
	return true
}

func validMicrosoftCollectionText(value string, maximum int) bool {
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

func validMicrosoftContinuation(value string) bool {
	return validMicrosoftCollectionText(value, microsoftMaximumContinuationBytes)
}

func deterministicMicrosoftInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("microsoft\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func decodeMicrosoftCollectionResponse(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func readMicrosoftCollectionBody(body io.Reader, maximum int64) ([]byte, bool) {
	if maximum < 1 {
		return nil, false
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	return value, err == nil && len(value) > 0 && int64(len(value)) <= maximum
}

func doMicrosoftCollectionRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrProvider
		}
	}()
	return client.Do(request)
}

func closeMicrosoftCollectionResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func rejectMicrosoftCollectionRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
