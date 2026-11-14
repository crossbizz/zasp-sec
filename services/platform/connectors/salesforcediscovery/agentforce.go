package salesforcediscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// What an Agentforce agent runs as, what it may do, and the org's guardrail
// switches. Three reads are added to a collection; each is optional: an org
// or a connected app that does not allow it yields an agent without that
// fact, never a failed collection.
//
// 1. The user an agent runs as and that user's permission sets.
// BotDefinition.BotUserId names the user; PermissionSetAssignment lists the
// permission sets (and the profile, which is a permission set owned by a
// profile) assigned to it. The names of the permission sets and two
// permissions of each are read: Modify All Data and View All Data, which
// make the agent a writer of, or a reader of, every record of the org.
//
// 2. The agent's topics and actions. The planner of an agent version is the
// GenAiPlannerDefinition named after it; its topics are the
// GenAiPluginDefinition rows of that planner and its actions the
// GenAiFunctionDefinition rows of those topics. All three are Tooling API
// objects. A topic and an action are each recorded as a tool of the agent
// (salesforce_agent_tool): name and, for an action, what it invokes (a
// flow, Apex, a prompt template, a standard action) and whether it asks for
// confirmation. Instructions, scopes and descriptions are not selected.
//
// 3. The Einstein Trust Layer switches of the org: prompt injection
// detection, input toxicity detection and data masking. They are the
// metadata type EinsteinAISettings, which is not a queryable object: it is
// read with the Metadata API call readMetadata. Salesforce has no read-only
// permission for the Metadata API ("Modify Metadata Through Metadata API
// Functions" or "Modify All Data" is required even to read), so this read
// succeeds only for a connection whose user was given that permission. The
// collector sends readMetadata, a read, and nothing else to that API. When
// the read is refused the switches are unknown, no guardrail finding is
// raised, and the rest of the collection is unaffected.
//
// DOCUMENTED:
//   - https://github.com/forcedotcom/agents (published as @salesforce/agents
//     2.5.0, src/agent.ts): BotDefinition has BotUserId, Type, AgentType;
//     BotVersion has DeveloperName, Status, VersionNumber; BotVersions is the
//     child relationship;
//   - https://github.com/forcedotcom/afv-library/blob/main/skills/
//     agentforce-architecture-analyze/references/soql_fields.md and
//     assets/soql/*.soql (field names checked there against live orgs at API
//     v66.0): GenAiPlannerDefinition (Id, DeveloperName, PlannerType),
//     matched by DeveloperName LIKE '<agent>%\_<version>';
//     GenAiPluginDefinition (Id, DeveloperName, MasterLabel, PluginType)
//     WHERE PlannerId = <planner>; GenAiFunctionDefinition (Id,
//     DeveloperName, MasterLabel, InvocationTargetType,
//     IsConfirmationRequired, PluginId) WHERE PluginId IN (<topics>); all
//     through the Tooling API;
//   - https://github.com/forcedotcom/wsdl (published as @salesforce/types
//     1.9.0, metadata.d.ts): the metadata type EinsteinAISettings with
//     enableAITrustInputToxicityDetection,
//     enableAITrustPromptInjectionDetection and enableTrustPIIMasking; it is
//     not an sObject of the Tooling WSDL (tooling.d.ts), so it cannot be
//     queried;
//   - https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_metadata_perm.htm
//     (as returned by a web search; the page could not be opened from here):
//     Metadata API access needs Modify Metadata Through Metadata API
//     Functions or Modify All Data.
//
// UNVERIFIED (nothing here was run against an org):
//   - PermissionSetAssignment (AssigneeId, PermissionSetId) and PermissionSet
//     (Name, IsOwnedByProfile, PermissionsModifyAllData,
//     PermissionsViewAllData) are standard objects written from the Object
//     Reference as remembered;
//   - the SOAP envelope of readMetadata, the full name EinsteinAI of the
//     settings record and the API version (66.0) at which the three fields
//     exist;
//   - that the Tooling queries above are accepted at the pinned API version
//     of the Data API requests (v62.0).
const (
	salesforceToolingQueryPath  = "/services/data/" + salesforceAPIVersion + "/tooling/query"
	salesforceMetadataSOAPPath  = "/services/Soap/m/66.0"
	salesforceMetadataBodyBytes = int64(256 * 1024)

	salesforceEnrichmentChunk        = 100
	salesforceMaximumUserChunks      = 10
	salesforceMaximumAssignmentPages = 5
	salesforceMaximumToolAgents      = 20
	salesforceMaximumAgentTopics     = 50
	salesforceMaximumAgentActions    = 200
	salesforceMaximumPageTools       = 600
	salesforceMaximumPermissionSets  = 20
	salesforceMaximumNamesBytes      = 1024

	salesforceToolsListed    = "listed"
	salesforceToolsNotListed = "not_listed"
	salesforceToolsPartial   = "partial"
)

var (
	salesforceUserIDPattern        = regexp.MustCompile(`^005[A-Za-z0-9]{15}$`)
	salesforceDeveloperNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
	salesforceTargetTypePattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// salesforceAgentReference is what the enrichment needs of one agent row.
type salesforceAgentReference struct {
	id, developerName, userID, activeVersion string
}

// salesforcePermissions are the permission facts of one agent user.
type salesforcePermissions struct {
	sets                 []string
	modifyAll, viewAll   bool
	truncated, sawNoName bool
}

// salesforceAgentTool is one topic or action of an agent.
type salesforceAgentTool struct {
	id, name, objectType, parent string
	targetType                   string
	confirmation                 *bool
}

// salesforceAgentEnrichment is what the optional reads found for the agents
// of one page.
type salesforceAgentEnrichment struct {
	// moderation is the org's guardrail level (high, medium, low) from the
	// Trust Layer switches, "" when they could not be read.
	moderation string
	// permissions by agent user id; nil when the assignments were not read.
	permissions map[string]salesforcePermissions
	// tools by agent id, and the agents whose tools were read (an agent in
	// toolsRead with no entry has none).
	tools     map[string][]salesforceAgentTool
	toolsRead map[string]string
}

// send performs one bounded request and returns the status and, for 200, the
// bounded body. Unlike get it classifies nothing: an optional read decides
// itself which refusals it tolerates.
func (api *SalesforceCollectionAPI) send(ctx context.Context, token []byte, method, providerURL string, headers map[string]string, body []byte, limit int64) (int, []byte, string, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest, err := http.NewRequestWithContext(bounded, method, providerURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, "", ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/json")
	if token != nil {
		providerRequest.Header.Set("Authorization", "Bearer "+string(token))
	}
	for name, value := range headers {
		providerRequest.Header.Set(name, value)
	}
	response, err := doSalesforceCollectionRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeSalesforceCollectionResponse(response)
		return 0, nil, "", providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil, response.Header.Get("Retry-After"), nil
	}
	payload, ok := readSalesforceCollectionBody(response.Body, limit)
	if !ok {
		return 0, nil, "", providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return http.StatusOK, payload, "", nil
}

// optionalQuery runs one SOQL query of an optional read, on the Data API or
// the Tooling API. refused is true when the org or the connected app does
// not allow it (the object or a field is unknown, or the user may not read
// it): the caller then goes without. Every other failure is classified as
// for the agents query, so a rate limit or an outage retries the page.
func (api *SalesforceCollectionAPI) optionalQuery(ctx context.Context, token []byte, instanceURL, path, soql string, limit int64) (records []json.RawMessage, next string, refused bool, err error) {
	target := instanceURL + path + "?q=" + url.QueryEscape(soql)
	if soql == "" {
		target = instanceURL + path
	}
	status, body, retryAfter, err := api.send(ctx, token, http.MethodGet, target, nil, nil, limit)
	if err != nil {
		return nil, "", false, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound:
		return nil, "", true, nil
	default:
		return nil, "", false, providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
	}
	var response salesforceQueryResponse
	if !decodeSalesforceCollectionResponse(body, &response) || response.Done == nil || response.Records == nil || len(response.Records) > salesforceMaximumPageItems {
		return nil, "", false, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if !*response.Done && response.NextRecordsURL != nil {
		// Only a path under the same query resource is followed.
		if locator, found := strings.CutPrefix(*response.NextRecordsURL, path+"/"); found && salesforceLocatorPattern.MatchString(locator) {
			next = path + "/" + locator
		}
	}
	return response.Records, next, false, nil
}

func salesforceQuoteIDs(ids []string) string {
	quoted := make([]string, len(ids))
	for index, id := range ids {
		quoted[index] = "'" + id + "'"
	}
	return strings.Join(quoted, ",")
}

// fetchSalesforcePermissions reads the permission sets of the agent users of
// one page. nil when the assignments may not be read.
func (api *SalesforceCollectionAPI) fetchSalesforcePermissions(ctx context.Context, token []byte, instanceURL string, references []salesforceAgentReference, limit int64) (map[string]salesforcePermissions, error) {
	unique := map[string]bool{}
	var users []string
	for _, reference := range references {
		if salesforceUserIDPattern.MatchString(reference.userID) && !unique[reference.userID] {
			unique[reference.userID] = true
			users = append(users, reference.userID)
		}
	}
	if len(users) == 0 {
		return nil, nil
	}
	sort.Strings(users)
	result := map[string]salesforcePermissions{}
	for chunk := 0; chunk*salesforceEnrichmentChunk < len(users) && chunk < salesforceMaximumUserChunks; chunk++ {
		ids := users[chunk*salesforceEnrichmentChunk : min((chunk+1)*salesforceEnrichmentChunk, len(users))]
		for _, id := range ids {
			result[id] = salesforcePermissions{}
		}
		path, soql := salesforceQueryPath, "SELECT AssigneeId,PermissionSet.Name,PermissionSet.IsOwnedByProfile,PermissionSet.PermissionsModifyAllData,PermissionSet.PermissionsViewAllData FROM PermissionSetAssignment WHERE AssigneeId IN ("+salesforceQuoteIDs(ids)+") ORDER BY AssigneeId,PermissionSetId"
		for page := 0; page < salesforceMaximumAssignmentPages; page++ {
			records, next, refused, err := api.optionalQuery(ctx, token, instanceURL, path, soql, limit)
			if err != nil {
				return nil, err
			}
			if refused {
				return nil, nil
			}
			for _, raw := range records {
				var assignment struct {
					AssigneeID    string `json:"AssigneeId"`
					PermissionSet *struct {
						Name             string `json:"Name"`
						IsOwnedByProfile bool   `json:"IsOwnedByProfile"`
						ModifyAllData    bool   `json:"PermissionsModifyAllData"`
						ViewAllData      bool   `json:"PermissionsViewAllData"`
					} `json:"PermissionSet"`
				}
				if !decodeSalesforceCollectionResponse(raw, &assignment) {
					return nil, providercollection.StableProviderFailure(collection.FailureMalformed)
				}
				facts, wanted := result[assignment.AssigneeID]
				if !wanted || assignment.PermissionSet == nil {
					continue
				}
				facts.modifyAll = facts.modifyAll || assignment.PermissionSet.ModifyAllData
				facts.viewAll = facts.viewAll || assignment.PermissionSet.ViewAllData
				// A profile's own permission set has a generated name; the
				// profile is counted in the two facts and not listed.
				if !assignment.PermissionSet.IsOwnedByProfile && salesforceDeveloperNamePattern.MatchString(assignment.PermissionSet.Name) {
					facts.sets = append(facts.sets, assignment.PermissionSet.Name)
				}
				result[assignment.AssigneeID] = facts
			}
			if next == "" {
				break
			}
			path, soql = next, ""
		}
	}
	return result, nil
}

// salesforcePermissionSetNames is the recorded form of an agent user's
// permission sets: sorted names joined by commas, bounded.
func salesforcePermissionSetNames(names []string) string {
	unique := map[string]bool{}
	var sorted []string
	for _, name := range names {
		if !unique[name] {
			unique[name] = true
			sorted = append(sorted, name)
		}
	}
	sort.Strings(sorted)
	if len(sorted) > salesforceMaximumPermissionSets {
		sorted = sorted[:salesforceMaximumPermissionSets]
	}
	joined := strings.Join(sorted, ",")
	for len(joined) > salesforceMaximumNamesBytes {
		sorted = sorted[:len(sorted)-1]
		joined = strings.Join(sorted, ",")
	}
	return joined
}

// fetchSalesforceAgentTools reads the topics and actions of the active
// agents of one page, at most budget tools in all. toolsRead says, per
// agent, whether its tools are listed, partial or not listed.
func (api *SalesforceCollectionAPI) fetchSalesforceAgentTools(ctx context.Context, token []byte, instanceURL string, references []salesforceAgentReference, budget int, limit int64) (map[string][]salesforceAgentTool, map[string]string, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	tools, read := map[string][]salesforceAgentTool{}, map[string]string{}
	budget = min(budget, salesforceMaximumPageTools)
	agents := 0
	for _, reference := range references {
		if reference.activeVersion == "" || !salesforceDeveloperNamePattern.MatchString(reference.developerName) || !salesforceDeveloperNamePattern.MatchString(reference.activeVersion) {
			continue
		}
		if agents >= salesforceMaximumToolAgents || budget < 1 {
			read[reference.id] = salesforceToolsNotListed
			continue
		}
		agents++
		// The planner of the agent's active version. An underscore is a
		// wildcard of LIKE and is escaped.
		escape := func(value string) string { return strings.ReplaceAll(value, "_", `\_`) }
		planners, _, refused, err := api.optionalQuery(ctx, token, instanceURL, salesforceToolingQueryPath,
			"SELECT Id,DeveloperName,PlannerType FROM GenAiPlannerDefinition WHERE DeveloperName LIKE '"+escape(reference.developerName)+`%\_`+escape(reference.activeVersion)+"'", limit)
		if err != nil {
			return nil, nil, err
		}
		if refused {
			// The Tooling API or the object is not available to this
			// connection: no agent of the org has its tools read.
			read[reference.id] = salesforceToolsNotListed
			agents = salesforceMaximumToolAgents
			continue
		}
		// The pattern also matches another agent whose name starts the same
		// way: the planner named exactly <agent>_<version> is the agent's,
		// and a single match is taken as it is.
		plannerID := ""
		for _, raw := range planners {
			var planner struct {
				ID            string `json:"Id"`
				DeveloperName string `json:"DeveloperName"`
			}
			if !decodeSalesforceCollectionResponse(raw, &planner) || !salesforceRecordIDPattern.MatchString(planner.ID) {
				return nil, nil, malformed
			}
			if planner.DeveloperName == reference.developerName+"_"+reference.activeVersion || len(planners) == 1 {
				plannerID = planner.ID
			}
		}
		if plannerID == "" {
			read[reference.id] = salesforceToolsNotListed
			continue
		}
		read[reference.id] = salesforceToolsListed
		topics, more, refused, err := api.optionalQuery(ctx, token, instanceURL, salesforceToolingQueryPath, "SELECT Id,DeveloperName,MasterLabel,PluginType FROM GenAiPluginDefinition WHERE PlannerId = '"+plannerID+"' ORDER BY Id", limit)
		if err != nil {
			return nil, nil, err
		}
		if refused {
			read[reference.id] = salesforceToolsNotListed
			continue
		}
		if more != "" || len(topics) > salesforceMaximumAgentTopics {
			read[reference.id], topics = salesforceToolsPartial, topics[:min(len(topics), salesforceMaximumAgentTopics)]
		}
		var topicIDs []string
		for _, raw := range topics {
			tool, ok := decodeSalesforceAgentTool(raw, "agent_topic")
			if !ok {
				return nil, nil, malformed
			}
			if budget < 1 {
				read[reference.id] = salesforceToolsPartial
				break
			}
			budget--
			tools[reference.id] = append(tools[reference.id], tool)
			topicIDs = append(topicIDs, tool.id)
		}
		actions := 0
		for start := 0; start < len(topicIDs); start += salesforceEnrichmentChunk {
			records, more, refused, err := api.optionalQuery(ctx, token, instanceURL, salesforceToolingQueryPath,
				"SELECT Id,DeveloperName,MasterLabel,InvocationTargetType,IsConfirmationRequired,PluginId FROM GenAiFunctionDefinition WHERE PluginId IN ("+salesforceQuoteIDs(topicIDs[start:min(start+salesforceEnrichmentChunk, len(topicIDs))])+") ORDER BY Id", limit)
			if err != nil {
				return nil, nil, err
			}
			if refused || more != "" {
				read[reference.id] = salesforceToolsPartial
			}
			for _, raw := range records {
				tool, ok := decodeSalesforceAgentTool(raw, "agent_action")
				if !ok {
					return nil, nil, malformed
				}
				if budget < 1 || actions >= salesforceMaximumAgentActions {
					read[reference.id] = salesforceToolsPartial
					break
				}
				budget--
				actions++
				tools[reference.id] = append(tools[reference.id], tool)
			}
		}
	}
	return tools, read, nil
}

// decodeSalesforceAgentTool keeps the id, the name and, of an action, what
// it invokes and whether it asks first.
func decodeSalesforceAgentTool(raw json.RawMessage, objectType string) (salesforceAgentTool, bool) {
	var record struct {
		ID                   string  `json:"Id"`
		DeveloperName        string  `json:"DeveloperName"`
		MasterLabel          *string `json:"MasterLabel"`
		InvocationTargetType *string `json:"InvocationTargetType"`
		ConfirmationRequired *bool   `json:"IsConfirmationRequired"`
		PluginID             *string `json:"PluginId"`
	}
	if !decodeSalesforceCollectionResponse(raw, &record) || !salesforceRecordIDPattern.MatchString(record.ID) || !validSalesforceCollectionText(record.DeveloperName, 256) {
		return salesforceAgentTool{}, false
	}
	tool := salesforceAgentTool{id: record.ID, name: record.DeveloperName, objectType: objectType}
	if record.MasterLabel != nil && validSalesforceCollectionText(*record.MasterLabel, 256) {
		tool.name = *record.MasterLabel
	}
	if objectType == "agent_action" {
		if record.PluginID == nil || !salesforceRecordIDPattern.MatchString(*record.PluginID) {
			return salesforceAgentTool{}, false
		}
		tool.parent, tool.confirmation = *record.PluginID, record.ConfirmationRequired
		if record.InvocationTargetType != nil && salesforceTargetTypePattern.MatchString(*record.InvocationTargetType) {
			tool.targetType = *record.InvocationTargetType
		}
	}
	return tool, true
}

// salesforceTrustSettings are the org's Einstein Trust Layer switches; a nil
// member was not stated.
type salesforceTrustSettings struct {
	inputToxicity, promptInjection, piiMasking *bool
}

// moderation is the guardrail level the switches amount to for an agent of
// the org: high when prompts are screened for both prompt injection and
// toxic input, low when for neither, medium when for one. "" when either
// switch is unknown.
func (settings salesforceTrustSettings) moderation() string {
	if settings.inputToxicity == nil || settings.promptInjection == nil {
		return ""
	}
	switch {
	case *settings.inputToxicity && *settings.promptInjection:
		return "high"
	case !*settings.inputToxicity && !*settings.promptInjection:
		return "low"
	}
	return "medium"
}

// fetchSalesforceTrustSettings reads the Trust Layer switches with the
// Metadata API call readMetadata. It never fails a collection: any answer
// other than a readable record leaves the switches unknown.
func (api *SalesforceCollectionAPI) fetchSalesforceTrustSettings(ctx context.Context, token []byte, instanceURL string) salesforceTrustSettings {
	var session bytes.Buffer
	if xml.EscapeText(&session, token) != nil {
		return salesforceTrustSettings{}
	}
	envelope := `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:met="http://soap.sforce.com/2006/04/metadata"><soapenv:Header><met:SessionHeader><met:sessionId>` +
		session.String() + `</met:sessionId></met:SessionHeader></soapenv:Header><soapenv:Body><met:readMetadata><met:type>EinsteinAISettings</met:type><met:fullNames>EinsteinAI</met:fullNames></met:readMetadata></soapenv:Body></soapenv:Envelope>`
	// The session travels in the SOAP header; no Authorization header is set.
	status, body, _, err := api.send(ctx, nil, http.MethodPost, instanceURL+salesforceMetadataSOAPPath, map[string]string{"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": `""`, "Accept": "text/xml"}, []byte(envelope), salesforceMetadataBodyBytes)
	if err != nil || status != http.StatusOK {
		return salesforceTrustSettings{}
	}
	var settings salesforceTrustSettings
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return settings
		}
		if err != nil {
			return salesforceTrustSettings{}
		}
		start, isStart := token.(xml.StartElement)
		if !isStart {
			continue
		}
		var target **bool
		switch start.Name.Local {
		case "enableAITrustInputToxicityDetection":
			target = &settings.inputToxicity
		case "enableAITrustPromptInjectionDetection":
			target = &settings.promptInjection
		case "enableTrustPIIMasking":
			target = &settings.piiMasking
		default:
			continue
		}
		var text string
		if decoder.DecodeElement(&text, &start) != nil || *target != nil {
			return salesforceTrustSettings{}
		}
		switch strings.TrimSpace(text) {
		case "true":
			value := true
			*target = &value
		case "false":
			value := false
			*target = &value
		default:
			return salesforceTrustSettings{}
		}
	}
}
