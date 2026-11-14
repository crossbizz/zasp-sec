package microsoftdiscovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// Azure AI Foundry agents (Foundry Agent Service).
//
// An agent is not a Resource Manager resource. It belongs to a project of an
// AI Foundry account and is listed on the project's own endpoint (the data
// plane) with a token for https://ai.azure.com. The Azure phase therefore
// does three more things for an AI Foundry account when the credential
// carries that token:
//
//	GET {account}/projects      (Resource Manager) the projects and each project's endpoint
//	GET {account}/raiPolicies   (Resource Manager) the content filter policies of the account
//	GET {project endpoint}/agents?api-version=v1   the agents of each project
//
// Of an agent it records the name, whether it is enabled, its kind, the
// model deployment it names, the kinds of its tools and the content filter
// policy that applies to it. Its instructions, its tool definitions and its
// metadata are in the response and are not decoded.
//
// Guardrail posture. The content filter that applies to an agent is the
// policy its definition names (rai_config.rai_policy_name) or, without one,
// the policy of the model deployment it runs on. The account's policies say
// what each filter does; the agent's content_moderation is derived from the
// four harm categories (microsoftRAIModeration), so an agent whose filter is
// switched off or only annotates is reported by the existing finding rule
// agent_content_moderation_low.
//
// Permissions. Listing projects and policies needs the Azure role Reader the
// Azure phase already asks for. Listing agents is a data action
// (Microsoft.CognitiveServices/accounts/AIServices/agents/read): the
// application needs the role Azure AI User on the project or on the account.
// Without it the project endpoint answers 401 or 403; the account is then
// recorded with agents "access_denied" and the collection continues.
//
// DOCUMENTED:
//   - https://github.com/Azure/azure-sdk-for-js (sdk/ai/ai-projects, published
//     as @azure/ai-projects 2.11.0): GET /agents{?after,api-version,before,
//     kind,limit,order} on the project endpoint, api-version "v1", token
//     scope https://ai.azure.com/.default; the list is {"data":[Agent],
//     "first_id","last_id","has_more"}; an Agent has id, name, state
//     ("enabled"|"disabled") and versions.latest, an AgentVersion with status
//     and definition {kind ("prompt"|"hosted"|"workflow"|"external"|"voice"),
//     rai_config {rai_policy_name}}; a prompt agent's definition has model
//     ("the model deployment to use"), instructions and tools;
//   - https://github.com/Azure/azure-sdk-for-js (sdk/cognitiveservices/
//     arm-cognitiveservices, published as @azure/arm-cognitiveservices
//     9.0.0): GET {account}/projects and GET {account}/raiPolicies, api
//     version 2025-12-01 among the known versions; a project's properties
//     hold endpoints (a map of names to URLs); a policy's properties hold
//     contentFilters [{name, enabled, blocking, severityThreshold, source}];
//     a deployment's properties hold raiPolicyName;
//   - https://learn.microsoft.com/azure/ai-foundry/reference/foundry-project-rest-preview
//     (as returned by a web search; the page could not be opened from here):
//     the project endpoint is https://<account>.services.ai.azure.com/api/
//     projects/<project>.
//
// UNVERIFIED (nothing here was run against a subscription):
//   - the key of the project endpoint in a project's endpoints map. The
//     collector takes any value of the map that is a project URL on
//     services.ai.azure.com and otherwise builds the URL from the account's
//     custom subdomain;
//   - the names of the harm category filters (hate, sexual, violence,
//     selfharm) and the values of severityThreshold (Low, Medium, High);
//   - the built-in role name Azure AI User for the agents data action;
//   - whether the type of a tool entry is in the member "type" for every
//     tool kind.
const (
	microsoftFoundryARMAPI       = "2025-12-01"
	microsoftFoundryAgentsAPI    = "v1"
	microsoftFoundryAgentsPage   = 100
	microsoftFoundryAgentPages   = 5
	microsoftFoundryMaximumReads = 60
	microsoftFoundryMaximumNames = 256

	microsoftFoundryAgentsListed    = "listed"
	microsoftFoundryAgentsNotListed = "not_listed"
	microsoftFoundryAgentsDenied    = "access_denied"
	microsoftFoundryAgentsPartial   = "partial"
)

var (
	microsoftFoundryHostPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}\.services\.ai\.azure\.com$`)
	microsoftFoundryProjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// microsoftRAIFilter is one content filter of a policy.
type microsoftRAIFilter struct {
	Name              string `json:"name"`
	Enabled           *bool  `json:"enabled"`
	Blocking          *bool  `json:"blocking"`
	SeverityThreshold string `json:"severityThreshold"`
}

// microsoftFoundryAgent is what is kept of one listed agent.
type microsoftFoundryAgent struct {
	project, host, name string
	status              string
	enabled             bool
	kind, model         string
	policy              string
	signals             []string
	runsCode            bool
}

// foundryGet sends one GET to a project endpoint with the Foundry token. The
// host has been checked against microsoftFoundryHostPattern: the token goes
// to no other host.
func (api *MicrosoftCollectionAPI) foundryGet(ctx context.Context, token []byte, host, path, query string) (int, []byte, string, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	if !microsoftFoundryHostPattern.MatchString(host) {
		return 0, nil, "", ErrInvalid
	}
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "https://"+host+path+"?"+query, nil)
	if err != nil {
		return 0, nil, "", ErrInvalid
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := doMicrosoftCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeMicrosoftCollectionResponse(response)
		return 0, nil, "", providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", api.clock())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil, response.Header.Get("Retry-After"), nil
	}
	body, ok := readMicrosoftCollectionBody(response.Body, microsoftMaximumResponseBytes)
	if !ok {
		return 0, nil, "", providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return http.StatusOK, body, "", nil
}

// microsoftRAIModeration is the moderation level of a content filter policy,
// from its filters for the four harm categories: "low" when one of them is
// switched off, does not block, or blocks only content of high severity;
// "high" when every one blocks from low severity on; "medium" otherwise. ""
// when the policy states no such filter.
func microsoftRAIModeration(filters []microsoftRAIFilter) string {
	seen, strict, weak := 0, true, false
	for _, filter := range filters {
		switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(filter.Name, "_", ""), "-", "")) {
		case "hate", "sexual", "violence", "selfharm":
		default:
			continue
		}
		seen++
		threshold := strings.ToLower(filter.SeverityThreshold)
		if filter.Enabled != nil && !*filter.Enabled || filter.Blocking != nil && !*filter.Blocking || threshold == "high" {
			weak = true
		}
		strict = strict && threshold == "low"
	}
	switch {
	case seen == 0:
		return ""
	case weak:
		return "low"
	case strict:
		return "high"
	}
	return "medium"
}

// microsoftFoundryPolicyName is the name of a policy an agent or a
// deployment names: the last segment of a resource id, or the name itself.
func microsoftFoundryPolicyName(value string) string {
	if index := strings.LastIndex(value, "/"); index >= 0 {
		value = value[index+1:]
	}
	return strings.ToLower(value)
}

// fetchFoundryAgents reads the projects, the content filter policies and the
// agents of one AI Foundry account. reads counts the requests of the page.
// status is what is recorded on the account: listed, partial (more agents or
// projects than one page reads), access_denied or not_listed.
func (api *MicrosoftCollectionAPI) fetchFoundryAgents(ctx context.Context, envelope microsoftCredential, accountID, subdomain string, deploymentPolicies map[string]string, reads *int) ([]microsoftFoundryAgent, map[string]string, string, error) {
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	if *reads+2 > microsoftFoundryMaximumReads {
		return nil, nil, microsoftFoundryAgentsNotListed, nil
	}
	*reads += 2
	status, body, retryAfter, err := api.armGet(ctx, envelope.armToken, accountID+"/projects", "api-version="+microsoftFoundryARMAPI)
	if err != nil {
		return nil, nil, "", err
	}
	switch {
	case status == http.StatusOK:
	// The account has no projects resource (an older account), or the role
	// covers the account and not its projects.
	case status == http.StatusNotFound || status == http.StatusForbidden || status == http.StatusBadRequest:
		return nil, nil, microsoftFoundryAgentsNotListed, nil
	default:
		return nil, nil, "", providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
	}
	var projects armList
	if !decodeMicrosoftCollectionResponse(body, &projects) || projects.Value == nil {
		return nil, nil, "", malformed
	}
	// The content filter policies; without them the agents are still listed.
	moderation := map[string]string{}
	status, body, retryAfter, err = api.armGet(ctx, envelope.armToken, accountID+"/raiPolicies", "api-version="+microsoftFoundryARMAPI)
	if err != nil {
		return nil, nil, "", err
	}
	switch {
	case status == http.StatusOK:
		var policies armList
		if !decodeMicrosoftCollectionResponse(body, &policies) || policies.Value == nil {
			return nil, nil, "", malformed
		}
		for _, raw := range *policies.Value {
			var policy struct {
				Name       string `json:"name"`
				Properties struct {
					ContentFilters []microsoftRAIFilter `json:"contentFilters"`
				} `json:"properties"`
			}
			if !decodeMicrosoftCollectionResponse(raw, &policy) {
				return nil, nil, "", malformed
			}
			if level := microsoftRAIModeration(policy.Properties.ContentFilters); level != "" && policy.Name != "" {
				moderation[microsoftFoundryPolicyName(policy.Name)] = level
			}
		}
	case status == http.StatusNotFound || status == http.StatusForbidden || status == http.StatusBadRequest:
	default:
		return nil, nil, "", providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
	}
	result := microsoftFoundryAgentsListed
	var agents []microsoftFoundryAgent
	seen := map[string]bool{}
	for _, raw := range *projects.Value {
		var project struct {
			Name       string `json:"name"`
			Properties struct {
				Endpoints map[string]string `json:"endpoints"`
			} `json:"properties"`
		}
		if !decodeMicrosoftCollectionResponse(raw, &project) {
			return nil, nil, "", malformed
		}
		// A child resource may be named "<account>/<project>".
		name := project.Name
		if index := strings.LastIndex(name, "/"); index >= 0 {
			name = name[index+1:]
		}
		if !microsoftFoundryProjectPattern.MatchString(name) || seen[strings.ToLower(name)] {
			return nil, nil, "", malformed
		}
		seen[strings.ToLower(name)] = true
		host := microsoftFoundryProjectHost(project.Properties.Endpoints, name, subdomain)
		if host == "" {
			result = microsoftFoundryAgentsPartial
			continue
		}
		after := ""
		for page := 0; ; page++ {
			if page >= microsoftFoundryAgentPages || *reads >= microsoftFoundryMaximumReads || len(agents) >= microsoftFoundryMaximumNames {
				result = microsoftFoundryAgentsPartial
				break
			}
			*reads++
			query := "api-version=" + microsoftFoundryAgentsAPI + "&limit=" + strconv.Itoa(microsoftFoundryAgentsPage) + "&order=asc"
			if after != "" {
				query += "&after=" + url.QueryEscape(after)
			}
			status, body, retryAfter, err := api.foundryGet(ctx, envelope.aiToken, host, "/api/projects/"+name+"/agents", query)
			if err != nil {
				return nil, nil, "", err
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				// The application has no role that may list the project's agents.
				return nil, nil, microsoftFoundryAgentsDenied, nil
			}
			if status == http.StatusNotFound || status == http.StatusBadRequest {
				// The project was deleted since the list, or its endpoint
				// does not serve this API version.
				result = microsoftFoundryAgentsPartial
				break
			}
			if status != http.StatusOK {
				return nil, nil, "", providercollection.ClassifyProviderHTTPFailure(ctx, nil, status, retryAfter, api.clock())
			}
			var list struct {
				Data    *[]json.RawMessage `json:"data"`
				LastID  string             `json:"last_id"`
				HasMore bool               `json:"has_more"`
			}
			if !decodeMicrosoftCollectionResponse(body, &list) || list.Data == nil || len(*list.Data) > microsoftFoundryAgentsPage {
				return nil, nil, "", malformed
			}
			for _, rawAgent := range *list.Data {
				agent, ok := decodeMicrosoftFoundryAgent(rawAgent, name, host, deploymentPolicies)
				if !ok || seen[strings.ToLower(name)+"/"+strings.ToLower(agent.name)] {
					return nil, nil, "", malformed
				}
				seen[strings.ToLower(name)+"/"+strings.ToLower(agent.name)] = true
				agents = append(agents, agent)
			}
			if !list.HasMore || len(*list.Data) == 0 {
				break
			}
			// A list that states no next id, or repeats one, cannot advance.
			if list.LastID == "" || list.LastID == after || !validMicrosoftContinuation(list.LastID) {
				return nil, nil, "", malformed
			}
			after = list.LastID
		}
	}
	return agents, moderation, result, nil
}

// microsoftFoundryProjectHost is the host of a project's endpoint: the host
// of the endpoint the project states for itself, when that is a project URL
// on services.ai.azure.com, otherwise the account's custom subdomain there.
// "" when neither names a host the token may be sent to.
func microsoftFoundryProjectHost(endpoints map[string]string, project, subdomain string) string {
	names := make([]string, 0, len(endpoints))
	for name := range endpoints {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parsed, err := url.Parse(endpoints[name])
		if err != nil || parsed.Scheme != "https" || parsed.Port() != "" || parsed.User != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if microsoftFoundryHostPattern.MatchString(host) && strings.EqualFold(strings.TrimSuffix(parsed.Path, "/"), "/api/projects/"+project) {
			return host
		}
	}
	if host := strings.ToLower(subdomain) + ".services.ai.azure.com"; subdomain != "" && microsoftFoundryHostPattern.MatchString(host) {
		return host
	}
	return ""
}

// decodeMicrosoftFoundryAgent keeps the name, the state, the kind, the model
// deployment, the tool kinds and the policy of one agent. The definition's
// instructions and the tools' own members have no field to land in.
func decodeMicrosoftFoundryAgent(raw json.RawMessage, project, host string, deploymentPolicies map[string]string) (microsoftFoundryAgent, bool) {
	var agent struct {
		Name     string `json:"name"`
		State    string `json:"state"`
		Versions struct {
			Latest struct {
				Status     string `json:"status"`
				Definition struct {
					Kind      string `json:"kind"`
					Model     string `json:"model"`
					RAIConfig struct {
						PolicyName string `json:"rai_policy_name"`
					} `json:"rai_config"`
					Tools []struct {
						Type string `json:"type"`
					} `json:"tools"`
				} `json:"definition"`
			} `json:"latest"`
		} `json:"versions"`
	}
	if !decodeMicrosoftCollectionResponse(raw, &agent) || !validMicrosoftCollectionText(agent.Name, 256) || strings.ContainsAny(agent.Name, "/") {
		return microsoftFoundryAgent{}, false
	}
	result := microsoftFoundryAgent{project: project, host: host, name: agent.Name, status: "UNKNOWN"}
	definition := agent.Versions.Latest.Definition
	switch {
	case agent.State == "enabled", agent.State == "" && agent.Versions.Latest.Status == "active":
		result.status, result.enabled = "ACTIVE", true
	case agent.State == "disabled":
		result.status = "INACTIVE"
	}
	switch definition.Kind {
	case "prompt", "hosted", "workflow", "external", "voice":
		result.kind = definition.Kind
	}
	if validMicrosoftCollectionText(definition.Model, 128) {
		result.model = definition.Model
	}
	kinds := make([]string, 0, len(definition.Tools))
	for _, tool := range definition.Tools {
		kinds = append(kinds, tool.Type)
	}
	var evidence agentsignals.Evidence
	result.runsCode = agentsignals.ToolRunsCode(evidence.Tools(kinds...))
	result.signals = evidence.Signals()
	// The policy the agent names, or the one of the deployment it runs on.
	result.policy = microsoftFoundryPolicyName(definition.RAIConfig.PolicyName)
	if result.policy == "" {
		result.policy = deploymentPolicies[strings.ToLower(definition.Model)]
	}
	return result, true
}
