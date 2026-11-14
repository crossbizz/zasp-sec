package agentsignals

import (
	"sort"
	"strings"
)

// What an agent's role may do, read from the Action entries of its policies'
// allowing statements. Only action names from this catalog are returned;
// nothing of a policy document is kept.

// aiActionNames are the catalog's model and agent invocation actions in
// their IAM spelling, sorted.
var aiActionNames = []string{
	"bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeGateway",
	"bedrock:InvokeAgent", "bedrock:InvokeFlow", "bedrock:InvokeInlineAgent", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:RetrieveAndGenerate",
	"sagemaker:InvokeEndpoint", "sagemaker:InvokeEndpointWithResponseStream",
}

// invocationActions maps an audit event name to the IAM action that
// authorizes the call. Converse is authorized by bedrock:InvokeModel and
// ConverseStream by bedrock:InvokeModelWithResponseStream (from the service
// authorization reference as remembered: UNVERIFIED).
var invocationActions = map[string]string{
	"invokemodel": "bedrock:InvokeModel", "converse": "bedrock:InvokeModel",
	"invokemodelwithresponsestream": "bedrock:InvokeModelWithResponseStream", "conversestream": "bedrock:InvokeModelWithResponseStream",
}

// IAMPatternMatches reports whether an IAM pattern (with * and ? wildcards,
// which also match "/" and ":") matches a value. Actions compare without
// regard to case; pass both lower-cased for that.
func IAMPatternMatches(pattern, value string) bool {
	// Iterative glob with backtracking on the last star.
	p, v, star, mark := 0, 0, -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, v
			p++
		case star >= 0:
			p = star + 1
			mark++
			v = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// GrantedAIActions returns the catalog's model and agent invocation actions
// that the given Action entries grant, sorted. An entry that names no service
// ("*", "*:Invoke*") is an administrative grant and is not expanded: it is
// reported by its own check.
func GrantedAIActions(patterns ...string) []string {
	granted := map[string]bool{}
	for _, raw := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		service, _, named := strings.Cut(pattern, ":")
		if !named || service == "" || strings.ContainsAny(service, "*?") {
			continue
		}
		for _, action := range aiActionNames {
			if IAMPatternMatches(pattern, strings.ToLower(action)) {
				granted[action] = true
			}
		}
	}
	actions := make([]string, 0, len(granted))
	for action := range granted {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}

// InvocationAction returns the IAM action that authorizes a recorded audit
// event, for the events whose use the audit log's lookup can show.
func InvocationAction(eventName string) (string, bool) {
	action, ok := invocationActions[strings.ToLower(eventName)]
	return action, ok
}

// ObservableAIAction reports whether the audit log's event lookup can show
// the use of an action. An action it cannot show is never called unused.
func ObservableAIAction(action string) bool {
	for _, observable := range invocationActions {
		if observable == action {
			return true
		}
	}
	return false
}

// dataServices are the data services whose grants are followed to data
// stores, by IAM service prefix.
var dataServices = map[string]bool{"s3": true, "dynamodb": true, "secretsmanager": true, "ssm": true, "rds-data": true}

var dataReadPrefixes = []string{"get", "list", "describe", "query", "scan", "batchget", "select", "head"}

// DataAction classifies one Action entry of an allowing statement. It
// returns the data service and whether the entry can only read ("read") or
// can change or delete data ("write"). An entry with a wildcard that is not a
// plain read prefix ("s3:*", "dynamodb:*Item") counts as write.
func DataAction(action string) (service, access string, ok bool) {
	lower := strings.ToLower(strings.TrimSpace(action))
	service, name, named := strings.Cut(lower, ":")
	if !named || !dataServices[service] || name == "" {
		return "", "", false
	}
	// Systems Manager is a data store only through its parameters.
	if service == "ssm" && !strings.Contains(name, "parameter") && name != "*" {
		return "", "", false
	}
	for _, prefix := range dataReadPrefixes {
		if strings.HasPrefix(name, prefix) {
			return service, "read", true
		}
	}
	return service, "write", true
}
