package agentsignals

import (
	"sort"
	"strings"
)

// AI surfaces of a SaaS platform: the platform's own API lists the subject
// under a surface that only AI workloads use. A collector records the
// catalog token, never the provider's text.
var saasSurfaces = map[string]strength{
	"model_serving": strong, "assistant": strong,
	// An AI product of the platform itself that is switched on for the
	// tenant.
	"now_assist": strong, "duo": strong, "rovo": strong,
	// A container or credential of a model provider's API organization.
	"api_project": strong, "api_workspace": strong, "api_key": strong, "service_account": strong,
	// A third-party application a person granted access to, or installed,
	// and a source repository its owners tagged as AI.
	"oauth_grant": strong, "marketplace_app": strong, "repository_topic": strong,
}

// Surface records that a SaaS platform's API lists the subject under one of
// its AI surfaces. A token outside the catalog is ignored.
func (evidence *Evidence) Surface(token string) {
	if value, ok := saasSurfaces[token]; ok {
		evidence.set().add("surface", token, value)
	}
}

// Hosted-model providers, matched in the provider name a SaaS platform's API
// states for an object (the external model behind a serving endpoint, for
// instance). The first match wins.
var modelProviders = []struct{ match, token string }{
	{"openai", "openai"}, {"anthropic", "anthropic"}, {"bedrock", "bedrock"}, {"vertex", "google"}, {"google", "google"}, {"gemini", "google"},
	{"cohere", "cohere"}, {"mistral", "mistral"}, {"ai21", "ai21"}, {"llama", "meta"}, {"databricks", "databricks"},
}

// ModelProvider records the hosted-model provider a platform's API states
// for the subject and returns its catalog token ("" when the name matches
// nothing). Only the catalog token is recorded.
func (evidence *Evidence) ModelProvider(name string) string {
	lower := strings.ToLower(name)
	for _, candidate := range modelProviders {
		if strings.Contains(lower, candidate.match) {
			evidence.set().add("model", candidate.token, strong)
			return candidate.token
		}
	}
	return ""
}

// Kinds of tool a platform's API states for an agent it lists (the type of
// each entry of an assistant's tools, for instance). The token says what the
// agent may do, never how the tool is configured.
var agentToolKinds = map[string]string{
	"code_interpreter": "code_interpreter", "shell": "shell", "local_shell": "shell", "apply_patch": "apply_patch",
	"computer_use": "computer_use", "computer_use_preview": "computer_use", "computer": "computer_use", "browser_automation": "computer_use", "browser_automation_preview": "computer_use",
	"file_search": "file_search", "azure_ai_search": "file_search", "retrieval": "file_search",
	"web_search": "web_search", "web_search_preview": "web_search", "bing_grounding": "web_search", "bing_custom_search": "web_search",
	"function": "function", "custom": "function", "openapi": "openapi", "mcp": "mcp", "a2a": "a2a", "a2a_preview": "a2a",
	"image_generation": "image_generation", "memory_search": "memory", "memory": "memory", "tool_search": "tool_search",
	"sharepoint_grounding": "sharepoint", "sharepoint_grounding_preview": "sharepoint", "fabric_dataagent": "fabric", "fabric_dataagent_preview": "fabric",
}

// Tools records the kinds of tool a platform's API states for the subject
// and returns the catalog tokens it recorded, sorted. A kind outside the
// catalog is ignored.
func (evidence *Evidence) Tools(kinds ...string) []string {
	seen := map[string]bool{}
	for _, kind := range kinds {
		if token, ok := agentToolKinds[strings.ToLower(kind)]; ok {
			evidence.set().add("tool", token, weak)
			seen[token] = true
		}
	}
	tokens := make([]string, 0, len(seen))
	for token := range seen {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

// ToolRunsCode reports whether one of the tool tokens Tools returned lets
// the agent run code or drive a computer.
func ToolRunsCode(tokens []string) bool {
	for _, token := range tokens {
		if token == "code_interpreter" || token == "shell" || token == "computer_use" || token == "apply_patch" {
			return true
		}
	}
	return false
}
