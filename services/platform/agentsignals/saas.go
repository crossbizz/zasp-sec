package agentsignals

import "strings"

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
