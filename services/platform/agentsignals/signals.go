// Package agentsignals is the reviewed catalog of signs that a workload,
// repository, function or connected application is an AI agent, and the
// matchers the discovery collectors share.
//
// A signal is a class:value token ("env:openai", "package:langgraph"). The
// value always comes from this catalog, never from the provider: a collector
// may read an environment variable name or an image reference to match it,
// but what it records is the catalog token. Nothing here reads a value that
// could be a credential.
package agentsignals

import (
	"path"
	"sort"
	"strings"
)

// MaximumSignals bounds the signals one entity records (the provider schema
// refuses more).
const MaximumSignals = 16

type strength int

const (
	// weak signals say the subject talks to a model or sits next to agent
	// tooling. One weak class alone does not make an agent.
	weak strength = iota + 1
	// strong signals name an agent framework, an agent protocol, an agent
	// platform, or a credential for a model provider.
	strong
)

type entry struct {
	match    string
	token    string
	strength strength
}

// Environment variable names. Only the name is matched; the value is never
// read. Exact names end without an underscore, prefixes end with one.
var environmentNames = []entry{
	{"OPENAI_API_KEY", "openai", strong}, {"OPENAI_BASE_URL", "openai", weak}, {"OPENAI_ORG_ID", "openai", weak}, {"OPENAI_PROJECT", "openai", weak},
	{"AZURE_OPENAI_", "azure_openai", strong},
	{"ANTHROPIC_API_KEY", "anthropic", strong}, {"ANTHROPIC_AUTH_TOKEN", "anthropic", strong}, {"ANTHROPIC_BASE_URL", "anthropic", weak}, {"ANTHROPIC_MODEL", "anthropic", weak}, {"CLAUDE_CODE_", "anthropic", strong},
	{"AWS_BEARER_TOKEN_BEDROCK", "bedrock", strong}, {"BEDROCK_", "bedrock", weak},
	{"GEMINI_API_KEY", "google", strong}, {"GOOGLE_GENAI_USE_VERTEXAI", "google", strong}, {"VERTEXAI_PROJECT", "google", weak}, {"VERTEXAI_LOCATION", "google", weak},
	{"COHERE_API_KEY", "cohere", strong}, {"CO_API_KEY", "cohere", strong}, {"MISTRAL_API_KEY", "mistral", strong}, {"GROQ_API_KEY", "groq", strong},
	{"TOGETHER_API_KEY", "together", strong}, {"FIREWORKS_API_KEY", "fireworks", strong}, {"PERPLEXITY_API_KEY", "perplexity", strong}, {"PERPLEXITYAI_API_KEY", "perplexity", strong},
	{"DEEPSEEK_API_KEY", "deepseek", strong}, {"XAI_API_KEY", "xai", strong}, {"OPENROUTER_API_KEY", "openrouter", strong}, {"REPLICATE_API_TOKEN", "replicate", strong},
	{"HUGGING_FACE_HUB_TOKEN", "huggingface", weak}, {"HUGGINGFACEHUB_API_TOKEN", "huggingface", strong}, {"HF_TOKEN", "huggingface", weak},
	{"LANGCHAIN_", "langchain", strong}, {"LANGSMITH_", "langchain", strong}, {"LANGFUSE_", "langfuse", weak}, {"LITELLM_", "litellm", strong},
	{"MCP_", "mcp", strong}, {"FASTMCP_", "mcp", strong}, {"A2A_", "a2a", strong}, {"CREWAI_", "crewai", strong}, {"AUTOGEN_", "autogen", strong},
	{"OTEL_INSTRUMENTATION_GENAI_", "genai_telemetry", weak},
	{"TAVILY_API_KEY", "tavily", weak}, {"E2B_API_KEY", "e2b", weak}, {"COMPOSIO_API_KEY", "composio", strong}, {"BROWSERBASE_API_KEY", "browserbase", weak},
}

// Container image repository substrings (matched against the lower-case
// reference with the tag and digest removed). Model servers are not listed:
// a model server is not an agent.
var imageSubstrings = []entry{
	{"langchain/langgraph", "langgraph", strong}, {"langflowai/langflow", "langflow", strong}, {"flowiseai/flowise", "flowise", strong}, {"n8nio/n8n", "n8n", strong},
	{"langgenius/dify-", "dify", strong}, {"danny-avila/librechat", "librechat", strong}, {"open-webui/open-webui", "open_webui", strong}, {"letta/letta", "letta", strong},
	{"crewai", "crewai", strong}, {"autogen", "autogen", strong}, {"kagent", "kagent", strong}, {"berriai/litellm", "litellm", weak}, {"agentgateway", "agentgateway", weak},
	{"bedrock-agentcore", "agentcore", strong}, {"claude-code", "claude_code", strong}, {"openhands", "openhands", strong},
}

// Command and argument fragments (matched against each lower-case element of
// a container's command and args).
var processFragments = []entry{
	{"mcp-server-", "mcp_server", strong}, {"@modelcontextprotocol/", "mcp_server", strong}, {"mcp-remote", "mcp_client", strong}, {"fastmcp", "mcp_server", strong},
	{"langgraph", "langgraph", strong}, {"crewai", "crewai", strong}, {"chainlit", "chainlit", strong}, {"langflow", "langflow", strong},
	{"claude-code", "claude_code", strong}, {"@anthropic-ai/claude", "claude_code", strong}, {"@openai/codex", "codex", strong}, {"@google/gemini-cli", "gemini_cli", strong},
	{"litellm", "litellm", weak},
}

// Container ports that agent tooling listens on by default. Always weak.
var defaultPorts = map[int]string{2024: "langgraph", 8123: "langgraph", 4000: "litellm", 7860: "langflow", 8283: "letta", 6274: "mcp_inspector"}

// Packages by ecosystem. Frameworks and agent protocols are strong; a bare
// model SDK is weak.
var packages = map[string][]entry{
	"pypi": {
		{"langchain", "langchain", strong}, {"langgraph", "langgraph", strong}, {"llama-index", "llamaindex", strong}, {"crewai", "crewai", strong}, {"autogen-agentchat", "autogen", strong},
		{"autogen-core", "autogen", strong}, {"pyautogen", "autogen", strong}, {"ag2", "autogen", strong}, {"openai-agents", "openai_agents", strong}, {"claude-agent-sdk", "claude_agent_sdk", strong},
		{"google-adk", "google_adk", strong}, {"strands-agents", "strands", strong}, {"semantic-kernel", "semantic_kernel", strong}, {"agent-framework", "agent_framework", strong},
		{"haystack-ai", "haystack", strong}, {"pydantic-ai", "pydantic_ai", strong}, {"smolagents", "smolagents", strong}, {"agno", "agno", strong}, {"phidata", "agno", strong},
		{"letta", "letta", strong}, {"dspy", "dspy", strong}, {"camel-ai", "camel", strong}, {"griptape", "griptape", strong}, {"browser-use", "browser_use", strong},
		{"bedrock-agentcore", "agentcore", strong}, {"azure-ai-agents", "azure_ai_agents", strong}, {"mcp", "mcp", strong}, {"fastmcp", "mcp", strong},
		{"langchain-mcp-adapters", "mcp", strong}, {"a2a-sdk", "a2a", strong}, {"composio-core", "composio", strong},
		{"openai", "openai", weak}, {"anthropic", "anthropic", weak}, {"google-genai", "google", weak}, {"vertexai", "google", weak}, {"cohere", "cohere", weak},
		{"mistralai", "mistral", weak}, {"groq", "groq", weak}, {"litellm", "litellm", weak}, {"ollama", "ollama", weak},
	},
	"npm": {
		{"langchain", "langchain", strong}, {"@langchain/core", "langchain", strong}, {"@langchain/langgraph", "langgraph", strong}, {"llamaindex", "llamaindex", strong},
		{"@openai/agents", "openai_agents", strong}, {"@anthropic-ai/claude-agent-sdk", "claude_agent_sdk", strong}, {"@mastra/core", "mastra", strong}, {"@google/adk", "google_adk", strong},
		{"@strands-agents/sdk", "strands", strong}, {"@microsoft/agents-hosting", "microsoft_agents", strong}, {"genkit", "genkit", strong}, {"@copilotkit/runtime", "copilotkit", strong},
		{"@voltagent/core", "voltagent", strong}, {"@inngest/agent-kit", "agent_kit", strong}, {"@cloudflare/agents", "cloudflare_agents", strong}, {"@browserbasehq/stagehand", "stagehand", strong},
		{"@azure/ai-agents", "azure_ai_agents", strong}, {"@modelcontextprotocol/sdk", "mcp", strong}, {"mcp-remote", "mcp", strong}, {"fastmcp", "mcp", strong}, {"@a2a-js/sdk", "a2a", strong},
		{"ai", "vercel_ai_sdk", weak}, {"openai", "openai", weak}, {"@anthropic-ai/sdk", "anthropic", weak}, {"@google/genai", "google", weak},
		{"@aws-sdk/client-bedrock-runtime", "bedrock", weak}, {"@aws-sdk/client-bedrock-agent-runtime", "bedrock", strong}, {"@aws-sdk/client-bedrock-agentcore", "agentcore", strong},
	},
	"go": {
		{"github.com/modelcontextprotocol/go-sdk", "mcp", strong}, {"github.com/mark3labs/mcp-go", "mcp", strong}, {"github.com/a2aproject/a2a-go", "a2a", strong}, {"google.golang.org/adk", "google_adk", strong},
		{"github.com/tmc/langchaingo", "langchain", strong}, {"github.com/cloudwego/eino", "eino", strong}, {"github.com/firebase/genkit/go", "genkit", strong},
		{"github.com/aws/aws-sdk-go-v2/service/bedrockagentruntime", "bedrock", strong}, {"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore", "agentcore", strong},
		{"github.com/openai/openai-go", "openai", weak}, {"github.com/sashabaranov/go-openai", "openai", weak}, {"github.com/anthropics/anthropic-sdk-go", "anthropic", weak},
		{"google.golang.org/genai", "google", weak}, {"github.com/aws/aws-sdk-go-v2/service/bedrockruntime", "bedrock", weak},
	},
}

// Repository paths that declare an agent or its tools. AGENTS.md, CLAUDE.md
// and editor instruction files are not listed: they say people use a coding
// assistant on the repository, not that the repository is an agent.
var manifestPaths = []entry{
	{".mcp.json", "mcp_config", strong}, {"mcp.json", "mcp_config", strong}, {".cursor/mcp.json", "mcp_config", strong}, {".vscode/mcp.json", "mcp_config", strong},
	{"claude_desktop_config.json", "mcp_config", strong},
	{"langgraph.json", "langgraph", strong}, {".bedrock_agentcore.yaml", "agentcore", strong}, {"agent-card.json", "a2a_agent_card", strong}, {".well-known/agent.json", "a2a_agent_card", strong},
	{".well-known/agent-card.json", "a2a_agent_card", strong},
}

// DependencyManifests are the file names whose contents PackageSignals can
// read, with the ecosystem each belongs to.
var DependencyManifests = map[string]string{"requirements.txt": "pypi", "pyproject.toml": "pypi", "package.json": "npm", "go.mod": "go"}

// IAM actions that let a principal call a model or an agent. A policy
// statement's Action entries may carry wildcards.
var iamActions = []entry{
	{"bedrock:invokemodel", "bedrock_invoke_model", strong}, {"bedrock:invokemodelwithresponsestream", "bedrock_invoke_model", strong},
	{"bedrock:invokeagent", "bedrock_invoke_agent", strong}, {"bedrock:invokeinlineagent", "bedrock_invoke_agent", strong}, {"bedrock:invokeflow", "bedrock_invoke_agent", strong},
	{"bedrock:retrieveandgenerate", "bedrock_invoke_model", strong},
	{"bedrock-agentcore:invokeagentruntime", "agentcore_invoke", strong}, {"bedrock-agentcore:invokegateway", "agentcore_invoke", strong},
	{"sagemaker:invokeendpoint", "sagemaker_invoke", weak}, {"sagemaker:invokeendpointwithresponsestream", "sagemaker_invoke", weak},
}

// Third-party AI applications, matched as whole words in an application's
// display name. Only names that are distinctive on their own are listed.
var saasApplications = []struct{ name, token, category string }{
	{"chatgpt", "chatgpt", "assistant"}, {"openai", "openai", "assistant"}, {"claude", "claude", "assistant"}, {"anthropic", "anthropic", "assistant"},
	{"microsoft copilot", "microsoft_copilot", "assistant"}, {"microsoft 365 copilot", "microsoft_copilot", "assistant"}, {"copilot studio", "copilot_studio", "agent_builder"},
	{"gemini", "gemini", "assistant"}, {"perplexity", "perplexity", "assistant"}, {"deepseek", "deepseek", "assistant"}, {"mistral", "mistral", "assistant"},
	{"glean", "glean", "enterprise_agent"}, {"moveworks", "moveworks", "enterprise_agent"}, {"notion ai", "notion_ai", "enterprise_agent"}, {"atlassian rovo", "rovo", "enterprise_agent"},
	{"slack ai", "slack_ai", "enterprise_agent"}, {"hebbia", "hebbia", "enterprise_agent"}, {"credal", "credal", "enterprise_agent"},
	{"cursor", "cursor", "coding_agent"}, {"github copilot", "github_copilot", "coding_agent"}, {"windsurf", "windsurf", "coding_agent"}, {"codeium", "codeium", "coding_agent"},
	{"devin", "devin", "coding_agent"}, {"replit", "replit", "coding_agent"}, {"lovable", "lovable", "coding_agent"}, {"sourcegraph cody", "cody", "coding_agent"},
	{"tabnine", "tabnine", "coding_agent"}, {"augment code", "augment", "coding_agent"}, {"claude code", "claude_code", "coding_agent"}, {"openai codex", "codex", "coding_agent"},
	{"zapier agents", "zapier_agents", "agent_builder"}, {"n8n", "n8n", "agent_builder"}, {"lindy", "lindy", "agent_builder"}, {"relevance ai", "relevance_ai", "agent_builder"},
	{"gumloop", "gumloop", "agent_builder"}, {"stack ai", "stack_ai", "agent_builder"}, {"crewai", "crewai", "agent_builder"}, {"langsmith", "langsmith", "agent_builder"},
	{"langchain", "langchain", "agent_builder"}, {"flowise", "flowise", "agent_builder"}, {"dify", "dify", "agent_builder"}, {"composio", "composio", "agent_builder"},
	{"agentforce", "agentforce", "customer_agent"}, {"now assist", "now_assist", "customer_agent"}, {"intercom fin", "intercom_fin", "customer_agent"}, {"decagon", "decagon", "customer_agent"},
	{"sierra ai", "sierra", "customer_agent"}, {"forethought", "forethought", "customer_agent"}, {"cresta", "cresta", "customer_agent"}, {"kore.ai", "kore_ai", "customer_agent"},
	{"otter.ai", "otter", "meeting_agent"}, {"fireflies", "fireflies", "meeting_agent"}, {"read ai", "read_ai", "meeting_agent"}, {"granola", "granola", "meeting_agent"},
	{"zoom ai companion", "zoom_ai_companion", "meeting_agent"}, {"tl;dv", "tldv", "meeting_agent"},
	{"jasper ai", "jasper", "writing_agent"}, {"copy.ai", "copy_ai", "writing_agent"}, {"grammarly", "grammarly", "writing_agent"}, {"harvey", "harvey", "writing_agent"},
	{"browserbase", "browserbase", "browser_agent"}, {"browser use", "browser_use", "browser_agent"}, {"multion", "multion", "browser_agent"},
}

type found map[string]strength

func (signals found) add(class, token string, value strength) {
	key := class + ":" + token
	if signals[key] < value {
		signals[key] = value
	}
}

// Evidence accumulates the signals found on one subject.
type Evidence struct{ signals found }

func (evidence *Evidence) set() found {
	if evidence.signals == nil {
		evidence.signals = found{}
	}
	return evidence.signals
}

// EnvironmentNames records the environment variable names that match.
func (evidence *Evidence) EnvironmentNames(names ...string) {
	for _, name := range names {
		for _, candidate := range environmentNames {
			if name == candidate.match || strings.HasSuffix(candidate.match, "_") && strings.HasPrefix(name, candidate.match) {
				evidence.set().add("env", candidate.token, candidate.strength)
			}
		}
	}
}

// Image records what a container image reference matches.
func (evidence *Evidence) Image(reference string) {
	repository := strings.ToLower(reference)
	if index := strings.Index(repository, "@"); index >= 0 {
		repository = repository[:index]
	}
	if index := strings.LastIndex(repository, ":"); index > strings.LastIndex(repository, "/") {
		repository = repository[:index]
	}
	for _, candidate := range imageSubstrings {
		if strings.Contains(repository, candidate.match) {
			evidence.set().add("image", candidate.token, candidate.strength)
		}
	}
}

// Command records what a container's command and arguments match.
func (evidence *Evidence) Command(elements ...string) {
	for _, element := range elements {
		lower := strings.ToLower(element)
		for _, candidate := range processFragments {
			if strings.Contains(lower, candidate.match) {
				evidence.set().add("process", candidate.token, candidate.strength)
			}
		}
	}
}

// Ports records the default agent-tooling ports among the given ports.
func (evidence *Evidence) Ports(ports ...int) {
	for _, port := range ports {
		if token, ok := defaultPorts[port]; ok {
			evidence.set().add("port", token, weak)
		}
	}
}

// Packages records the listed packages of one ecosystem (pypi, npm or go).
func (evidence *Evidence) Packages(ecosystem string, names ...string) {
	catalog := packages[ecosystem]
	for _, name := range names {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if ecosystem == "pypi" {
			normalized = strings.NewReplacer("_", "-", ".", "-").Replace(normalized)
		}
		for _, candidate := range catalog {
			if normalized == candidate.match {
				evidence.set().add("package", candidate.token, candidate.strength)
			}
		}
	}
}

// Paths records the repository paths that are agent manifests. A manifest
// counts at the repository root or in any directory.
func (evidence *Evidence) Paths(paths ...string) {
	for _, value := range paths {
		clean := strings.ToLower(path.Clean("/" + value))
		for _, candidate := range manifestPaths {
			if strings.HasSuffix(clean, "/"+candidate.match) {
				evidence.set().add("manifest", candidate.token, candidate.strength)
			}
		}
	}
}

// IAMActions records which model or agent invocations the Action entries of
// allowing policy statements grant. Entries may carry * wildcards.
func (evidence *Evidence) IAMActions(actions ...string) {
	for _, action := range actions {
		pattern := strings.ToLower(strings.TrimSpace(action))
		if pattern == "" {
			continue
		}
		for _, candidate := range iamActions {
			if matched, err := path.Match(pattern, candidate.match); err == nil && matched {
				evidence.set().add("iam", candidate.token, candidate.strength)
			}
		}
	}
}

// Application records a third-party AI application by its display name and
// returns its category ("" when the name matches nothing).
func (evidence *Evidence) Application(displayName string) string {
	words := " " + strings.Join(strings.FieldsFunc(strings.ToLower(displayName), func(character rune) bool {
		return !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == ';')
	}), " ") + " "
	category := ""
	for _, candidate := range saasApplications {
		if strings.Contains(words, " "+candidate.name+" ") {
			evidence.set().add("app", candidate.token, strong)
			if category == "" {
				category = candidate.category
			}
		}
	}
	return category
}

// IsAgent reports whether the evidence is enough to list the subject as an
// inferred agent: one strong signal, or weak signals of two different classes.
func (evidence Evidence) IsAgent() bool {
	classes := map[string]bool{}
	for key, value := range evidence.signals {
		if value == strong {
			return true
		}
		classes[key[:strings.Index(key, ":")]] = true
	}
	return len(classes) >= 2
}

// Signals returns the recorded signals in the canonical order the provider
// schema requires: sorted, unique, strong signals kept first when there are
// more than MaximumSignals.
func (evidence Evidence) Signals() []string {
	keys := make([]string, 0, len(evidence.signals))
	for key := range evidence.signals {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if evidence.signals[keys[left]] != evidence.signals[keys[right]] {
			return evidence.signals[keys[left]] > evidence.signals[keys[right]]
		}
		return keys[left] < keys[right]
	})
	if len(keys) > MaximumSignals {
		keys = keys[:MaximumSignals]
	}
	sort.Strings(keys)
	return keys
}

// Discovery is the "discovery" attribute of an agent entity.
type Discovery struct {
	Method   string   `json:"method"`
	Platform string   `json:"platform"`
	Signals  []string `json:"signals"`
}

const (
	// MethodProviderAPI: the provider's control plane lists the object as an agent.
	MethodProviderAPI = "provider_api"
	// MethodInferred: the product concluded it from signals.
	MethodInferred = "inferred"
)

// NewDiscovery builds the attribute; signals are never nil so the JSON is an array.
func NewDiscovery(method, platform string, signals []string) Discovery {
	if signals == nil {
		signals = []string{}
	}
	return Discovery{Method: method, Platform: platform, Signals: signals}
}

// Posture is the posture object every agent entity carries. Facts a collector
// cannot observe stay false: a false fact raises no finding.
type Posture struct {
	HumanCredential        bool   `json:"human_credential"`
	CredentialFingerprint  string `json:"credential_fingerprint"`
	UntrustedInput         bool   `json:"untrusted_input"`
	ProductionWrite        bool   `json:"production_write"`
	ShellExecution         bool   `json:"shell_execution"`
	ProductionCredential   bool   `json:"production_credential"`
	UnrestrictedEgress     bool   `json:"unrestricted_egress"`
	SensitiveDataReach     bool   `json:"sensitive_data_reach"`
	UnapprovedRemoteTool   bool   `json:"unapproved_remote_tool"`
	DestructiveTool        bool   `json:"destructive_tool"`
	RuntimeControl         bool   `json:"runtime_control"`
	ProductionAgent        bool   `json:"production_agent"`
	RuntimePolicySupported bool   `json:"runtime_policy_supported"`
	HostFilesystem         bool   `json:"host_filesystem"`
	Privileged             bool   `json:"privileged"`
	CICDWrite              bool   `json:"cicd_write"`
	ProductionSecretReach  bool   `json:"production_secret_reach"`
	CredentialActive       bool   `json:"credential_active"`
}
