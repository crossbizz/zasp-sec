package agentsignals

import (
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
)

var signalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$`)

func TestEveryCatalogTokenIsAValidSignal(t *testing.T) {
	check := func(class string, entries []entry) {
		for _, candidate := range entries {
			if !signalPattern.MatchString(class+":"+candidate.token) || candidate.match == "" || candidate.strength != weak && candidate.strength != strong {
				t.Errorf("%s entry %+v is not a valid signal", class, candidate)
			}
		}
	}
	check("env", environmentNames)
	check("image", imageSubstrings)
	check("process", processFragments)
	check("manifest", manifestPaths)
	check("iam", iamActions)
	for _, entries := range packages {
		check("package", entries)
	}
	for _, token := range defaultPorts {
		check("port", []entry{{"port", token, weak}})
	}
	for _, application := range saasApplications {
		check("app", []entry{{application.name, application.token, strong}})
		if application.category == "" {
			t.Errorf("application %q has no category", application.name)
		}
	}
}

func TestEnvironmentNamesMatchExactNamesAndPrefixesOnly(t *testing.T) {
	var evidence Evidence
	evidence.EnvironmentNames("OPENAI_API_KEY", "LANGCHAIN_TRACING_V2", "MY_OPENAI_API_KEY", "DATABASE_URL", "AGENT_NAME")
	if got := evidence.Signals(); !reflect.DeepEqual(got, []string{"env:langchain", "env:openai"}) || !evidence.IsAgent() {
		t.Fatalf("signals = %v", got)
	}
}

func TestOneWeakClassIsNotAnAgentButTwoAre(t *testing.T) {
	var evidence Evidence
	evidence.Ports(4000, 8080)
	if evidence.IsAgent() || !reflect.DeepEqual(evidence.Signals(), []string{"port:litellm"}) {
		t.Fatalf("a default port alone made an agent: %v", evidence.Signals())
	}
	evidence.EnvironmentNames("OPENAI_BASE_URL")
	if !evidence.IsAgent() {
		t.Fatalf("two weak classes did not make an agent: %v", evidence.Signals())
	}
	var none Evidence
	if none.IsAgent() || len(none.Signals()) != 0 {
		t.Fatal("no evidence made an agent")
	}
}

func TestImageIgnoresTagAndDigestAndModelServers(t *testing.T) {
	var evidence Evidence
	evidence.Image("registry.example.com:5000/langchain/langgraph-api:3.11@sha256:abc")
	evidence.Image("ollama/ollama:latest")
	evidence.Image("nginx:crewai")
	if got := evidence.Signals(); !reflect.DeepEqual(got, []string{"image:langgraph"}) {
		t.Fatalf("signals = %v", got)
	}
}

func TestCommandPackagesAndPaths(t *testing.T) {
	var evidence Evidence
	evidence.Command("npx", "-y", "@modelcontextprotocol/server-filesystem", "/data")
	evidence.Packages("pypi", "LangGraph", "pydantic_ai", "requests", "openai")
	evidence.Packages("npm", "@mastra/core", "left-pad")
	evidence.Paths("services/bot/.mcp.json", "AGENTS.md", "docs/mcp.json.md", "langgraph.json")
	want := []string{"manifest:langgraph", "manifest:mcp_config", "package:langgraph", "package:mastra", "package:openai", "package:pydantic_ai", "process:mcp_server"}
	if got := evidence.Signals(); !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %v", got)
	}
}

func TestIAMActionsHonourWildcards(t *testing.T) {
	for actions, want := range map[string][]string{
		"bedrock:InvokeModel":      {"iam:bedrock_invoke_model"},
		"bedrock:Invoke*":          {"iam:bedrock_invoke_agent", "iam:bedrock_invoke_model"},
		"bedrock-agentcore:*":      {"iam:agentcore_invoke"},
		"*":                        {"iam:agentcore_invoke", "iam:bedrock_invoke_agent", "iam:bedrock_invoke_model", "iam:sagemaker_invoke"},
		"s3:GetObject":             {},
		"bedrock:ListAgents":       {},
		"sagemaker:InvokeEndpoint": {"iam:sagemaker_invoke"},
	} {
		var evidence Evidence
		evidence.IAMActions(actions)
		if got := evidence.Signals(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: signals = %v, want %v", actions, got, want)
		}
	}
	var weakOnly Evidence
	weakOnly.IAMActions("sagemaker:InvokeEndpoint")
	if weakOnly.IsAgent() {
		t.Fatal("a SageMaker invocation alone made an agent")
	}
}

func TestApplicationMatchesWholeWords(t *testing.T) {
	for name, want := range map[string]string{
		"ChatGPT Enterprise":    "assistant",
		"Claude (Anthropic)":    "assistant",
		"Cursor":                "coding_agent",
		"Precursor Analytics":   "",
		"Salesforce Agentforce": "customer_agent",
		"Otter.ai":              "meeting_agent",
		"Workday":               "",
		"Microsoft 365 Copilot": "assistant",
		"Geminids Observatory":  "",
	} {
		var evidence Evidence
		if got := evidence.Application(name); got != want || (want != "") != evidence.IsAgent() {
			t.Errorf("%q: category = %q, want %q (signals %v)", name, got, want, evidence.Signals())
		}
	}
}

func TestSignalsAreBoundedSortedAndKeepStrongFirst(t *testing.T) {
	var evidence Evidence
	evidence.Ports(2024, 4000, 7860, 8283, 6274)
	evidence.EnvironmentNames("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "COHERE_API_KEY", "MISTRAL_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY", "PERPLEXITY_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY", "REPLICATE_API_TOKEN", "MCP_SERVER", "A2A_URL", "CREWAI_KEY")
	signals := evidence.Signals()
	if len(signals) != MaximumSignals {
		t.Fatalf("len = %d", len(signals))
	}
	for index, signal := range signals {
		if signal[:4] != "env:" || index > 0 && signals[index-1] >= signal {
			t.Fatalf("signals = %v", signals)
		}
	}
}

func TestPostureAndDiscoveryEncodeTheSchemaShapes(t *testing.T) {
	posture, _ := json.Marshal(Posture{})
	var fields map[string]any
	if json.Unmarshal(posture, &fields) != nil || len(fields) != 18 || fields["credential_fingerprint"] != "" {
		t.Fatalf("posture = %s", posture)
	}
	discovery, _ := json.Marshal(NewDiscovery(MethodProviderAPI, "bedrock_agent", nil))
	if string(discovery) != `{"method":"provider_api","platform":"bedrock_agent","signals":[]}` {
		t.Fatalf("discovery = %s", discovery)
	}
}
