package agentsignals

import (
	"path"
	"strings"
)

// Tier: 1 | Purpose: identify custom SDK and HTTP repository candidates.
// Model: none. Authority: inferred inventory evidence.
// Fallback: absent signals and oversized trees preserve existing results.
func (evidence *Evidence) RepositoryToolLayout(paths []string) {
	if evidence.IsAgent() || len(paths) > 20000 {
		return
	}
	sdk, tools, client, prompt := false, false, false, false
	for key := range evidence.signals {
		sdk = sdk || strings.HasPrefix(key, "package:")
	}
	for _, name := range paths {
		switch repositoryLayoutSignal(name) {
		case "tools":
			tools = true
		case "client":
			client = true
		case "prompt":
			prompt = true
		}
	}
	if tools && (sdk || client && prompt) {
		evidence.set().add("layout", "tool_schema", weak)
		if client && prompt {
			evidence.set().add("layout", "system_prompt", weak)
			evidence.set().add("client", "model_http", weak)
		}
	}
}

func repositoryLayoutSignal(name string) string {
	components := strings.Split(strings.ToLower(name), "/")
	if len(components) > 6 {
		return ""
	}
	for _, part := range components[:len(components)-1] {
		switch part {
		case "vendor", "node_modules", ".venv", "site-packages", "fixtures", "testdata", "tests", "examples", "docs", ".git", "dist", "build":
			return ""
		}
	}
	filename := components[len(components)-1]
	ext := path.Ext(filename)
	switch ext {
	case ".py", ".ts", ".js", ".go", ".json", ".md", ".txt", ".jinja", ".j2":
	default:
		return ""
	}
	stem := strings.ReplaceAll(strings.TrimSuffix(filename, ext), "-", "_")
	switch stem {
	case "tool_schema", "tool_schemas", "function_tools":
		return "tools"
	case "llm_client", "model_client", "chat_completions_client":
		return "client"
	case "system_prompt", "system_instructions":
		return "prompt"
	}
	return ""
}
