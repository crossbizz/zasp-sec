package agentsignals

import (
	"reflect"
	"strings"
	"testing"
)

func TestMCPToolRiskIsTheMostDangerousClassOfTheName(t *testing.T) {
	for name, want := range map[string]string{
		"run_shell": MCPToolRiskExecute, "execute_sql": MCPToolRiskExecute, "runCommand": MCPToolRiskExecute, "bash": MCPToolRiskExecute, "invoke_lambda": MCPToolRiskExecute,
		"create_issue": MCPToolRiskWrite, "deleteFile": MCPToolRiskWrite, "push_files": MCPToolRiskWrite, "send-message": MCPToolRiskWrite, "fetch_and_save": MCPToolRiskWrite,
		"fetch": MCPToolRiskNetwork, "browser_navigate": MCPToolRiskNetwork, "get_url": MCPToolRiskNetwork,
		"list_issues": MCPToolRiskRead, "search": MCPToolRiskRead, "db.query": MCPToolRiskRead, "list_runs": MCPToolRiskRead,
		"frobnicate": MCPToolRiskUnclassified,
	} {
		if got := MCPToolRisk(name); got != want {
			t.Errorf("MCPToolRisk(%q)=%q, want %q", name, got, want)
		}
	}
}

func TestParseMCPConfigKeepsIdentityAndNeverSecrets(t *testing.T) {
	secret := "sk-" + "livesecret0123456789abcdef"
	config := `{"mcpServers":{
	 "github":{"command":"/usr/local/bin/npx","args":["-y","@modelcontextprotocol/server-github"],"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"` + secret + `"},"autoApprove":["create_issue","list_issues","` + secret + `"]},
	 "pinned":{"command":"npx","args":["-y","@acme/tools@1.4.2","--api-key","` + secret + `"]},
	 "py":{"command":"uvx","args":["--from","mcp-server-time==2025.1.14","mcp-server-time"]},
	 "pylatest":{"command":"uvx","args":["mcp-server-fetch"]},
	 "docs":{"type":"http","url":"https://user:` + secret + `@MCP.Docs.Example/v1/mcp?session=1"},
	 "open":{"url":"http://tools.internal.example:8080/sse"},
	 "keyed":{"url":"https://mcp.vendor.example/mcp","headers":{"Authorization":"Bearer ` + secret + `"}},
	 "bridge":{"command":"npx","args":["mcp-remote","https://mcp.linear.example/sse"]},
	 "local":{"command":"python","args":["server.py","--token","` + secret + `"]},
	 "image":{"command":"docker","args":["run","-i","--rm","-e","TOKEN","ghcr.io/github/github-mcp-server"]},
	 "` + secret + `":{"command":"node"},
	 "broken":{"command":""}
	}}`
	servers := ParseMCPConfig([]byte(config))
	byName := map[string]MCPServerDeclaration{}
	for _, server := range servers {
		byName[server.Name] = server
		for _, value := range append([]string{server.Name, server.Command, server.Package, server.EndpointHost}, server.Tools...) {
			if strings.Contains(value, "livesecret") || strings.Contains(value, "session") {
				t.Fatalf("a secret or a URL part was kept: %+v", server)
			}
		}
	}
	want := map[string]MCPServerDeclaration{
		"github":   {Name: "github", Transport: MCPTransportStdio, Command: "npx", Package: "@modelcontextprotocol/server-github", Auth: MCPAuthNotApplicable, Tools: []string{"create_issue", "list_issues"}},
		"pinned":   {Name: "pinned", Transport: MCPTransportStdio, Command: "npx", Package: "@acme/tools", PackagePinned: true, Auth: MCPAuthNotApplicable, Tools: []string{}},
		"py":       {Name: "py", Transport: MCPTransportStdio, Command: "uvx", Package: "mcp-server-time", PackagePinned: true, Auth: MCPAuthNotApplicable, Tools: []string{}},
		"pylatest": {Name: "pylatest", Transport: MCPTransportStdio, Command: "uvx", Package: "mcp-server-fetch", Auth: MCPAuthNotApplicable, Tools: []string{}},
		"docs":     {Name: "docs", Transport: MCPTransportHTTP, EndpointHost: "mcp.docs.example", Auth: MCPAuthDeclared, Tools: []string{}},
		"open":     {Name: "open", Transport: MCPTransportSSE, EndpointHost: "tools.internal.example", PlainHTTP: true, Auth: MCPAuthNone, Tools: []string{}},
		"keyed":    {Name: "keyed", Transport: MCPTransportHTTP, EndpointHost: "mcp.vendor.example", Auth: MCPAuthDeclared, Tools: []string{}},
		"bridge":   {Name: "bridge", Transport: MCPTransportStdio, Command: "npx", Package: "mcp-remote", EndpointHost: "mcp.linear.example", Auth: MCPAuthNone, Tools: []string{}},
		"local":    {Name: "local", Transport: MCPTransportStdio, Command: "python", Auth: MCPAuthNotApplicable, Tools: []string{}},
		"image":    {Name: "image", Transport: MCPTransportStdio, Command: "docker", Package: "ghcr.io/github/github-mcp-server", Auth: MCPAuthNotApplicable, Tools: []string{}},
	}
	if !reflect.DeepEqual(byName, want) {
		t.Fatalf("declarations:\n got %+v\nwant %+v", byName, want)
	}
	if vscode := ParseMCPConfig([]byte(`{"servers":{"fs":{"type":"stdio","command":"npx","args":["@modelcontextprotocol/server-filesystem@latest","/"]}}}`)); len(vscode) != 1 || vscode[0].Package != "@modelcontextprotocol/server-filesystem" || vscode[0].PackagePinned {
		t.Fatalf("vscode servers: %+v", vscode)
	}
	for _, document := range []string{``, `[]`, `{"mcpServers":[]}`, `{"mcpServers":{"x":"y"}}`, `not json`} {
		if got := ParseMCPConfig([]byte(document)); len(got) != 0 {
			t.Fatalf("%q declared %+v", document, got)
		}
	}
}

func TestClaudeSettingsToolPermissions(t *testing.T) {
	got := ClaudeSettingsToolPermissions([]byte(`{"permissions":{"allow":["Bash(ls)","mcp__github__create_issue","mcp__github__list_issues","mcp__github"],"deny":["mcp__shell__run_command"]}}`))
	want := map[string][]string{"github": {"create_issue", "list_issues"}, "shell": {"run_command"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions: %+v", got)
	}
}

func TestSkillPathsRecordsPathAndKindOnly(t *testing.T) {
	got := SkillPaths("README.md", ".claude/skills/release/SKILL.md", ".claude/skills/release/run.sh", "skills/triage/SKILL.md", "AGENTS.md", "docs/CLAUDE.md", ".cursor/rules/style.mdc", ".cursorrules", "src/skill.md", "bad\x00path/SKILL.md")
	want := []Skill{{Path: ".claude/skills/release", Kind: SkillKindSkill}, {Path: ".cursor/rules/style.mdc", Kind: SkillKindRules}, {Path: ".cursorrules", Kind: SkillKindRules}, {Path: "AGENTS.md", Kind: SkillKindInstructions}, {Path: "docs/CLAUDE.md", Kind: SkillKindInstructions}, {Path: "skills/triage", Kind: SkillKindSkill}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skills: %+v", got)
	}
}

func TestMCPServerWorkloadAndRemoteHost(t *testing.T) {
	for reference, want := range map[string]bool{"ghcr.io/github/github-mcp-server:v1": true, "mcp/postgres@sha256:abc": true, "acme/jira-mcp": true, "nginx:1.27": false, "acme/mcpx": false} {
		if MCPServerImage(reference) != want {
			t.Errorf("MCPServerImage(%q) != %v", reference, want)
		}
	}
	if !MCPServerCommand("python", "-m", "mcp_server_time") || MCPServerCommand("node", "server.js") {
		t.Fatal("MCPServerCommand")
	}
	if host, ok := IsRemoteMCPHost("MCP.Linear.App."); !ok || host != "mcp.linear.app" {
		t.Fatalf("remote host: %q %v", host, ok)
	}
	if _, ok := IsRemoteMCPHost("api.openai.com"); ok {
		t.Fatal("a model API is not an MCP server")
	}
}
