package githubdiscovery

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// The whole collection of an installation, driven by the shared collection
// client exactly as the worker drives it, ends in a typed snapshot in which
// the inferred agent project is an agent related to its repository.
func TestCollectionClientCompletesATypedSnapshotWithAnAgentProject(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{
		{status: http.StatusOK, body: `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`},
		{status: http.StatusOK, body: `{"total_count":1,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":false,"default_branch":"main","permissions":{"admin":false,"maintain":false,"pull":true,"push":false,"triage":false},"owner":{"login":"acme"}}]}`},
		agentProjectTree(false, agentProjectBlob("README.md", 10), agentProjectDirectory("tools"), agentProjectBlob("tools/.mcp.json", 80), agentProjectBlob(".claude/settings.json", 60), agentProjectBlob(".claude/skills/release/SKILL.md", 40), agentProjectBlob("AGENTS.md", 30),
			// A script in the skill's directory, a desktop extension manifest
			// and the CODEOWNERS file: read in this order after the
			// configuration (manifest, settings, CODEOWNERS).
			strings.Replace(agentProjectBlob(".claude/skills/release/run", 20), `"100644"`, `"100755"`, 1), agentProjectBlob("ext/manifest.json", 200), agentProjectBlob(".github/CODEOWNERS", 40)),
		agentProjectContent(typedSnapshotMCPConfig),
		agentProjectContent(typedSnapshotDXTManifest),
		agentProjectContent(`{"permissions":{"allow":["mcp__tracker__create_issue","mcp__shell__run_command","mcp__unknown__read"]}}`),
		agentProjectContent("# owners\n/.claude/ @acme/agents " + typedSnapshotMCPSecret + "\n"),
		{status: http.StatusOK, body: `{"total_count":1,"workflows":[{"id":801,"name":"Build and deploy","path":".github/workflows/build-and-deploy.yml","state":"active"}]}`},
		{status: http.StatusOK, body: `{"total_count":1,"environments":[{"id":901,"name":"production"}]}`},
	}}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := typedSnapshotRequest(t, collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/installation/customer-0001", agentProjectSubject)
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte(agentProjectCredential))
	byKind, relationships := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"github_installation":  {"asset", 9000},
		"github_app":           {"tool", 9000},
		"github_organization":  {"asset", 9000},
		"github_permission":    {"asset", 9000},
		"github_repository":    {"tool", 9000},
		"github_workflow":      {"tool", 9000},
		"github_environment":   {"asset", 9000},
		"github_agent_project": {"agent", 6000},
		"github_mcp_server":    {"tool", 9000},
		"github_mcp_tool":      {"tool", 9000},
		"github_agent_skill":   {"asset", 9000},
	})
	requireTypedSnapshotMCP(t, byKind, relationships)
	if len(roundTripper.requests) != 9 || len(driver.objects) != 6 {
		t.Fatalf("provider calls = %d, artifacts = %d", len(roundTripper.requests), len(driver.objects))
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(agentProjectCredential)) {
			t.Fatalf("artifact %s stores the credential", key)
		}
	}
	if len(byKind["github_agent_project"]) != 1 {
		t.Fatalf("agent projects = %+v", byKind["github_agent_project"])
	}
	project := byKind["github_agent_project"][0]
	if project.ID != deterministicGitHubInventoryID(agentProjectSubject, "github_agent_project", "101") || project.SourceNativeID != "github:repository:101:agent_project" || project.DisplayName != "acme/alpha" ||
		string(project.StableFields) != `{"installation_id":9001,"name":"acme/alpha","owner":"acme","repository":"alpha"}` ||
		string(project.Attributes) != `{"discovery":{"method":"inferred","platform":"github_repository","signals":["manifest:mcp_config"]},"posture":`+agentProjectPosture+`}` {
		t.Fatalf("agent project = %+v\nstable %s\nattributes %s", project, project.StableFields, project.Attributes)
	}
	if !typedSnapshotEdge(relationships, "contains", deterministicGitHubInventoryID(agentProjectSubject, "github_repository", "101"), project.ID) {
		t.Fatalf("agent project is not related to its repository: %+v", relationships)
	}
}

// A configuration with a secret in every place a client lets one be written.
var typedSnapshotMCPSecret = "sk-" + "live0123456789abcdefSECRET"

var typedSnapshotMCPConfig = `{"mcpServers":{
 "tracker":{"command":"npx","args":["-y","@acme/tracker-mcp","--token","` + typedSnapshotMCPSecret + `"],"env":{"TRACKER_TOKEN":"` + typedSnapshotMCPSecret + `"},"autoApprove":["list_issues"]},
 "shell":{"command":"uvx","args":["mcp-shell==1.2.0"]},
 "docs":{"type":"http","url":"https://mcp.docs.example/v1?key=` + typedSnapshotMCPSecret + `","headers":{"Authorization":"Bearer ` + typedSnapshotMCPSecret + `"}},
 "open":{"url":"https://tools.example/sse"}
}}`

// A desktop extension manifest: the server and the names of its tools are
// read, nothing else. UNVERIFIED shape (agentsignals.ParseDXTManifest).
var typedSnapshotDXTManifest = `{"dxt_version":"0.1","name":"files-extension","description":"` + typedSnapshotMCPSecret + `",
 "server":{"type":"node","entry_point":"server/index.js","mcp_config":{"command":"node","args":["${__dirname}/server/index.js","--token","` + typedSnapshotMCPSecret + `"],"env":{"FILES_TOKEN":"` + typedSnapshotMCPSecret + `"}}},
 "tools":[{"name":"read_file","description":"` + typedSnapshotMCPSecret + `"},{"name":"write_file","description":"x"}]}`

// requireTypedSnapshotMCP checks the MCP servers, their tools and the skills
// of the typed snapshot, and that nothing of the configuration's secrets,
// arguments or URL paths reached it.
func requireTypedSnapshotMCP(t *testing.T, byKind map[string][]typedSnapshotEntity, relationships []typedSnapshotRelationship) {
	t.Helper()
	project := deterministicGitHubInventoryID(agentProjectSubject, "github_agent_project", "101")
	servers := map[string]string{}
	for _, server := range byKind["github_mcp_server"] {
		servers[server.DisplayName] = string(server.Attributes)
		if !typedSnapshotEdge(relationships, "depends_on", project, server.ID) {
			t.Fatalf("server %s is not used by the agent project", server.DisplayName)
		}
	}
	wantServers := map[string]string{
		"tracker": `{"auth":"not_applicable","command":"npx","config_path":"tools/.mcp.json","package":"@acme/tracker-mcp","package_pinned":false,"source":"repository_config","transport":"stdio"}`,
		"shell":   `{"auth":"not_applicable","command":"uvx","config_path":"tools/.mcp.json","package":"mcp-shell","package_pinned":true,"source":"repository_config","transport":"stdio"}`,
		"docs":    `{"auth":"declared","config_path":"tools/.mcp.json","endpoint_host":"mcp.docs.example","plain_http":false,"source":"repository_config","transport":"http"}`,
		"open":    `{"auth":"none","config_path":"tools/.mcp.json","endpoint_host":"tools.example","plain_http":false,"source":"repository_config","transport":"sse"}`,
		// The server a desktop extension packages.
		"files-extension": `{"auth":"not_applicable","command":"node","config_path":"ext/manifest.json","source":"repository_config","transport":"stdio"}`,
	}
	if len(servers) != len(wantServers) {
		t.Fatalf("servers = %v", servers)
	}
	for name, want := range wantServers {
		if servers[name] != want {
			t.Fatalf("server %s = %s\nwant %s", name, servers[name], want)
		}
	}
	tools := map[string]string{}
	for _, tool := range byKind["github_mcp_tool"] {
		tools[tool.DisplayName] = string(tool.StableFields) + string(tool.Attributes)
	}
	wantTools := map[string]string{
		"list_issues":  `{"installation_id":9001,"name":"list_issues","owner":"acme","repository":"alpha","server":"tracker"}{"risk":"read"}`,
		"create_issue": `{"installation_id":9001,"name":"create_issue","owner":"acme","repository":"alpha","server":"tracker"}{"risk":"write"}`,
		"run_command":  `{"installation_id":9001,"name":"run_command","owner":"acme","repository":"alpha","server":"shell"}{"risk":"execute"}`,
		"read_file":    `{"installation_id":9001,"name":"read_file","owner":"acme","repository":"alpha","server":"files-extension"}{"risk":"read"}`,
		"write_file":   `{"installation_id":9001,"name":"write_file","owner":"acme","repository":"alpha","server":"files-extension"}{"risk":"write"}`,
	}
	if len(tools) != len(wantTools) {
		t.Fatalf("tools = %v", tools)
	}
	for name, want := range wantTools {
		if tools[name] != want {
			t.Fatalf("tool %s = %s", name, tools[name])
		}
	}
	skills := map[string]string{}
	for _, skill := range byKind["github_agent_skill"] {
		skills[skill.DisplayName] = string(skill.Attributes)
		if !typedSnapshotEdge(relationships, "contains", project, skill.ID) {
			t.Fatalf("skill %s is not attached to the agent project", skill.DisplayName)
		}
	}
	// The skill's directory ships an executable file and CODEOWNERS names an
	// owner for it; the instruction file at the root has none.
	if len(skills) != 2 || skills[".claude/skills/release"] != `{"ownership":"covered","scripts":true,"skill_kind":"skill"}` || skills["AGENTS.md"] != `{"ownership":"uncovered","skill_kind":"agent_instructions"}` {
		t.Fatalf("skills = %v", skills)
	}
	for kind, entities := range byKind {
		for _, entity := range entities {
			for _, forbidden := range []string{typedSnapshotMCPSecret, "live0123456789", "--token", "/v1", "key=", "@acme/agents", "__dirname", "entry_point"} {
				if bytes.Contains(entity.Attributes, []byte(forbidden)) || bytes.Contains(entity.StableFields, []byte(forbidden)) || bytes.Contains([]byte(entity.DisplayName+entity.SourceNativeID), []byte(forbidden)) {
					t.Fatalf("%s %s carries %q", kind, entity.DisplayName, forbidden)
				}
			}
		}
	}
}
