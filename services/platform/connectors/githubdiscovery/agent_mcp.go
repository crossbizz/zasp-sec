package githubdiscovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// The agentproject page also reads, from the same file tree:
//
//   - the repository's MCP configuration files (.mcp.json, mcp.json,
//     .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json), at most
//     githubMaximumMCPConfigs of them, and the shared Claude Code settings
//     file for the tools its permission rules name. From a configuration only
//     the server's name, transport, command base name or URL host, launched
//     package and whether any authentication is declared are kept
//     (agentsignals.ParseMCPConfig); no environment value, header, argument or
//     URL path leaves the parser;
//   - the paths of skills and instruction files (SKILL.md directories,
//     AGENTS.md, CLAUDE.md, .cursor/rules). Their contents are never
//     requested.
const (
	githubMaximumMCPConfigs      = 4
	githubMaximumMCPConfigDepth  = 3
	githubMaximumRepositoryMCP   = 32
	githubMaximumRepositoryTools = 128
)

// repositoryMCPServer is one MCP server a repository declares, with the
// configuration file that declared it first.
type repositoryMCPServer struct {
	agentsignals.MCPServerDeclaration
	ConfigPath string
}

// mcpConfigCandidates returns the MCP configuration files of a tree to read:
// shallow first, then by path, at most githubMaximumMCPConfigs.
func mcpConfigCandidates(entries []struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}) (configs []string, settings string) {
	for _, entry := range entries {
		if entry.Type != "blob" || entry.Size < 2 || entry.Size > githubMaximumAgentManifestBytes || !validGitHubText(entry.Path, 512) || strings.Count(entry.Path, "/") > githubMaximumMCPConfigDepth {
			continue
		}
		if agentsignals.IsMCPConfigPath(entry.Path) {
			configs = append(configs, entry.Path)
		}
		if entry.Path == ".claude/settings.json" {
			settings = entry.Path
		}
	}
	sort.Slice(configs, func(left, right int) bool {
		leftDepth, rightDepth := strings.Count(configs[left], "/"), strings.Count(configs[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return configs[left] < configs[right]
	})
	if len(configs) > githubMaximumMCPConfigs {
		configs = configs[:githubMaximumMCPConfigs]
	}
	return configs, settings
}

// readAgentProjectFile reads one file of the default branch. It returns nil
// for a file that is gone, is not a base64 file or is over the size limit:
// none of those is evidence either way.
func (api *InstallationCollectionAPI) readAgentProjectFile(ctx context.Context, credential []byte, repositoryURL, branch, filePath string) ([]byte, error) {
	query := url.Values{}
	query.Set("ref", branch)
	status, body, err := api.getAgentProjectResource(ctx, credential, repositoryURL+"/contents/"+escapeGitHubPath(filePath)+"?"+query.Encode(), githubMaximumAgentContentResponseBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || body == nil {
		return nil, nil
	}
	var content repositoryContentResponse
	if !decodeInstallationResponse(body, &content) {
		return nil, errMalformedAgentProjectFile
	}
	if content.Type != "file" || content.Encoding != "base64" {
		return nil, nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.Map(dropBase64Whitespace, content.Content))
	if decodeErr != nil || int64(len(decoded)) > githubMaximumAgentManifestBytes {
		return nil, nil
	}
	return decoded, nil
}

// readRepositoryMCPServers reads the configuration files and returns the
// servers they declare, by name. A server two files declare is the one of the
// first file; the tools of both are kept.
func (api *InstallationCollectionAPI) readRepositoryMCPServers(ctx context.Context, credential []byte, repositoryURL, branch string, configs []string, settings string) ([]repositoryMCPServer, error) {
	byName := map[string]*repositoryMCPServer{}
	tools := map[string]map[string]bool{}
	for _, config := range configs {
		content, err := api.readAgentProjectFile(ctx, credential, repositoryURL, branch, config)
		if err != nil {
			return nil, err
		}
		for _, declared := range agentsignals.ParseMCPConfig(content) {
			if byName[declared.Name] == nil {
				if len(byName) >= githubMaximumRepositoryMCP {
					continue
				}
				byName[declared.Name] = &repositoryMCPServer{MCPServerDeclaration: declared, ConfigPath: config}
				tools[declared.Name] = map[string]bool{}
			}
			for _, tool := range declared.Tools {
				tools[declared.Name][tool] = true
			}
		}
	}
	if settings != "" && len(byName) > 0 {
		content, err := api.readAgentProjectFile(ctx, credential, repositoryURL, branch, settings)
		if err != nil {
			return nil, err
		}
		// A rule names a server by the name the configuration gave it.
		for server, named := range agentsignals.ClaudeSettingsToolPermissions(content) {
			if byName[server] == nil {
				continue
			}
			for _, tool := range named {
				tools[server][tool] = true
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	servers := make([]repositoryMCPServer, 0, len(names))
	remaining := githubMaximumRepositoryTools
	for _, name := range names {
		server := *byName[name]
		server.Tools = server.Tools[:0:0]
		for tool := range tools[name] {
			server.Tools = append(server.Tools, tool)
		}
		sort.Strings(server.Tools)
		if len(server.Tools) > agentsignals.MaximumMCPToolsPerServer {
			server.Tools = server.Tools[:agentsignals.MaximumMCPToolsPerServer]
		}
		if len(server.Tools) > remaining {
			server.Tools = server.Tools[:remaining]
		}
		remaining -= len(server.Tools)
		servers = append(servers, server)
	}
	return servers, nil
}

// normalizeAgentProjectInventory emits the MCP servers and tools of an agent
// project and the repository's skills. Servers hang off the project (a
// repository that declares one is a project); a skill hangs off the project
// when there is one and off the repository otherwise.
func normalizeAgentProjectInventory(subject collection.SubjectBinding, state githubPageState, project bool, servers []repositoryMCPServer, skills []agentsignals.Skill) ([]json.RawMessage, []json.RawMessage, bool) {
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	nativeID := strconv.FormatInt(state.RepositoryID, 10)
	repositoryEntityID := deterministicGitHubInventoryID(subject, "github_repository", nativeID)
	projectEntityID := deterministicGitHubInventoryID(subject, "github_agent_project", nativeID)
	var entities, relationships []json.RawMessage
	stable := func(name string, extra map[string]any) json.RawMessage {
		fields := map[string]any{"installation_id": installationID, "name": name, "owner": state.Owner, "repository": state.Repository}
		for key, value := range extra {
			fields[key] = value
		}
		encoded, _ := json.Marshal(fields)
		return encoded
	}
	add := func(kind, native, display string, stableFields json.RawMessage, attributes map[string]any, relationshipKind, relationshipType, from string) bool {
		id := deterministicGitHubInventoryID(subject, kind, native)
		encodedAttributes, _ := json.Marshal(attributes)
		entity, entityErr := marshalGitHubEntity(id, kind, native, display, stableFields, encodedAttributes)
		relationship, relationshipErr := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, relationshipKind, from+":"+native), relationshipKind, native, from, id, relationshipType)
		if entityErr != nil || relationshipErr != nil {
			return false
		}
		entities = append(entities, entity)
		relationships = append(relationships, relationship)
		return true
	}
	if project {
		for _, server := range servers {
			native := "github:repository:" + nativeID + ":mcp_server:" + server.Name
			attributes := map[string]any{"source": "repository_config", "transport": server.Transport, "auth": server.Auth, "config_path": server.ConfigPath}
			if server.Command != "" {
				attributes["command"] = server.Command
			}
			if server.Package != "" {
				attributes["package"], attributes["package_pinned"] = server.Package, server.PackagePinned
			}
			if server.EndpointHost != "" {
				attributes["endpoint_host"], attributes["plain_http"] = server.EndpointHost, server.PlainHTTP
			}
			if !add("github_mcp_server", native, server.Name, stable(server.Name, nil), attributes, "depends_on", "agent_project_mcp_server", projectEntityID) {
				return nil, nil, false
			}
			serverEntityID := deterministicGitHubInventoryID(subject, "github_mcp_server", native)
			for _, tool := range server.Tools {
				toolNative := "github:repository:" + nativeID + ":mcp_tool:" + server.Name + ":" + tool
				if !add("github_mcp_tool", toolNative, tool, stable(tool, map[string]any{"server": server.Name}), map[string]any{"risk": agentsignals.MCPToolRisk(tool)}, "contains", "mcp_server_tool", serverEntityID) {
					return nil, nil, false
				}
			}
		}
	}
	owner, relationshipType := repositoryEntityID, "repository_agent_skill"
	if project {
		owner, relationshipType = projectEntityID, "agent_project_skill"
	}
	for _, skill := range skills {
		if !add("github_agent_skill", "github:repository:"+nativeID+":agent_skill:"+skill.Path, skill.Path, stable(skill.Path, nil), map[string]any{"skill_kind": skill.Kind}, "contains", relationshipType, owner) {
			return nil, nil, false
		}
	}
	return entities, relationships, true
}
