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
//   - at most githubMaximumDXTManifests manifest.json files, for the MCP
//     server a desktop extension packages and the tool names it lists
//     (agentsignals.ParseDXTManifest); a manifest.json of anything else
//     declares nothing;
//   - the paths of skills and instruction files (SKILL.md directories,
//     AGENTS.md, CLAUDE.md, .cursor/rules). Their contents are never
//     requested. Whether a skill directory ships scripts is read from the
//     tree (extension and git mode), and whether a code owner is named for a
//     skill from the path patterns of the repository's CODEOWNERS file, the
//     one file read for skills; neither the patterns nor the owners are kept.
const (
	githubMaximumMCPConfigs      = 4
	githubMaximumDXTManifests    = 2
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

// candidateFile is a file of the tree that may be read: a blob with its size.
type candidateFile struct {
	Path string
	Size int64
}

// candidateFiles returns the blobs of a tree.
func candidateFiles(entries []struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Mode string `json:"mode"`
}) []candidateFile {
	files := make([]candidateFile, 0, len(entries))
	for _, entry := range entries {
		if entry.Type == "blob" {
			files = append(files, candidateFile{Path: entry.Path, Size: entry.Size})
		}
	}
	return files
}

// mcpConfigCandidates returns the MCP configuration files of a tree to read:
// shallow first, then by path, at most githubMaximumMCPConfigs; the shared
// Claude Code settings file; and, in the same order, at most
// githubMaximumDXTManifests manifest.json files.
func mcpConfigCandidates(entries []candidateFile) (configs []string, settings string, extensions []string) {
	for _, entry := range entries {
		if entry.Size < 2 || entry.Size > githubMaximumAgentManifestBytes || !validGitHubText(entry.Path, 512) || strings.Count(entry.Path, "/") > githubMaximumMCPConfigDepth {
			continue
		}
		if agentsignals.IsMCPConfigPath(entry.Path) {
			configs = append(configs, entry.Path)
		}
		if agentsignals.IsDXTManifestPath(entry.Path) {
			extensions = append(extensions, entry.Path)
		}
		if entry.Path == ".claude/settings.json" {
			settings = entry.Path
		}
	}
	shallowFirst := func(paths []string, maximum int) []string {
		sort.Slice(paths, func(left, right int) bool {
			leftDepth, rightDepth := strings.Count(paths[left], "/"), strings.Count(paths[right], "/")
			if leftDepth != rightDepth {
				return leftDepth < rightDepth
			}
			return paths[left] < paths[right]
		})
		if len(paths) > maximum {
			paths = paths[:maximum]
		}
		return paths
	}
	return shallowFirst(configs, githubMaximumMCPConfigs), settings, shallowFirst(extensions, githubMaximumDXTManifests)
}

// markSkillOwnership sets the skills' ownership from the repository's
// CODEOWNERS file: the first of GitHub's three locations the tree holds. A
// tree that was cut short may hide the file, and a file that cannot be read
// decides nothing: ownership is then left unset.
func (api *InstallationCollectionAPI) markSkillOwnership(ctx context.Context, credential []byte, repositoryURL, branch string, entries []candidateFile, truncated bool, skills []agentsignals.Skill) error {
	present := map[string]int64{}
	for _, entry := range entries {
		present[entry.Path] = entry.Size
	}
	for _, location := range agentsignals.CodeownersPaths {
		size, found := present[location]
		if !found {
			continue
		}
		if size < 1 || size > githubMaximumAgentManifestBytes {
			return nil
		}
		content, err := api.readAgentProjectFile(ctx, credential, repositoryURL, branch, location)
		if err != nil || content == nil {
			return err
		}
		agentsignals.MarkSkillOwnership(skills, agentsignals.ParseCodeowners(content))
		return nil
	}
	if !truncated {
		agentsignals.MarkSkillOwnership(skills, nil)
	}
	return nil
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
func (api *InstallationCollectionAPI) readRepositoryMCPServers(ctx context.Context, credential []byte, repositoryURL, branch string, configs []string, settings string, extensions []string) ([]repositoryMCPServer, error) {
	byName := map[string]*repositoryMCPServer{}
	tools := map[string]map[string]bool{}
	for index, config := range append(append([]string(nil), configs...), extensions...) {
		content, err := api.readAgentProjectFile(ctx, credential, repositoryURL, branch, config)
		if err != nil {
			return nil, err
		}
		declarations := agentsignals.ParseMCPConfig(content)
		if index >= len(configs) {
			// A desktop extension manifest declares one server.
			declarations = nil
			if packaged, ok := agentsignals.ParseDXTManifest(content); ok {
				declarations = []agentsignals.MCPServerDeclaration{packaged}
			}
		}
		for _, declared := range declarations {
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
		attributes := map[string]any{"skill_kind": skill.Kind}
		if skill.ScriptsKnown {
			attributes["scripts"] = skill.Scripts
		}
		if skill.Ownership != "" {
			attributes["ownership"] = skill.Ownership
		}
		if !add("github_agent_skill", "github:repository:"+nativeID+":agent_skill:"+skill.Path, skill.Path, stable(skill.Path, nil), attributes, "contains", relationshipType, owner) {
			return nil, nil, false
		}
	}
	return entities, relationships, true
}
