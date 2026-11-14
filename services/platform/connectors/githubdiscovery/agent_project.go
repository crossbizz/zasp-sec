package githubdiscovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// The agentproject phase runs once per non-archived repository, between the
// repository page and its workflow pages. One page reads the repository's
// file tree and at most githubMaximumAgentManifests dependency manifests, so
// it makes at most 1+githubMaximumAgentManifests provider calls. Nothing is
// carried to another page: a failed page is retried whole from its cursor.
const (
	githubAgentProjectPhase         = "agentproject"
	githubMaximumAgentManifests     = 6
	githubMaximumAgentManifestBytes = int64(256 * 1024)
	// A manifest of the maximum size, base64-encoded with line breaks inside
	// a JSON string, plus the other fields of the contents response.
	githubMaximumAgentContentResponseBytes = int64(512 * 1024)
)

type repositoryTreeResponse struct {
	Tree *[]struct {
		Path string `json:"path"`
		Type string `json:"type"`
		Size int64  `json:"size"`
		Mode string `json:"mode"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

type repositoryContentResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

func (api *InstallationCollectionAPI) fetchAgentProjectPage(ctx context.Context, credential []byte, request CollectionPageRequest, state githubPageState) (CollectionPage, error) {
	repositoryURL := githubCollectionEndpoint + "/repos/" + url.PathEscape(state.Owner) + "/" + url.PathEscape(state.Repository)
	status, body, err := api.getAgentProjectResource(ctx, credential, repositoryURL+"/git/trees/"+escapeGitHubPath(state.DefaultBranch)+"?recursive=1", githubMaximumResponseBytes)
	if err != nil {
		return CollectionPage{}, err
	}
	var evidence agentsignals.Evidence
	var servers []repositoryMCPServer
	var skills []agentsignals.Skill
	// 404: the default branch has no commit. 409: the repository is empty.
	if status != http.StatusNotFound && status != http.StatusConflict {
		var tree repositoryTreeResponse
		if body == nil || !decodeInstallationResponse(body, &tree) || tree.Tree == nil {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		paths := make([]string, 0, len(*tree.Tree))
		files := make([]agentsignals.RepositoryFile, 0, len(*tree.Tree))
		manifests := make([]string, 0, githubMaximumAgentManifests)
		for _, entry := range *tree.Tree {
			if entry.Type != "blob" || entry.Path == "" {
				continue
			}
			paths = append(paths, entry.Path)
			files = append(files, agentsignals.RepositoryFile{Path: entry.Path, Executable: entry.Mode == "100755"})
			if _, known := agentsignals.DependencyManifests[path.Base(entry.Path)]; known && strings.Count(entry.Path, "/") <= 1 && entry.Size >= 1 && entry.Size <= githubMaximumAgentManifestBytes && validGitHubText(entry.Path, 512) {
				manifests = append(manifests, entry.Path)
			}
		}
		evidence.Paths(paths...)
		// Root manifests first, then by path, so the same tree always reads
		// the same files.
		sort.Slice(manifests, func(left, right int) bool {
			leftDepth, rightDepth := strings.Count(manifests[left], "/"), strings.Count(manifests[right], "/")
			if leftDepth != rightDepth {
				return leftDepth < rightDepth
			}
			return manifests[left] < manifests[right]
		})
		if len(manifests) > githubMaximumAgentManifests {
			manifests = manifests[:githubMaximumAgentManifests]
		}
		for _, manifest := range manifests {
			query := url.Values{}
			query.Set("ref", state.DefaultBranch)
			status, body, err = api.getAgentProjectResource(ctx, credential, repositoryURL+"/contents/"+escapeGitHubPath(manifest)+"?"+query.Encode(), githubMaximumAgentContentResponseBytes)
			if err != nil {
				return CollectionPage{}, err
			}
			// The file changed since the tree was read: gone, or grown past
			// the limit. It is not evidence either way.
			if status != http.StatusOK || body == nil {
				continue
			}
			var content repositoryContentResponse
			if !decodeInstallationResponse(body, &content) {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
			if content.Type != "file" || content.Encoding != "base64" {
				continue
			}
			decoded, decodeErr := base64.StdEncoding.DecodeString(strings.Map(dropBase64Whitespace, content.Content))
			if decodeErr != nil || int64(len(decoded)) > githubMaximumAgentManifestBytes {
				continue
			}
			name := path.Base(manifest)
			evidence.Packages(agentsignals.DependencyManifests[name], manifestPackageNames(name, decoded)...)
		}
		// The MCP servers the repository declares, and its skills (paths only).
		configs, settings, extensions := mcpConfigCandidates(candidateFiles(*tree.Tree))
		if servers, err = api.readRepositoryMCPServers(ctx, credential, repositoryURL, state.DefaultBranch, configs, settings, extensions); err != nil {
			if err == errMalformedAgentProjectFile {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
			return CollectionPage{}, err
		}
		skills = agentsignals.SkillPaths(paths...)
		if len(skills) > 0 {
			// What the tree says about the skills, and whether the
			// repository's CODEOWNERS patterns name an owner for them.
			agentsignals.MarkSkillScripts(skills, files, !tree.Truncated)
			if err = api.markSkillOwnership(ctx, credential, repositoryURL, state.DefaultBranch, candidateFiles(*tree.Tree), tree.Truncated, skills); err != nil {
				if err == errMalformedAgentProjectFile {
					return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
				}
				return CollectionPage{}, err
			}
		}
	}
	var entities, relationships []json.RawMessage
	if evidence.IsAgent() {
		var normalized bool
		if entities, relationships, normalized = normalizeAgentProject(request.Subject, state, evidence.Signals()); !normalized {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
	}
	if len(servers) > 0 || len(skills) > 0 {
		more, edges, normalized := normalizeAgentProjectInventory(request.Subject, state, evidence.IsAgent(), servers, skills)
		if !normalized {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		entities, relationships = append(entities, more...), append(relationships, edges...)
		sortGitHubInventory(entities)
		sortGitHubInventory(relationships)
	}
	nextState := state
	nextState.Phase = "workflows"
	nextState.Lineage++
	next, cursorOK := nextGitHubCursor(request.Subject, nextState)
	page, pageErr := NewCollectionPage(request.Subject, next, false, entities, relationships)
	if !cursorOK || pageErr != nil || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if !githubPageFits(request, page) {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

// getAgentProjectResource sends one GET. It returns the status and the body
// for 200, the status alone for 404 and 409 (the caller decides what a
// missing object means), and the classified failure for anything else. A 200
// whose body is larger than maximum returns a nil body.
func (api *InstallationCollectionAPI) getAgentProjectResource(ctx context.Context, credential []byte, providerURL string, maximum int64) (int, []byte, error) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest, err := http.NewRequestWithContext(bounded, http.MethodGet, providerURL, nil)
	if err != nil {
		return 0, nil, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/vnd.github+json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(credential))
	providerRequest.Header.Set("User-Agent", "zasp-discovery/1")
	providerRequest.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := doInstallationRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeInstallationResponse(response)
		return 0, nil, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", time.Now().UTC())
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict {
		return response.StatusCode, nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return 0, nil, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		if bounded.Err() != nil {
			return 0, nil, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", time.Now().UTC())
		}
		return 0, nil, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if int64(len(body)) > maximum {
		return http.StatusOK, nil, nil
	}
	return http.StatusOK, body, nil
}

func normalizeAgentProject(subject collection.SubjectBinding, state githubPageState, signals []string) ([]json.RawMessage, []json.RawMessage, bool) {
	installationID, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || installationID < 1 || installationID > 1<<53 {
		return nil, nil, false
	}
	nativeID := strconv.FormatInt(state.RepositoryID, 10)
	fullName := state.Owner + "/" + state.Repository
	repositoryEntityID := deterministicGitHubInventoryID(subject, "github_repository", nativeID)
	projectEntityID := deterministicGitHubInventoryID(subject, "github_agent_project", nativeID)
	stable, _ := json.Marshal(struct {
		InstallationID int64  `json:"installation_id"`
		Name           string `json:"name"`
		Owner          string `json:"owner"`
		Repository     string `json:"repository"`
	}{installationID, fullName, state.Owner, state.Repository})
	attributes, _ := json.Marshal(struct {
		Posture   agentsignals.Posture   `json:"posture"`
		Discovery agentsignals.Discovery `json:"discovery"`
	}{agentsignals.Posture{}, agentsignals.NewDiscovery(agentsignals.MethodInferred, "github_repository", signals)})
	entity, err := marshalGitHubEntity(projectEntityID, "github_agent_project", "github:repository:"+nativeID+":agent_project", fullName, stable, attributes)
	if err != nil {
		return nil, nil, false
	}
	contains, err := marshalGitHubRelationship(deterministicGitHubInventoryID(subject, "contains", nativeID+":agent_project"), "contains", "github:repository:"+nativeID+":agent_project", repositoryEntityID, projectEntityID, "repository_agent_project")
	if err != nil {
		return nil, nil, false
	}
	return []json.RawMessage{entity}, []json.RawMessage{contains}, true
}

// errMalformedAgentProjectFile marks a contents response that is not the
// provider's document.
var errMalformedAgentProjectFile = errors.New("github discovery: malformed contents response")

func sortGitHubInventory(values []json.RawMessage) {
	sort.SliceStable(values, func(left, right int) bool {
		var a, b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(values[left], &a)
		_ = json.Unmarshal(values[right], &b)
		return a.ID < b.ID
	})
}

func escapeGitHubPath(value string) string {
	segments := strings.Split(value, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func dropBase64Whitespace(character rune) rune {
	if character == '\n' || character == '\r' || character == ' ' || character == '\t' {
		return -1
	}
	return character
}

// manifestPackageNames returns the package names a dependency manifest
// declares. Only names leave this function: versions, URLs, comments and
// every other part of the file are dropped here.
func manifestPackageNames(name string, content []byte) []string {
	switch name {
	case "requirements.txt":
		return requirementsPackageNames(string(content))
	case "pyproject.toml":
		return pyprojectPackageNames(string(content))
	case "package.json":
		var manifest struct {
			Dependencies    map[string]json.RawMessage `json:"dependencies"`
			DevDependencies map[string]json.RawMessage `json:"devDependencies"`
		}
		if json.Unmarshal(content, &manifest) != nil {
			return nil
		}
		names := make([]string, 0, len(manifest.Dependencies)+len(manifest.DevDependencies))
		for dependency := range manifest.Dependencies {
			names = append(names, dependency)
		}
		for dependency := range manifest.DevDependencies {
			names = append(names, dependency)
		}
		return names
	case "go.mod":
		return goModulePaths(string(content))
	default:
		return nil
	}
}

// pythonRequirementName returns the distribution name a requirement
// specifier starts with ("langgraph>=0.2", "mcp[cli]", "openai ; python_version<'3.13'").
func pythonRequirementName(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	end := 0
	for end < len(specifier) {
		character := specifier[end]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			break
		}
		end++
	}
	return specifier[:end]
}

func requirementsPackageNames(content string) []string {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		// Options (-r, -c, -e, --index-url, ...) name files and URLs, not packages.
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if name := pythonRequirementName(line); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// pyprojectPackageNames reads, best effort and without a TOML parser, the
// strings of every `dependencies = [...]` array (PEP 621) and the keys of the
// Poetry dependency tables.
func pyprojectPackageNames(content string) []string {
	var names []string
	section := ""
	inArray := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		rest := trimmed
		if !inArray {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(trimmed, "[") {
				section = strings.TrimSpace(strings.Trim(strings.SplitN(trimmed, "#", 2)[0], "[] \t\r"))
				continue
			}
			key, value, assignment := strings.Cut(trimmed, "=")
			if !assignment {
				continue
			}
			key = strings.Trim(strings.TrimSpace(key), `"'`)
			if section == "tool.poetry.dependencies" || section == "tool.poetry.dev-dependencies" || strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies") {
				if key != "python" && pythonRequirementName(key) == key {
					names = append(names, key)
				}
				continue
			}
			value = strings.TrimSpace(value)
			if key != "dependencies" || !strings.HasPrefix(value, "[") {
				continue
			}
			inArray, rest = true, value[1:]
		}
		// Inside the array: quoted strings are requirements, ] outside a
		// string ends it, # outside a string starts a comment.
		for index := 0; index < len(rest); index++ {
			character := rest[index]
			if character == '"' || character == '\'' {
				end := strings.IndexByte(rest[index+1:], character)
				if end < 0 {
					break
				}
				if name := pythonRequirementName(rest[index+1 : index+1+end]); name != "" {
					names = append(names, name)
				}
				index += end + 1
				continue
			}
			if character == ']' {
				inArray = false
				break
			}
			if character == '#' {
				break
			}
		}
	}
	return names
}

func goModulePaths(content string) []string {
	var names []string
	inBlock := false
	for _, line := range strings.Split(content, "\n") {
		if index := strings.Index(line, "//"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if inBlock {
			if fields[0] == ")" {
				inBlock = false
				continue
			}
			names = append(names, fields[0])
			continue
		}
		if fields[0] != "require" || len(fields) < 2 {
			continue
		}
		if fields[1] == "(" {
			inBlock = true
			continue
		}
		names = append(names, fields[1])
	}
	return names
}
