package agentsignals

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// What can be said about a skill without reading it: whether its directory
// ships scripts (from the file tree: a script extension or git's executable
// mode) and whether a code owner is named for its path (from the path
// patterns of the repository's CODEOWNERS file). Neither reads the skill.

// RepositoryFile is one file of a repository tree: its path and whether git
// records it as executable (tree mode 100755).
type RepositoryFile struct {
	Path       string
	Executable bool
}

const (
	// SkillOwnershipCovered: a CODEOWNERS pattern with an owner matches.
	SkillOwnershipCovered = "covered"
	// SkillOwnershipUncovered: the repository has a CODEOWNERS file and no
	// pattern with an owner matches the skill.
	SkillOwnershipUncovered = "uncovered"
	// SkillOwnershipNoCodeowners: the repository has no CODEOWNERS file.
	SkillOwnershipNoCodeowners = "no_codeowners"
)

// CodeownersPaths are where GitHub looks for the file, in its order of
// precedence (GitHub documentation, as remembered: UNVERIFIED).
var CodeownersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// skillScriptExtensions are file extensions an interpreter or a shell runs
// directly.
var skillScriptExtensions = wordSet(".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd")

// MarkSkillScripts sets, for every skill directory, whether a file under it
// is a script. complete is false when the tree listing was cut short: a
// script that was seen is still one, an absence is then not asserted
// (ScriptsKnown stays false). Instruction and rule files are single files and
// are left alone, and so is a SKILL.md at the repository root, whose
// directory is the whole repository.
func MarkSkillScripts(skills []Skill, files []RepositoryFile, complete bool) {
	for index := range skills {
		skill := &skills[index]
		if skill.Kind != SkillKindSkill || skill.Path == "SKILL.md" {
			continue
		}
		prefix := skill.Path + "/"
		for _, file := range files {
			clean := strings.TrimPrefix(path.Clean("/"+file.Path), "/")
			if !strings.HasPrefix(clean, prefix) || path.Base(clean) == "SKILL.md" {
				continue
			}
			if file.Executable || skillScriptExtensions[strings.ToLower(path.Ext(clean))] {
				skill.Scripts = true
				break
			}
		}
		skill.ScriptsKnown = skill.Scripts || complete
	}
}

// CodeownersRules are the path patterns of a CODEOWNERS file, in file order,
// each with whether it names an owner. The owners themselves are not kept.
type CodeownersRules struct {
	rules []codeownersRule
}

type codeownersRule struct {
	pattern *regexp.Regexp
	owned   bool
}

const (
	maximumCodeownersRules   = 2000
	maximumCodeownersPattern = 256
)

// ParseCodeowners reads the path patterns of a CODEOWNERS file. A line is a
// pattern followed by owners; "#" starts a comment; a pattern with no owner
// leaves what it matches unowned. Negation ("!") and character ranges ("[")
// are not CODEOWNERS syntax and such a line is skipped, as GitHub skips an
// invalid line. The matching below follows GitHub's documentation of the
// syntax as remembered and has not been compared with GitHub's own
// evaluation: UNVERIFIED.
func ParseCodeowners(content []byte) *CodeownersRules {
	parsed := &CodeownersRules{}
	for _, line := range strings.Split(string(content), "\n") {
		if len(parsed.rules) == maximumCodeownersRules {
			break
		}
		line = strings.TrimSpace(strings.ReplaceAll(line, `\ `, "\x00"))
		if comment := strings.Index(line, "#"); comment >= 0 && (comment == 0 || line[comment-1] == ' ' || line[comment-1] == '\t') {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pattern := strings.ReplaceAll(fields[0], "\x00", " ")
		if len(pattern) > maximumCodeownersPattern || strings.HasPrefix(pattern, "!") || strings.ContainsAny(pattern, "[]\\") {
			continue
		}
		compiled := codeownersPattern(pattern)
		if compiled == nil {
			continue
		}
		owned := false
		for _, owner := range fields[1:] {
			if strings.Contains(owner, "@") {
				owned = true
			}
		}
		parsed.rules = append(parsed.rules, codeownersRule{pattern: compiled, owned: owned})
	}
	return parsed
}

// codeownersPattern compiles one pattern. A leading "/" or a "/" inside the
// pattern anchors it at the repository root; otherwise it matches at any
// depth. "*" stays inside one path element and "**" crosses them. A pattern
// that names a directory owns everything under it, except "dir/*", which
// owns only the files directly in dir.
func codeownersPattern(pattern string) *regexp.Regexp {
	trimmed := strings.TrimPrefix(pattern, "/")
	directory := strings.HasSuffix(trimmed, "/")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" {
		return nil
	}
	anchored := strings.HasPrefix(pattern, "/") || strings.Contains(trimmed, "/")
	elements := strings.Split(trimmed, "/")
	direct := len(elements) > 1 && elements[len(elements)-1] == "*"
	var expression strings.Builder
	expression.WriteString("^")
	if !anchored {
		expression.WriteString("(?:.*/)?")
	}
	for index, element := range elements {
		last := index == len(elements)-1
		if element == "**" {
			if last {
				expression.WriteString(".*")
			} else {
				expression.WriteString("(?:.*/)?")
			}
			continue
		}
		for _, character := range element {
			switch character {
			case '*':
				expression.WriteString("[^/]*")
			case '?':
				expression.WriteString("[^/]")
			default:
				expression.WriteString(regexp.QuoteMeta(string(character)))
			}
		}
		if !last {
			expression.WriteString("/")
		}
	}
	switch {
	case directory:
		expression.WriteString("/.*")
	case !direct && elements[len(elements)-1] != "**":
		expression.WriteString("(?:/.*)?")
	}
	expression.WriteString("$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return nil
	}
	return compiled
}

// Owned reports whether the last pattern that matches a path names an owner.
func (rules *CodeownersRules) Owned(filePath string) bool {
	clean := strings.TrimPrefix(path.Clean("/"+filePath), "/")
	for index := len(rules.rules) - 1; index >= 0; index-- {
		if rules.rules[index].pattern.MatchString(clean) {
			return rules.rules[index].owned
		}
	}
	return false
}

// MarkSkillOwnership sets every skill's ownership from the repository's
// CODEOWNERS patterns; nil rules mean the repository has no such file. A
// skill directory is owned when its SKILL.md is.
func MarkSkillOwnership(skills []Skill, rules *CodeownersRules) {
	for index := range skills {
		skill := &skills[index]
		if rules == nil {
			skill.Ownership = SkillOwnershipNoCodeowners
			continue
		}
		file := skill.Path
		if skill.Kind == SkillKindSkill && skill.Path != "SKILL.md" {
			file = skill.Path + "/SKILL.md"
		}
		skill.Ownership = SkillOwnershipUncovered
		if rules.Owned(file) {
			skill.Ownership = SkillOwnershipCovered
		}
	}
}

// IsDXTManifestPath reports whether a repository path may be the manifest of
// a desktop extension (an MCP server packaged for a desktop client).
func IsDXTManifestPath(value string) bool {
	return path.Base(path.Clean("/"+value)) == "manifest.json"
}

// ParseDXTManifest reads the manifest.json of a desktop extension and
// returns the MCP server it packages with the tool names it lists. Only
// dxt_version or manifest_version (as a string; a browser extension's is a
// number), name, server.type, server.mcp_config (command and argument
// elements, reduced as ParseMCPConfig reduces them) and tools[].name are
// read. Tool descriptions, user configuration and environment values are not
// decoded. The member names are from the desktop extension manifest
// specification as remembered: UNVERIFIED.
func ParseDXTManifest(content []byte) (MCPServerDeclaration, bool) {
	var manifest struct {
		DXTVersion      string          `json:"dxt_version"`
		ManifestVersion json.RawMessage `json:"manifest_version"`
		Name            string          `json:"name"`
		Server          *struct {
			Type      string         `json:"type"`
			MCPConfig mcpServerEntry `json:"mcp_config"`
		} `json:"server"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(content, &manifest) != nil || manifest.Server == nil {
		return MCPServerDeclaration{}, false
	}
	var version string
	if manifest.DXTVersion == "" && (json.Unmarshal(manifest.ManifestVersion, &version) != nil || version == "") {
		return MCPServerDeclaration{}, false
	}
	if kind := manifest.Server.Type; kind != "node" && kind != "python" && kind != "binary" {
		return MCPServerDeclaration{}, false
	}
	name := manifest.Name
	if !mcpServerNamePattern.MatchString(name) || strings.TrimSpace(name) != name || looksLikeSecret(name) {
		return MCPServerDeclaration{}, false
	}
	entry := manifest.Server.MCPConfig
	entry.URL, entry.ServerURL, entry.HTTPURL = "", "", ""
	server, ok := declaredMCPServer(name, entry)
	if !ok {
		return MCPServerDeclaration{}, false
	}
	seen := map[string]bool{}
	for _, tool := range manifest.Tools {
		if ValidMCPToolName(tool.Name) {
			seen[tool.Name] = true
		}
	}
	server.Tools = boundedSortedNames(seen, MaximumMCPToolsPerServer)
	return server, true
}
