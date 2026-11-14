package agentsignals

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// MCP servers and their tools, as the discovery collectors record them.
//
// A collector reads a declaration (a repository's .mcp.json, a gateway
// target, a workload) and keeps only what identifies the server: its name,
// its transport, the base name of the command or the host of the URL, the
// package a launcher starts and whether that package is pinned, and whether
// the declaration states any authentication. It never keeps an environment
// variable value, a header value, an argument, a URL path or query, or a tool
// description.

// MCP server transports.
const (
	MCPTransportStdio = "stdio"
	MCPTransportHTTP  = "http"
	MCPTransportSSE   = "sse"
)

// What a declaration says about authentication.
const (
	// MCPAuthDeclared: the declaration names a credential (a header, an OAuth
	// member, an authorizer). Only the presence is recorded.
	MCPAuthDeclared = "declared"
	// MCPAuthNone: a remote server whose declaration names no credential.
	MCPAuthNone = "none"
	// MCPAuthNotApplicable: a stdio server; it is a local process.
	MCPAuthNotApplicable = "not_applicable"
)

// MCP tool risk classes, from the most to the least dangerous. A tool is the
// most dangerous class one of its name's words matches.
const (
	MCPToolRiskExecute      = "execute"
	MCPToolRiskWrite        = "write"
	MCPToolRiskNetwork      = "network"
	MCPToolRiskRead         = "read"
	MCPToolRiskUnclassified = "unclassified"
)

// Bounds of what one declaration file may contribute.
const (
	MaximumMCPServersPerFile = 32
	MaximumMCPToolsPerServer = 64
	MaximumSkillsPerProject  = 64
)

// Words of a tool name. Execute words run code or commands on the server's
// host; the leading verbs run something the caller names.
var (
	mcpExecuteWords = wordSet("exec", "execute", "shell", "bash", "terminal", "eval", "spawn", "subprocess", "command", "cmd", "powershell", "script")
	mcpExecuteVerbs = wordSet("run", "invoke", "launch", "trigger", "deploy")
	mcpWriteWords   = wordSet("create", "update", "delete", "remove", "write", "put", "post", "patch", "insert", "upsert", "drop", "set", "add", "edit", "modify", "merge", "push", "commit",
		"send", "upload", "move", "rename", "destroy", "terminate", "kill", "close", "approve", "comment", "reply", "publish", "grant", "revoke", "transfer", "pay", "purchase", "cancel",
		"restart", "stop", "start", "enable", "disable", "reset", "apply", "import", "save", "append", "truncate", "assign", "archive", "fork", "lock", "unlock")
	mcpNetworkWords = wordSet("fetch", "http", "https", "curl", "wget", "browse", "browser", "navigate", "crawl", "scrape", "download", "url", "webhook", "proxy")
	mcpReadWords    = wordSet("get", "list", "read", "search", "find", "query", "describe", "show", "view", "lookup", "count", "check", "status", "select", "summarize", "retrieve", "inspect", "export", "diff", "log", "logs")
)

func wordSet(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[word] = true
	}
	return set
}

var mcpToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$`)

// ValidMCPToolName reports whether a tool name may be recorded.
func ValidMCPToolName(name string) bool {
	return mcpToolNamePattern.MatchString(name) && !looksLikeSecret(name)
}

// MCPToolRisk classifies a tool by the words of its name ("run_shell",
// "createIssue", "db.query"). The name is all that is read.
func MCPToolRisk(name string) string {
	words := nameWords(name)
	risk := MCPToolRiskUnclassified
	for index, word := range words {
		switch {
		case mcpExecuteWords[word] || index == 0 && mcpExecuteVerbs[word]:
			return MCPToolRiskExecute
		case mcpWriteWords[word]:
			risk = MCPToolRiskWrite
		case mcpNetworkWords[word] && risk != MCPToolRiskWrite:
			risk = MCPToolRiskNetwork
		case mcpReadWords[word] && risk == MCPToolRiskUnclassified:
			risk = MCPToolRiskRead
		}
	}
	return risk
}

// nameWords splits a tool name at separators and at lower-to-upper case
// changes, lower-cased.
func nameWords(name string) []string {
	var words []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	var prior rune
	for _, character := range name {
		switch {
		case !unicode.IsLetter(character) && !unicode.IsDigit(character):
			flush()
		case unicode.IsUpper(character) && unicode.IsLower(prior):
			flush()
			current = append(current, character)
		default:
			current = append(current, character)
		}
		prior = character
	}
	flush()
	return words
}

// MCPServerDeclaration is one server a configuration file declares, reduced
// to what may be recorded.
type MCPServerDeclaration struct {
	Name      string
	Transport string
	// Command is the base name of a stdio server's command ("npx", "python").
	Command string
	// Package is the package a launcher (npx, uvx, ...) starts, without its
	// version; "" when the command is not a known launcher.
	Package string
	// PackagePinned is true when Package carries an exact version.
	PackagePinned bool
	// EndpointHost is the host of a remote server's URL, lower-cased.
	EndpointHost string
	// PlainHTTP is true when the URL scheme is http.
	PlainHTTP bool
	Auth      string
	// Tools are the tool names the declaration lists, sorted.
	Tools []string
}

var (
	mcpServerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:@/-]{0,63}$`)
	mcpCommandPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	mcpPackagePattern    = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}$`)
	mcpHostPattern       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,8}$`)
	mcpExactVersion      = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.-]{1,32})?$`)
	mcpImageDigest       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	secretPrefixes       = []string{"sk-", "ghp_", "gho_", "ghs_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "akia", "aiza", "eyj", "glpat-", "dapi"}
)

// looksLikeSecret is true for a value that is shaped like a credential: a
// known token prefix, or a long run of letters and digits mixed together. Such
// a value is never recorded, whatever member it was found in.
func looksLikeSecret(value string) bool {
	lower := strings.ToLower(value)
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(lower, prefix) && len(value) >= len(prefix)+12 {
			return true
		}
	}
	for _, run := range strings.FieldsFunc(value, func(character rune) bool {
		return !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
	}) {
		if len(run) < 20 {
			continue
		}
		letters, digits := 0, 0
		for _, character := range run {
			if character >= '0' && character <= '9' {
				digits++
			} else {
				letters++
			}
		}
		if letters >= 4 && digits >= 4 {
			return true
		}
	}
	return false
}

// MCPConfigPaths are the repository paths ParseMCPConfig reads, matched at
// the repository root or in any directory (lower-case, as Paths matches).
var MCPConfigPaths = []string{".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json"}

// IsMCPConfigPath reports whether a repository path is an MCP configuration
// file.
func IsMCPConfigPath(value string) bool {
	clean := strings.ToLower(path.Clean("/" + value))
	for _, candidate := range MCPConfigPaths {
		if strings.HasSuffix(clean, "/"+candidate) {
			return true
		}
	}
	return false
}

// mcpServerEntry is the union of the members the common clients write. The
// member names are from the clients' documentation as remembered, not from a
// schema: UNVERIFIED. An unknown member is ignored, and env and header values
// are never decoded (only their member names are read).
type mcpServerEntry struct {
	Type      string                     `json:"type"`
	Transport string                     `json:"transport"`
	Command   json.RawMessage            `json:"command"`
	Args      []json.RawMessage          `json:"args"`
	URL       string                     `json:"url"`
	ServerURL string                     `json:"serverUrl"`
	HTTPURL   string                     `json:"httpUrl"`
	Headers   map[string]json.RawMessage `json:"headers"`
	Env       map[string]json.RawMessage `json:"env"`
	OAuth     json.RawMessage            `json:"oauth"`
	Auth      json.RawMessage            `json:"auth"`
	// Tool lists: Cline and Amazon Q write autoApprove, Roo Code alwaysAllow,
	// Gemini CLI includeTools. UNVERIFIED.
	AutoApprove  []json.RawMessage `json:"autoApprove"`
	AlwaysAllow  []json.RawMessage `json:"alwaysAllow"`
	IncludeTools []json.RawMessage `json:"includeTools"`
}

// ParseMCPConfig returns the servers a configuration file declares, sorted by
// name. The servers are under mcpServers (Claude, Cursor, .mcp.json) or
// servers (.vscode/mcp.json). A file that is not such a document, or is larger
// than the caller's limit, declares nothing.
func ParseMCPConfig(content []byte) []MCPServerDeclaration {
	var document struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	if json.Unmarshal(content, &document) != nil {
		return nil
	}
	declared := document.MCPServers
	if len(declared) == 0 {
		declared = document.Servers
	}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	servers := make([]MCPServerDeclaration, 0, len(names))
	for _, name := range names {
		var entry mcpServerEntry
		if !mcpServerNamePattern.MatchString(name) || strings.TrimSpace(name) != name || looksLikeSecret(name) || json.Unmarshal(declared[name], &entry) != nil {
			continue
		}
		if server, ok := declaredMCPServer(name, entry); ok {
			servers = append(servers, server)
			if len(servers) == MaximumMCPServersPerFile {
				break
			}
		}
	}
	return servers
}

func declaredMCPServer(name string, entry mcpServerEntry) (MCPServerDeclaration, bool) {
	server := MCPServerDeclaration{Name: name, Tools: declaredMCPTools(entry.AutoApprove, entry.AlwaysAllow, entry.IncludeTools)}
	remote := entry.URL
	if remote == "" {
		remote = entry.ServerURL
	}
	if remote == "" {
		remote = entry.HTTPURL
	}
	var command string
	_ = json.Unmarshal(entry.Command, &command)
	args := make([]string, 0, len(entry.Args))
	for _, raw := range entry.Args {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			args = append(args, value)
		}
	}
	switch {
	case remote != "":
		host, plain, credential, ok := mcpURLHost(remote)
		if !ok {
			return MCPServerDeclaration{}, false
		}
		server.EndpointHost, server.PlainHTTP = host, plain
		server.Transport = MCPTransportHTTP
		if kind := strings.ToLower(entry.Type + entry.Transport); strings.Contains(kind, "sse") || strings.HasSuffix(strings.TrimSuffix(strings.SplitN(remote, "?", 2)[0], "/"), "/sse") {
			server.Transport = MCPTransportSSE
		}
		server.Auth = MCPAuthNone
		if credential || len(entry.OAuth) > 0 || len(entry.Auth) > 0 || credentialNames(entry.Headers) || credentialNames(entry.Env) {
			server.Auth = MCPAuthDeclared
		}
	case command != "":
		base := path.Base(strings.ReplaceAll(command, `\`, "/"))
		base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".cmd")
		if !mcpCommandPattern.MatchString(base) || looksLikeSecret(base) {
			return MCPServerDeclaration{}, false
		}
		server.Transport, server.Command, server.Auth = MCPTransportStdio, base, MCPAuthNotApplicable
		server.Package, server.PackagePinned = launchedPackage(strings.ToLower(base), args)
		// mcp-remote is a stdio bridge to a remote server: the server is the
		// host it is pointed at.
		if server.Package == "mcp-remote" || strings.ToLower(base) == "mcp-remote" {
			for _, arg := range args {
				if host, plain, credential, ok := mcpURLHost(arg); ok {
					server.EndpointHost, server.PlainHTTP, server.Auth = host, plain, MCPAuthNone
					if credential || credentialNames(entry.Env) || hasHeaderArgument(args) {
						server.Auth = MCPAuthDeclared
					}
					break
				}
			}
		}
	default:
		return MCPServerDeclaration{}, false
	}
	return server, true
}

func hasHeaderArgument(args []string) bool {
	for _, arg := range args {
		if arg == "--header" || arg == "-H" || strings.HasPrefix(arg, "--header=") {
			return true
		}
	}
	return false
}

// mcpURLHost returns the host of an http or https URL, whether the scheme is
// http, and whether the URL itself carries a credential (user information or
// a key-like query parameter name). Nothing else of the URL is returned.
func mcpURLHost(value string) (string, bool, bool, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false, false, false
	}
	host := strings.ToLower(parsed.Hostname())
	if len(host) < 1 || len(host) > 253 || !mcpHostPattern.MatchString(host) {
		return "", false, false, false
	}
	credential := parsed.User != nil
	for name := range parsed.Query() {
		if credentialName(name) {
			credential = true
		}
	}
	return host, parsed.Scheme == "http", credential, true
}

func credentialName(name string) bool {
	lower := strings.ToLower(name)
	for _, fragment := range []string{"authorization", "token", "api-key", "api_key", "apikey", "secret", "password", "cookie", "x-api-key", "bearer", "credential"} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// credentialNames reports whether any member name of a header or environment
// object names a credential. The values are never decoded.
func credentialNames(members map[string]json.RawMessage) bool {
	for name := range members {
		if credentialName(name) {
			return true
		}
	}
	return false
}

func declaredMCPTools(lists ...[]json.RawMessage) []string {
	seen := map[string]bool{}
	for _, list := range lists {
		for _, raw := range list {
			var name string
			if json.Unmarshal(raw, &name) == nil && ValidMCPToolName(name) {
				seen[name] = true
			}
		}
	}
	return boundedSortedNames(seen, MaximumMCPToolsPerServer)
}

func boundedSortedNames(seen map[string]bool, maximum int) []string {
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maximum {
		names = names[:maximum]
	}
	return names
}

// launchedPackage returns the package a launcher command starts and whether
// it is pinned to an exact version. Launchers: npx, bunx, pnpx and "pnpm dlx"
// (npm), uvx, "uv tool run" and "pipx run" (PyPI), "docker run" (an image).
// A flag is skipped; --from and -p name the package explicitly. Anything that
// is not shaped like a package name is not recorded.
func launchedPackage(command string, args []string) (string, bool) {
	ecosystem := ""
	switch command {
	case "npx", "bunx", "pnpx":
		ecosystem = "npm"
	case "uvx":
		ecosystem = "pypi"
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			ecosystem, args = "npm", args[1:]
		}
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			ecosystem, args = "pypi", args[2:]
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			ecosystem, args = "pypi", args[1:]
		}
	case "docker", "podman":
		if len(args) > 0 && args[0] == "run" {
			ecosystem, args = "image", args[1:]
		}
	}
	if ecosystem == "" {
		return "", false
	}
	specifier := ""
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if (arg == "--from" || arg == "-p" || arg == "--package") && ecosystem != "image" && index+1 < len(args) {
			specifier = args[index+1]
			break
		}
		if strings.HasPrefix(arg, "--from=") || strings.HasPrefix(arg, "--package=") {
			specifier = arg[strings.Index(arg, "=")+1:]
			break
		}
		if strings.HasPrefix(arg, "-") {
			// docker run flags that take a value.
			if ecosystem == "image" && !strings.Contains(arg, "=") && dockerValueFlags[arg] {
				index++
			}
			continue
		}
		specifier = arg
		break
	}
	if specifier == "" {
		return "", false
	}
	name, version := specifier, ""
	switch ecosystem {
	case "npm":
		if index := strings.LastIndex(specifier, "@"); index > 0 {
			name, version = specifier[:index], specifier[index+1:]
		}
	case "pypi":
		for _, separator := range []string{"==", "@"} {
			if index := strings.Index(specifier, separator); index > 0 {
				name, version = specifier[:index], specifier[index+len(separator):]
				break
			}
		}
		if index := strings.IndexAny(name, "[<>~!="); index > 0 {
			name = name[:index]
		}
	case "image":
		if index := strings.Index(specifier, "@"); index > 0 {
			name, version = specifier[:index], specifier[index+1:]
		} else if index := strings.LastIndex(specifier, ":"); index > strings.LastIndex(specifier, "/") {
			name, version = specifier[:index], specifier[index+1:]
		}
	}
	name = strings.ToLower(name)
	if ecosystem == "image" {
		// A registry host and path: keep the repository, drop nothing else.
		if len(name) > 128 || strings.ContainsAny(name, " \t@?#") || !mcpPackagePattern.MatchString(strings.ReplaceAll(strings.ReplaceAll(name, "/", "-"), ":", "-")) {
			return "", false
		}
	} else if !mcpPackagePattern.MatchString(name) {
		return "", false
	}
	if looksLikeSecret(name) {
		return "", false
	}
	pinned := mcpExactVersion.MatchString(version) || ecosystem == "image" && (mcpImageDigest.MatchString(version) || version != "" && version != "latest")
	return name, pinned
}

var dockerValueFlags = map[string]bool{"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true, "--name": true, "--network": true, "--mount": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--env-file": true, "--entrypoint": true, "-l": true, "--label": true}

// ClaudeSettingsToolPermissions reads a .claude/settings.json and returns,
// per MCP server name, the tools its permission rules name
// ("mcp__<server>__<tool>" in permissions.allow, ask or deny). The rule
// grammar is from the client's documentation as remembered: UNVERIFIED.
func ClaudeSettingsToolPermissions(content []byte) map[string][]string {
	var document struct {
		Permissions struct {
			Allow []json.RawMessage `json:"allow"`
			Ask   []json.RawMessage `json:"ask"`
			Deny  []json.RawMessage `json:"deny"`
		} `json:"permissions"`
	}
	if json.Unmarshal(content, &document) != nil {
		return nil
	}
	found := map[string]map[string]bool{}
	for _, list := range [][]json.RawMessage{document.Permissions.Allow, document.Permissions.Ask, document.Permissions.Deny} {
		for _, raw := range list {
			var rule string
			if json.Unmarshal(raw, &rule) != nil || !strings.HasPrefix(rule, "mcp__") {
				continue
			}
			server, tool, named := strings.Cut(strings.TrimPrefix(rule, "mcp__"), "__")
			if !named || !mcpServerNamePattern.MatchString(server) || !ValidMCPToolName(tool) {
				continue
			}
			if found[server] == nil {
				found[server] = map[string]bool{}
			}
			found[server][tool] = true
		}
	}
	result := make(map[string][]string, len(found))
	for server, tools := range found {
		result[server] = boundedSortedNames(tools, MaximumMCPToolsPerServer)
	}
	return result
}

// IsClaudeSettingsPath reports whether a repository path is a shared Claude
// Code settings file.
func IsClaudeSettingsPath(value string) bool {
	return strings.HasSuffix(strings.ToLower(path.Clean("/"+value)), "/.claude/settings.json")
}

// Skill kinds.
const (
	// SkillKindSkill: a directory holding a SKILL.md.
	SkillKindSkill = "skill"
	// SkillKindInstructions: an agent instruction file (AGENTS.md, CLAUDE.md).
	SkillKindInstructions = "agent_instructions"
	// SkillKindRules: editor rule files (.cursor/rules, .cursorrules).
	SkillKindRules = "editor_rules"
)

// Skill is an agent skill or instruction file of a repository: where it is
// and what kind it is. Its contents are never read.
type Skill struct {
	Path string
	Kind string
}

var skillPathPattern = regexp.MustCompile(`^[A-Za-z0-9._@+ /-]{1,512}$`)

// SkillPaths returns the skills and instruction files among a repository's
// file paths, sorted by path, at most MaximumSkillsPerProject. A skill is the
// directory of a SKILL.md; every file under .cursor/rules is one rule file.
func SkillPaths(paths ...string) []Skill {
	found := map[string]string{}
	for _, value := range paths {
		clean := strings.TrimPrefix(path.Clean("/"+value), "/")
		if len(clean) > 512 || !skillPathPattern.MatchString(clean) || strings.TrimSpace(clean) != clean {
			continue
		}
		base, lower := path.Base(clean), strings.ToLower(clean)
		switch {
		case base == "SKILL.md":
			directory := path.Dir(clean)
			if directory == "." {
				directory = "SKILL.md"
			}
			found[directory] = SkillKindSkill
		case base == "AGENTS.md" || base == "CLAUDE.md" || lower == ".github/copilot-instructions.md":
			found[clean] = SkillKindInstructions
		case base == ".cursorrules" || strings.Contains("/"+lower, "/.cursor/rules/"):
			found[clean] = SkillKindRules
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > MaximumSkillsPerProject {
		names = names[:MaximumSkillsPerProject]
	}
	skills := make([]Skill, 0, len(names))
	for _, name := range names {
		skills = append(skills, Skill{Path: name, Kind: found[name]})
	}
	return skills
}

// MCPServerImage reports whether a container image reference names an MCP
// server image: a repository whose last path element starts or ends with
// "mcp-server" or "mcp" as a word ("ghcr.io/github/github-mcp-server",
// "mcp/postgres"). The tag and digest are not read.
func MCPServerImage(reference string) bool {
	repository := strings.ToLower(reference)
	if index := strings.Index(repository, "@"); index >= 0 {
		repository = repository[:index]
	}
	if index := strings.LastIndex(repository, ":"); index > strings.LastIndex(repository, "/") {
		repository = repository[:index]
	}
	elements := strings.Split(repository, "/")
	last := elements[len(elements)-1]
	if strings.Contains(last, "mcp-server") || strings.Contains(last, "mcp_server") || strings.HasSuffix(last, "-mcp") || strings.HasPrefix(last, "mcp-") {
		return true
	}
	// Docker's catalog publishes servers as mcp/<name>.
	return len(elements) >= 2 && elements[len(elements)-2] == "mcp"
}

// MCPServerCommand reports whether a container's command and arguments start
// an MCP server.
func MCPServerCommand(elements ...string) bool {
	for _, element := range elements {
		lower := strings.ToLower(element)
		for _, fragment := range []string{"mcp-server", "mcp_server", "@modelcontextprotocol/server-", "fastmcp"} {
			if strings.Contains(lower, fragment) {
				return true
			}
		}
	}
	return false
}

// IsRemoteMCPHost reports whether a DNS name is a hosted MCP server by the
// catalog's rule (mcp.<vendor domain>), and returns the host in lower case.
// It is the one case where the name itself, not only a token, may be kept:
// the name is the server's identity and is in the catalog by rule.
func IsRemoteMCPHost(name string) (string, bool) {
	token, _, ok := classifyEgressHost(name)
	host := strings.TrimSuffix(strings.ToLower(name), ".")
	if !ok || token != "mcp_remote" || !mcpHostPattern.MatchString(host) {
		return "", false
	}
	return host, true
}
