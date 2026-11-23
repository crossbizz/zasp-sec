package addons

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
)

var (
	npmName           = regexp.MustCompile("^(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]{0,212}$")
	jsVersion         = regexp.MustCompile("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$")
	pythonRequirement = regexp.MustCompile("^([A-Za-z0-9][A-Za-z0-9_.-]{0,150})(?:\\[[A-Za-z0-9_.,-]+\\])?\\s*(.*)$")
	pythonVersion     = regexp.MustCompile("^==([0-9][0-9a-zA-Z.+!-]{0,85})$")
	shellPattern      = regexp.MustCompile(`(?m)(?:^|[^\w.])(?:os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|child_process(?:["']\))?\.exec(?:Sync)?\s*\(|Invoke-Expression\b)`)
	networkPattern    = regexp.MustCompile(`(?m)(?:^|[^\w.])(?:curl\s|wget\s|requests\.(?:get|post|put)\s*\(|fetch\s*\(|Invoke-WebRequest\b)`)
)

const maxDependencies = 2048

func (s *scanner) finding(path, id, severity, message, fix string) {
	f := Finding{RuleID: id, Severity: severity, Path: path, Message: message, Remediation: fix,
		FrameworkEvidence: addonevidence.References(id, s.report.Ruleset)}
	// Directory and archive scans inspect the bytes just added to Files.
	if n := len(s.report.Files); n > 0 && s.report.Files[n-1].Path == path {
		f.FileSHA256 = s.report.Files[n-1].SHA256
	}
	s.report.Findings = append(s.report.Findings, f)
}

func (s *scanner) inspect(p string, data []byte) {
	n := path.Base(p)
	current := s.report.Ruleset == addonevidence.CurrentRuleset
	if current && instructionFile(n) {
		s.instructionsV2(p, data)
	}
	switch {
	case n == "package.json":
		var m struct {
			License     json.RawMessage   `json:"license"`
			Runtime     map[string]string `json:"dependencies"`
			Development map[string]string `json:"devDependencies"`
			Optional    map[string]string `json:"optionalDependencies"`
			Peer        map[string]string `json:"peerDependencies"`
		}
		if err := json.Unmarshal(data, &m); err != nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			s.skip(p, "invalid_declaration")
			return
		}
		var license string
		if json.Unmarshal(m.License, &license) == nil && strings.TrimSpace(license) != "" {
			s.declaredLicense = true
		}
		if len(m.Runtime)+len(m.Optional)+len(m.Peer)+len(m.Development) > maxDependencies-len(s.report.Dependencies) {
			s.skip(p, "dependency_limit")
			return
		}
		unpinned := false
		for _, group := range []map[string]string{m.Runtime, m.Development, m.Optional, m.Peer} {
			for name, spec := range group {
				version := ""
				if jsVersion.MatchString(spec) {
					version = spec
				} else {
					unpinned = true
				}
				if npmName.MatchString(name) {
					s.report.Dependencies = append(s.report.Dependencies, Dependency{name, "npm", version, p})
				}
			}
		}
		if unpinned {
			s.unpinned(p)
		}
	case n == "requirements.txt":
		unpinned := false
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if line == "" {
				continue
			}
			line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			if strings.HasPrefix(line, "-") {
				s.skip(p, "unsupported_requirement_directive")
				continue
			}
			parts := pythonRequirement.FindStringSubmatch(line)
			if parts == nil {
				s.skip(p, "unsupported_requirement")
				continue
			}
			if tail := parts[2]; tail != "" && !strings.ContainsAny(tail[:1], "=~!<>@") {
				s.skip(p, "unsupported_requirement")
				continue
			}
			version := ""
			if match := pythonVersion.FindStringSubmatch(parts[2]); match != nil {
				version = match[1]
			} else {
				unpinned = true
			}
			if len(s.report.Dependencies) >= maxDependencies {
				s.skip(p, "dependency_limit")
				break
			}
			s.report.Dependencies = append(s.report.Dependencies, Dependency{parts[1], "pypi", version, p})
		}
		if unpinned {
			s.unpinned(p)
		}
	case isMCP(n):
		s.inspectMCP(p, data)
	case n == "SKILL.md":
		if bytes.Contains(data, []byte("<!--")) || bytes.ContainsAny(data, "\u200b\u202a\u202b\u202d\u202e\u2066\u2067\u2068") {
			s.finding(p, "instruction.hidden_text", "low", "Instruction file contains hidden markup or text-direction controls.", "Inspect the source text and remove unintended hidden instructions.")
		}
	case isScript(n):
		if current {
			s.scriptV2(p, data)
			return
		}
		if shellPattern.Match(data) {
			s.finding(p, "script.shell_execution", "medium", "Script references a process execution API.", "Review the subprocess and the minimum permissions it needs.")
		}
		if networkPattern.Match(data) {
			s.finding(p, "script.network_access", "medium", "Script references a network client.", "Review the destination and which data the script may send.")
		}
	}
}

func isScript(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".sh", ".bash", ".py", ".js", ".cjs", ".mjs", ".ts", ".ps1":
		return true
	}
	return false
}

func (s *scanner) unpinned(p string) {
	s.finding(p, "dependency.unpinned", "medium", "A dependency declaration allows multiple versions or a non-version source.", "Pin an approved version and review the lockfile and resolved dependencies.")
}

func (s *scanner) inspectMCP(p string, data []byte) {
	var m struct {
		Servers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &m); err != nil || m.Servers == nil {
		s.skip(p, "invalid_mcp_declaration")
		return
	}
	remote, unpinned, execRisk := false, false, false
	bad := false
	for _, raw := range m.Servers {
		var server struct {
			Command string
			Args    []string
			URL     string
			Headers json.RawMessage `json:"headers"`
			Auth    json.RawMessage `json:"auth"`
		}
		if err := json.Unmarshal(raw, &server); err != nil || (server.Command == "" && server.URL == "") {
			bad = true
			continue
		}
		if s.report.Ruleset == addonevidence.CurrentRuleset && (launcherNeedsPin(server.Command, server.Args) || insecureMCPEndpoint(server.URL, server.Headers, server.Auth)) {
			execRisk = true
		}
		if server.URL != "" {
			remote = true
		}
		command := strings.ToLower(path.Base(strings.ReplaceAll(server.Command, "\\", "/")))
		if command != "npx" && command != "uvx" {
			continue
		}
		// Only simple, unambiguous launch forms establish a pin locally.
		pinned := false
		for _, arg := range server.Args {
			if arg == "-y" || arg == "--yes" {
				continue
			}
			if command == "npx" {
				i := strings.LastIndexByte(arg, '@')
				pinned = i > 0 && npmName.MatchString(arg[:i]) && jsVersion.MatchString(arg[i+1:])
			} else {
				parts := strings.SplitN(arg, "==", 2)
				pinned = len(parts) == 2 && pythonVersion.MatchString("=="+parts[1])
			}
			break
		}
		if !pinned {
			unpinned = true
		}
	}
	if bad {
		s.skip(p, "invalid_mcp_declaration")
	}
	if execRisk {
		s.finding(p, "mcp.unpinned_exec", "high", "A package launcher has no exact release or a plaintext MCP destination has no declared authorization header.", "Pin the reviewed release and use an authenticated encrypted destination.")
	}
	if remote {
		s.finding(p, "mcp.remote_endpoint", "low", "The declaration references a remote MCP service. Its implementation is unverified.", "Review the service owner, permissions and independently observed tool schema.")
	}
	if unpinned {
		s.finding(p, "mcp.unpinned_launcher", "medium", "A package launcher has no recognized exact package version.", "Pin and review the package before allowing this launcher.")
	}
}
