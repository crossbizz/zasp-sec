package addons

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

var (
	readOperand      = regexp.MustCompile(`(?i)\b(?:open|read_text|read_bytes|readFileSync|readFile|Get-Content|cat)\b`)
	sensitiveOperand = regexp.MustCompile(`(?i)(?:^|[/\\~])(?:\.ssh|\.aws)(?:[/\\]|$)|(?:^|[/\\])\.env(?:[.\x22\x27/\\\s]|$)|(?:\.kube[/\\]config|KUBECONFIG|(?:Network[/\\])?Cookies(?:\.sqlite)?|cookies\.sqlite)(?:[\x22\x27\s)]|$)`)
	writeOnlyMode    = regexp.MustCompile(`,\s*(?:mode\s*=\s*)?["'][wax]b?["']`)
	pathRead         = regexp.MustCompile(`\bPath\s*\([^\n)]{1,384}\)\s*\.\s*(?:read_text|read_bytes)\s*\(`)
	keychainRead     = regexp.MustCompile(`(?i)\bsecurity\s+find-(?:generic|internet)-password\b`)
	pipeToExec       = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\r\n|;]{0,768}\|\s*(?:sh|bash|zsh|python(?:3)?)\b|\bInvoke-Expression\s*\(\s*Invoke-WebRequest\b|\beval\s*\(\s*atob\s*\(|\bexec\s*\(\s*base64\.b64decode\s*\(`)
)

func (s *scanner) scriptV2(file string, data []byte) {
	clean, code := scriptViews(file, data)
	if shellPattern.Match(code) {
		s.finding(file, "script.shell_execution", "medium", "Script references a process execution API.", "Review the subprocess and the minimum permissions it needs.")
	}
	if networkPattern.Match(code) {
		s.finding(file, "script.network_access", "medium", "Script references a network client.", "Review the destination and the data sent.")
	}
	readsSensitive := keychainRead.Match(code)
	for _, loc := range readOperand.FindAllIndex(code, 256) {
		// Match only the operation's first operand on the same line. Preserve its
		// quotes in the clean view while excluding operations named inside strings.
		tail := clean[loc[1]:min(len(clean), loc[1]+384)]
		if bytes.EqualFold(code[loc[0]:loc[1]], []byte("open")) {
			call := tail
			if end := bytes.IndexAny(call, "\n\r;)"); end >= 0 {
				call = call[:end]
			}
			if writeOnlyMode.Match(call) {
				continue
			}
		}
		if end := bytes.IndexAny(tail, "\n\r,;)"); end >= 0 {
			tail = tail[:end]
		}
		if sensitiveOperand.Match(bytes.TrimLeft(tail, " (\t\x22\x27")) {
			readsSensitive = true
			break
		}
	}
	if !readsSensitive {
		for _, loc := range pathRead.FindAllIndex(code, 256) {
			if sensitiveOperand.Match(clean[loc[0]:loc[1]]) {
				readsSensitive = true
				break
			}
		}
	}
	if readsSensitive {
		s.finding(file, "script.credential_path_access", "high", "A read references a credential-bearing location.", "Review why this input is required and restrict access to the approved credential.")
	}
	if pipeToExec.Match(code) {
		s.finding(file, "script.remote_exec_pipe", "high", "A download or decoded value is passed directly to an interpreter.", "Review the fixed artifact before running it and verify its source and digest.")
	}
}

func instructionFile(name string) bool {
	switch strings.ToLower(name) {
	case "skill.md", "agents.md", "claude.md", "instructions.md", "copilot-instructions.md":
		return true
	}
	return false
}

func (s *scanner) instructionsV2(file string, data []byte) {
	if guardrail.ContainsInstructionOverride(string(data)) {
		s.finding(file, "instruction.override", "high", "Instruction text contains a directive to replace earlier instructions or a forged role marker.", "Inspect the instruction in context and remove unauthorized directives.")
	}
}

func launcherNeedsPin(command string, args []string) bool {
	cmd := strings.ToLower(path.Base(strings.ReplaceAll(command, "\\", "/")))
	if cmd != "npx" && cmd != "uvx" && cmd != "pipx" {
		return false
	}
	for _, arg := range args {
		if arg == "-y" || arg == "--yes" || (cmd == "pipx" && arg == "run") {
			continue
		}
		if cmd == "npx" {
			i := strings.LastIndexByte(arg, '@')
			return i <= 0 || !npmName.MatchString(arg[:i]) || !validAdvisoryRelease("npm", arg[i+1:])
		}
		name, version, ok := strings.Cut(arg, "==")
		return !ok || !advisoryName.MatchString(name) || !validAdvisoryRelease("pypi", version)
	}
	return true
}

func insecureMCPEndpoint(address string, raw, auth json.RawMessage) bool {
	destination, err := url.Parse(address)
	if err != nil || destination.Scheme != "http" || destination.Host == "" || destination.User != nil || len(auth) > 0 {
		return false
	}
	var headers map[string]string
	if len(raw) > 0 && json.Unmarshal(raw, &headers) != nil {
		return false
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") && strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}
