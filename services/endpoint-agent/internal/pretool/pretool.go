// Package pretool classifies a bounded, local tool request. It returns stable
// rule identifiers and reason codes; raw arguments never leave the evaluator.
package pretool

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

type Result struct {
	WouldBlock   bool
	RuleID       string
	ReasonCode   string
	NextStepHint string
	Unavailable  bool
}

func blocked(rule, reason string) Result {
	return Result{WouldBlock: true, RuleID: rule, ReasonCode: reason, NextStepHint: "review_endpoint_policy"}
}
func unknown(rule string) Result {
	return Result{Unavailable: true, RuleID: rule, ReasonCode: "input_unavailable", NextStepHint: "contact_endpoint_admin"}
}

var shellIndicators = map[string]*regexp.Regexp{
	"shell_pipe":        regexp.MustCompile(`(?i)\b(curl|wget)\b[^;\n|]*\|\s*(?:/[^\s|]+/)?(?:ba)?sh\b`),
	"secret_transfer":   regexp.MustCompile(`(?i)\b(curl|wget|scp|rsync|nc|netcat)\b[^\n]*(?:/(?:\.aws|\.ssh)(?:/|\s|$)|(?:/|\s)\.env(?:\s|$))`),
	"reverse_shell":     regexp.MustCompile(`(?i)(?:/(?:dev)/(?:tcp|udp)/|\b(?:nc|netcat)\b[^;\n]*\s-(?:e|c)\s)`),
	"privileged_mode":   regexp.MustCompile(`(?i)\bchmod\s+(?:[ugoa]*\+s|[46][0-7]{3})\b`),
	"encoded_execution": regexp.MustCompile(`(?i)\bbase64\b[^;\n|]*(?:-d|--decode)\s*\|\s*(?:/[^\s|]+/)?(?:ba)?sh\b`),
}

func domainMatches(host string, patterns []string) bool {
	hostname := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(hostname, p[1:]) {
				return true
			}
		} else if hostname == p {
			return true
		}
	}
	return false
}
func matchesTool(tool string, values []string, denylist bool) bool {
	for _, v := range values {
		if v == tool {
			return true
		}
		if !strings.HasSuffix(v, "__*") {
			continue
		}
		remainder, ok := strings.CutPrefix(tool, strings.TrimSuffix(v, "*"))
		// Multiple MCP separators can make a nested server indistinguishable
		// from a tool name. An allowlist requires an unambiguous namespace.
		if ok && remainder != "" && (denylist || !strings.Contains(remainder, "__")) {
			return true
		}
	}
	return false
}
func destinations(v any, key string, depth int, result *[]string) bool {
	if depth > 8 || len(*result) > 32 {
		return false
	}
	switch a := v.(type) {
	case map[string]any:
		for k, child := range a {
			if !destinations(child, k, depth+1, result) {
				return false
			}
		}
	case []any:
		for _, child := range a {
			if !destinations(child, key, depth+1, result) {
				return false
			}
		}
	case string:
		location := strings.ToLower(key)
		explicit := location == "url" || location == "uri" || location == "destination_url" || location == "endpoint_url" || location == "host" || location == "domain" || location == "destination"
		if !explicit && !strings.Contains(a, "://") {
			return true
		}
		if len(a) > 2048 {
			return false
		}
		if !strings.Contains(a, "://") && (location == "host" || location == "domain" || location == "destination") {
			a = "https://" + a
		}
		u, err := url.Parse(a)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return false
		}
		*result = append(*result, u.Hostname())
	}
	return true
}
func sensitive(value, home, cwd, tool string, classes []string) (string, bool) {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) || strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//") {
		return "unverifiable_path", true
	}
	// Reject ambiguous traversal before joining or cleaning. The pathname seen
	// by a tool may resolve through a symlink before the ".." component.
	for _, elem := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if elem == ".." {
			return "unverifiable_path", true
		}
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, "~\\") {
		if !filepath.IsAbs(home) {
			return "", false
		}
		value = filepath.Join(home, value[2:])
	} else if strings.HasPrefix(value, "~") || strings.Contains(value, "$") {
		return "", false
	}
	if !filepath.IsAbs(value) {
		if !filepath.IsAbs(cwd) {
			return "", false
		}
		value = filepath.Join(cwd, value)
	}
	p := filepath.Clean(value)
	segments := strings.Split(strings.ToLower(filepath.ToSlash(p)), "/")
	for _, c := range classes {
		for n, v := range segments {
			switch c {
			case "ssh":
				if v == ".ssh" {
					return c, true
				}
			case "aws":
				if v == ".aws" {
					return c, true
				}
			case "gcloud":
				if n > 0 && segments[n-1] == ".config" && v == "gcloud" {
					return c, true
				}
			case "dotenv":
				if v == ".env" || strings.HasPrefix(v, ".env.") {
					return c, true
				}
			case "pem":
				if strings.HasSuffix(v, ".pem") {
					return c, true
				}
			case "identity_key":
				if strings.Contains(v, "id_rsa") {
					return c, true
				}
			}
		}
	}
	if (tool == "Glob" || tool == "Grep") && filepath.IsAbs(home) {
		rel, err := filepath.Rel(p, home)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", false
		}
	}
	return pathChain(p)
}
func Evaluate(policy endpointprotocol.PolicyV2, tool string, payload json.RawMessage, home, cwd string) Result {
	var args map[string]any
	if len(payload) > 16<<10 || json.Unmarshal(payload, &args) != nil || args == nil {
		return unknown("")
	}
	var incomplete Result
	for _, r := range policy.Rules {
		match := evaluateRule(r, tool, args, home, cwd)
		if match.WouldBlock {
			return match
		}
		if match.Unavailable && !incomplete.Unavailable {
			incomplete = match
		}
	}
	if incomplete.Unavailable {
		return incomplete
	}
	return Result{ReasonCode: "within_scope"}
}

// evaluateRule never reads file contents, executes commands, or resolves DNS.
func evaluateRule(r endpointprotocol.PretoolRule, tool string, args map[string]any, home, cwd string) Result {
	switch r.Type {
	case "mcp_tool_policy", "destination_domain_policy":
		isMCP := strings.HasPrefix(tool, "mcp__")
		if !isMCP && (r.Type == "mcp_tool_policy" || tool != "WebFetch") {
			return Result{}
		}
		hosts := []string{}
		if r.Type == "mcp_tool_policy" {
			matched := matchesTool(tool, r.Values, r.Match == "denylist")
			if (r.Match == "allowlist") != matched {
				return blocked(r.ID, "mcp_tool_restricted")
			}
			if len(r.AllowedDestinations) == 0 {
				return Result{}
			}
			if !destinations(args, "", 0, &hosts) || len(hosts) == 0 {
				return unknown(r.ID)
			}
			for _, host := range hosts {
				if !domainMatches(host, r.AllowedDestinations) {
					return blocked(r.ID, "destination_restricted")
				}
			}
		} else {
			if !destinations(args, "", 0, &hosts) || (tool == "WebFetch" && len(hosts) == 0) {
				return unknown(r.ID)
			}
			for _, host := range hosts {
				if (r.Match == "allowlist") != domainMatches(host, r.Values) {
					return blocked(r.ID, "destination_restricted")
				}
			}
		}
	case "shell_command_policy":
		if tool != "Bash" {
			return Result{}
		}
		command, ok := args["command"].(string)
		if !ok || len(command) == 0 || len(command) > 8192 {
			return unknown(r.ID)
		}
		for _, code := range r.Values {
			indicator := shellIndicators[code]
			if indicator == nil {
				return unknown(r.ID)
			}
			if indicator.MatchString(command) {
				return blocked(r.ID, code)
			}
		}
	case "file_path_policy":
		if !slices.Contains([]string{"Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "apply_patch"}, tool) {
			return Result{}
		}
		location, _ := args["file_path"].(string)
		if tool == "Glob" || tool == "Grep" {
			location, _ = args["path"].(string)
			if location == "" {
				location = cwd
			}
		}
		if tool == "apply_patch" {
			patch, _ := args["command"].(string)
			paths, ok := patchPaths(patch)
			if !ok {
				return unknown(r.ID)
			}
			for _, p := range paths {
				if c, verified := sensitive(p, home, cwd, tool, r.Values); c != "" {
					return blocked(r.ID, c)
				} else if !verified {
					return unknown(r.ID)
				}
			}
			return Result{}
		}
		if tool == "Glob" {
			if pattern, ok := args["pattern"].(string); ok {
				if c, _ := sensitive(pattern, home, location, tool, r.Values); c != "" {
					return blocked(r.ID, c)
				}
			}
		}
		c, ok := sensitive(location, home, cwd, tool, r.Values)
		if c != "" {
			return blocked(r.ID, c)
		}
		if !ok {
			return unknown(r.ID)
		}
	}
	return Result{}
}

// Codex emits apply_patch writes in tool_input.command. A patch may affect
// multiple paths; inspect headers only and never store or apply patch text.
func patchPaths(raw string) ([]string, bool) {
	if len(raw) > 16<<10 {
		return nil, false
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) < 3 || lines[0] != "*** Begin Patch" || lines[len(lines)-1] != "*** End Patch" {
		return nil, false
	}
	var paths []string
	for _, line := range lines[1 : len(lines)-1] {
		if !strings.HasPrefix(line, "*** ") || line == "*** End of File" {
			continue
		}
		var found bool
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if name, ok := strings.CutPrefix(line, prefix); ok && name != "" && len(paths) < 32 {
				paths = append(paths, name)
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return paths, len(paths) > 0
}
