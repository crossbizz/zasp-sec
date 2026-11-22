package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (s source) profile() string {
	if s.harness == "Codex" {
		return "codex-local-skills.v1"
	}
	return "claude-code-local-addons.v1"
}

func validProfile(harness, cwd, project string) bool {
	switch harness {
	case "claude-code":
		return cwd == "."
	case "codex", "all":
		return cwd == "." || (project != "" && len(cwd) <= 1024 && filepath.IsLocal(cwd) && filepath.Clean(cwd) == cwd &&
			len(strings.Split(filepath.ToSlash(cwd), "/")) <= 16)
	default:
		return false
	}
}

// The selected project is the outer boundary. An optional working directory
// reproduces nested repository lookup without walking above that boundary.
func codexSources(project, scope, cwd string) []source {
	var locations []source
	if scope == "all" || scope == "personal" {
		home, _ := os.UserHomeDir()
		locations = append(locations, source{"Codex", "personal", home, ".agents/skills", false})
	}
	if scope == "all" || scope == "managed" {
		var base string
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			base = "/etc"
		}
		locations = append(locations, source{"Codex", "managed", base, "codex/skills", false})
	}
	if project != "" && (scope == "all" || scope == "project") {
		for dir := cwd; ; dir = filepath.Dir(dir) {
			locations = append(locations, source{"Codex", "project", project, filepath.ToSlash(filepath.Join(dir, ".agents", "skills")), false})
			if dir == "." {
				break
			}
		}
	}
	return locations
}
