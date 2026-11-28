package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const maxRootEntries = 256
const inventoryBudget = time.Minute

type source struct {
	harness string
	scope   string
	base    string
	rel     string
	mcp     bool
}

type rootCoverage struct {
	Harness string `json:"harness"`
	Profile string `json:"profile"`
	Scope   string `json:"scope"`
	Path    string `json:"root"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

type installation struct {
	Profile        string                      `json:"profile"`
	Enablement     string                      `json:"enablement"`
	Name           string                      `json:"name"`
	Harness        string                      `json:"harness"`
	Type           string                      `json:"type"`
	Scope          string                      `json:"scope"`
	Path           string                      `json:"path"`
	Status         string                      `json:"status"`
	ManifestDigest string                      `json:"manifest_digest,omitempty"`
	SkillScan      *endpointprotocol.SkillScan `json:"skill_scan,omitempty"`
	Findings       int                         `json:"findings_count"`
	Skipped        []addons.Skip               `json:"skipped,omitempty"`
	Usage          string                      `json:"usage"`
	Declaration    *addons.Declaration         `json:"declaration,omitempty"`
}

func claudeSources(project, scope string) []source {
	var locations []source
	if scope == "all" || scope == "personal" {
		home, _ := os.UserHomeDir()
		locations = append(locations, source{"Claude Code", "personal", home, ".claude/skills", false})
	}
	if scope == "all" || scope == "managed" {
		var managed string
		switch runtime.GOOS {
		case "darwin":
			managed = "/Library/Application Support/ClaudeCode"
		case "linux":
			managed = "/etc/claude-code"
		case "windows":
			if programFiles := os.Getenv("ProgramFiles"); filepath.IsAbs(programFiles) {
				managed = filepath.Join(programFiles, "ClaudeCode")
			}
		}
		locations = append(locations, source{"Claude Code", "managed", managed, "skills", false},
			source{"Claude Code", "managed", managed, "managed-mcp.json", true})
	}
	if project != "" && (scope == "all" || scope == "project") {
		locations = append(locations, source{"Claude Code", "project", project, ".claude/skills", false},
			source{"Claude Code", "project", project, ".mcp.json", true})
	}
	return locations
}

func inventory(project, scope, harness, codexCWD string, declarations bool) localReport {
	report := newEnvelope("inventory")
	report.Coverage.Limits = []string{
		"Enabled plugins, synced stores and built-in system skills are outside these local discovery profiles",
		"Installation does not establish use, enablement, effective permissions or approval",
	}
	var enabled []source
	if harness == "claude-code" || harness == "all" {
		enabled = append(enabled, claudeSources(project, scope)...)
		report.Coverage.Limits = append(report.Coverage.Limits, "The Claude Code profile reads skill directories and selected MCP declarations; personal .claude.json is excluded")
	}
	if harness == "codex" || harness == "all" {
		enabled = append(enabled, codexSources(project, scope, codexCWD)...)
		report.Coverage.Limits = append(report.Coverage.Limits, "The Codex profile reads selected .agents/skills roots and documented Unix admin skills. Linked targets and per-user enablement configuration are not read")
	}
	deadline := time.Now().Add(inventoryBudget)
	for _, location := range enabled {
		root := rootCoverage{Harness: location.harness, Profile: location.profile(), Scope: location.scope, Path: location.rel, Status: "complete"}
		items, reason := discover(location, deadline)
		switch {
		case reason == "not_installed":
			root.Status = "absent"
		case reason != "":
			root.Status = "partial"
			root.Reason = reason
			report.Status = "partial"
		}
		report.Coverage.Roots = append(report.Coverage.Roots, root)
		report.Items = append(report.Items, items...)
	}
	if declarations {
		addDeclarations(&report, project, scope, deadline)
	}
	return report
}

func sourceRoot(location source) (*os.Root, string) {
	if location.base == "" {
		if location.harness == "Codex" && location.scope == "managed" {
			return nil, "admin_root_unverified_on_platform"
		}
		return nil, "location_unavailable"
	}
	info, err := os.Lstat(filepath.Clean(location.base))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			switch location.scope {
			case "project":
				return nil, "selected_project_missing"
			case "personal":
				return nil, "home_unavailable"
			}
		}
		return nil, pathReason(err)
	}
	if addons.IsLink(info) {
		return nil, "symlink_skipped"
	}
	if !info.IsDir() {
		return nil, "not_directory"
	}
	root, err := os.OpenRoot(location.base)
	if err != nil {
		return nil, pathReason(err)
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		root.Close()
		return nil, "changed_during_discovery"
	}
	subdir := location.rel
	if location.mcp {
		subdir = filepath.ToSlash(filepath.Dir(filepath.FromSlash(location.rel)))
	}
	if subdir != "." {
		components := strings.Split(subdir, "/")
		for i, component := range components {
			child, reason := addons.OpenDirectory(root, component)
			root.Close()
			if reason == "missing" {
				if location.harness == "Codex" && location.scope == "project" && i < len(components)-2 {
					return nil, "selected_workdir_missing"
				}
				return nil, "not_installed"
			}
			if reason != "" {
				return nil, reason
			}
			root = child
		}
	}
	return root, ""
}

func pathReason(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "not_installed"
	}
	return "unreadable"
}

func discover(location source, deadline time.Time) ([]installation, string) {
	if time.Now().After(deadline) {
		return nil, "time_limit"
	}
	dir, reason := sourceRoot(location)
	if reason != "" {
		return nil, reason
	}
	defer dir.Close()
	if location.mcp {
		name := filepath.Base(location.rel)
		if _, err := dir.Lstat(name); err != nil {
			return nil, pathReason(err)
		}
		item := observed(location, name, addons.ScanIn(dir, name))
		if item.Status != "complete" {
			return []installation{item}, "incomplete_declaration"
		}
		return []installation{item}, ""
	}
	handle, err := dir.Open(".")
	if err != nil {
		return nil, pathReason(err)
	}
	defer handle.Close()
	before, err := handle.Stat()
	if err != nil {
		return nil, "unreadable"
	}
	entries, err := handle.ReadDir(maxRootEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "unreadable"
	}
	if len(entries) > maxRootEntries {
		return nil, "entry_limit"
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var items []installation
	for _, entry := range entries {
		if time.Now().After(deadline) {
			return items, "time_limit"
		}
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		item := observed(location, entry.Name(), addons.ScanIn(dir, entry.Name()))
		if item.Status != "complete" {
			reason = "incomplete_bundles"
		}
		items = append(items, item)
	}
	after, err := handle.Stat()
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		return items, "changed_during_discovery"
	}
	return items, reason
}

func observed(location source, name string, scan addons.Report) installation {
	path := location.rel
	kind := "mcp_declaration"
	var summary *endpointprotocol.SkillScan
	if !location.mcp {
		path += "/" + name
		kind = "skill"
		counts := make(map[string]int)
		for _, finding := range scan.Findings {
			counts[finding.RuleID]++
		}
		summary = &endpointprotocol.SkillScan{Ruleset: scan.Ruleset, RuleCounts: counts, SkippedCount: min(len(scan.Skipped), 1024)}
	}
	return installation{Name: name, Harness: location.harness, Profile: location.profile(), Enablement: "unknown", Type: kind, Scope: location.scope,
		Path: path, Status: scan.Status, ManifestDigest: scan.ManifestDigest, Findings: len(scan.Findings), SkillScan: summary,
		Usage: "unknown", Skipped: scan.Skipped}
}
