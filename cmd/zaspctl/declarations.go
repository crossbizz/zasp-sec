package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

type declarationLocation struct {
	source
	kind string
	file bool
}

func addDeclarations(report *localReport, project, scope string, deadline time.Time) {
	report.Coverage.Limits = append(report.Coverage.Limits,
		"Claude declaration records describe static files only. Custom component paths, nested command groups, marketplace cache discovery and merged runtime settings are outside this profile.")
	remaining := maxRootEntries
	inspect := func(base, scope, path, kind string, file bool) bool {
		location := declarationLocation{source{"Claude Code", scope, base, path, file}, kind, file}
		items, why := inspectLocation(location, deadline, &remaining)
		root := rootCoverage{Harness: "Claude Code", Profile: "claude-code-declarations.v1", Scope: scope, Path: path, Status: "complete"}
		switch why {
		case "not_installed":
			root.Status = "absent"
		case "":
		default:
			root.Status = "partial"
			root.Reason = why
			report.Status = "partial"
		}
		report.Coverage.Roots = append(report.Coverage.Roots, root)
		report.Items = append(report.Items, items...)
		return len(items) == 1 && items[0].Status == "complete"
	}
	standard := func(base, scope string) {
		inspect(base, scope, ".claude/agents", "subagent", false)
		inspect(base, scope, ".claude/commands", "command", false)
		inspect(base, scope, ".claude/settings.json", "hook", true)
	}
	if scope == "personal" || scope == "all" {
		home, _ := os.UserHomeDir()
		standard(home, "personal")
	}
	if scope == "managed" || scope == "all" {
		base := claudeSources("", "managed")[0].base
		inspect(base, "managed", "managed-settings.json", "hook", true)
	}
	if project != "" && (scope == "project" || scope == "all") {
		standard(project, "project")
		inspect(project, "project", ".claude/settings.local.json", "hook", true)
		if inspect(project, "project", ".claude-plugin/plugin.json", "plugin", true) {
			inspect(project, "project", "agents", "subagent", false)
			inspect(project, "project", "commands", "command", false)
			inspect(project, "project", "hooks/hooks.json", "hook", true)
		}
	}
}

func inspectLocation(location declarationLocation, deadline time.Time, remaining *int) ([]installation, string) {
	dir, why := sourceRoot(location.source)
	if why != "" {
		return nil, why
	}
	defer dir.Close()
	var items []installation
	scan := func(name string) string {
		if *remaining <= 0 {
			return "declaration_limit"
		}
		if time.Now().After(deadline) {
			return "time_limit"
		}
		*remaining--
		data, why := addons.InspectDeclaration(dir, location.kind, name)
		if why == "missing" {
			return "not_installed"
		}
		if data == nil && why == "" {
			return ""
		}
		path := location.rel
		if !location.file {
			path += "/" + name
		}
		item := installation{Harness: "Claude Code", Profile: "claude-code-declarations.v1", Scope: location.scope,
			Type: location.kind, Path: path, Name: name, Status: "complete", Enablement: "unknown", Usage: "unknown", Declaration: data}
		if why != "" {
			item.Status = "partial"
			item.Skipped = []addons.Skip{{Path: name, Reason: why}}
		}
		items = append(items, item)
		return why
	}
	if location.file {
		why = scan(filepath.Base(location.rel))
		return items, why
	}
	handle, err := dir.Open(".")
	if err != nil {
		return nil, "unreadable"
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
	for _, entry := range entries {
		if entry.IsDir() || (entry.Type()&os.ModeSymlink != 0 && !strings.HasSuffix(entry.Name(), ".md")) {
			why = "nested_or_linked_declaration_skipped"
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		if reason := scan(entry.Name()); reason != "" {
			if reason == "declaration_limit" || reason == "time_limit" {
				return items, reason
			}
			why = "incomplete_declarations"
		}
	}
	after, err := handle.Stat()
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		return items, "changed_during_discovery"
	}
	return items, why
}

func (i installation) DeclarationSummary() string {
	if i.Declaration == nil {
		return ""
	}
	switch i.Type {
	case "hook":
		return fmt.Sprintf("%d handlers (%d command)", i.Declaration.HandlerCount, i.Declaration.CommandHandlers)
	case "plugin":
		if len(i.Declaration.ComponentKeys) > 0 {
			return "Manifest fields: " + strings.Join(i.Declaration.ComponentKeys, ", ")
		}
		return "Manifest present"
	default:
		if i.Declaration.DeclaresTools {
			return "Tool list declared"
		}
		return "Markdown declaration"
	}
}
