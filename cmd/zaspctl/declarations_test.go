package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClaudeDeclarationInventory(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".claude/agents/reviewer.md": "---\nname: reviewer\ndescription: A local review demo.\ntools: Read\n---\nprivate-fixture-content",
		".claude/commands/check.md":  "An instruction. private-fixture-content",
		".claude/settings.json":      `{"env":{"private":"private-fixture-content"},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"private-fixture-content"}]}]}}`,
		".claude-plugin/plugin.json": `{"name":"example","agents":["../private-fixture-content"],"commands":{"test":{"content":"private-fixture-content"}}}`,
		"hooks/hooks.json":           `{"hooks":{"PostToolUse":[{"hooks":[{"type":"http","url":"https://example.invalid/private-fixture-content"}]}]}}`,
		"unrelated/private.md":       "private-fixture-content",
	}
	for name, data := range files {
		fixtureFile(t, filepath.Join(project, name), data)
	}
	exec := func(want int, flags ...string) localReport {
		t.Helper()
		var out, diagnostics bytes.Buffer
		args := append([]string{"addons", "inventory", "--scope", "project", "--project", project, "--local", "--json"}, flags...)
		if code := run(args, &out, &diagnostics); code != want {
			t.Fatalf("code %d, wanted %d: %s", code, want, diagnostics.String())
		}
		if strings.Contains(out.String(), "private-fixture-content") {
			t.Fatal("private declaration field escaped")
		}
		return decodeReport(t, out.String())
	}
	if report := exec(0); len(report.Items) != 0 {
		t.Fatalf("default profile opted into parsing declarations")
	}
	report := exec(0, "--declarations")
	if len(report.Items) != 5 {
		t.Fatalf("found %d declarations, wanted 5: %#v", len(report.Items), report.Coverage.Roots)
	}
	byPath := map[string]installation{}
	for _, item := range report.Items {
		if item.ManifestDigest != "" || item.Usage != "unknown" || item.Enablement != "unknown" || item.Profile != "claude-code-declarations.v1" || item.Declaration == nil {
			t.Fatalf("invalid declaration identity: %#v", item)
		}
		byPath[item.Path] = item
	}
	if !byPath[".claude/agents/reviewer.md"].Declaration.DeclaresTools ||
		byPath[".claude/settings.json"].Declaration.CommandHandlers != 1 ||
		byPath["hooks/hooks.json"].Declaration.HandlerCount != 1 || byPath["hooks/hooks.json"].Declaration.CommandHandlers != 0 ||
		len(byPath[".claude-plugin/plugin.json"].Declaration.ComponentKeys) != 2 {
		t.Fatal("declaration structure mismatch")
	}
	var out, diag bytes.Buffer
	if code := run([]string{"addons", "scan", filepath.Join(project, ".claude/commands/check.md"), "--local", "--json"}, &out, &diag); code != 3 {
		t.Fatalf("single markdown file entered the immutable skill scanner: %d", code)
	}
	fixtureFile(t, filepath.Join(project, ".claude/agents/invalid.md"), "---\nname: sample\n---\ntemplate")
	report = exec(3, "--declarations")
	if report.Status != "partial" {
		t.Fatal("invalid frontmatter was silently accepted")
	}
}

func TestDeclarationProfileSkipsAliasesAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	location := declarationLocation{source{"Claude Code", "project", dir, ".claude/commands", false}, "command", false}
	fixtureFile(t, filepath.Join(dir, ".claude/commands/huge.md"), strings.Repeat("x", (256<<10)+1))
	candidate := filepath.Join(dir, ".claude/commands/alias.md")
	linked := os.Link(filepath.Join(dir, ".claude/commands/huge.md"), candidate) == nil
	remaining := maxRootEntries
	rows, why := inspectLocation(location, time.Now().Add(time.Minute), &remaining)
	if why != "incomplete_declarations" || len(rows) < 1 || (linked && len(rows) != 2) {
		t.Fatalf("bounded result=%#v why=%s", rows, why)
	}
	for _, row := range rows {
		if row.Status != "partial" || row.ManifestDigest != "" {
			t.Fatal("unsupported artifact was identified")
		}
	}
}
