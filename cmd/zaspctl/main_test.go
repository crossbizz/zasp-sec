package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOfflineCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "zaspctl")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	// Exercise the executable's argument handling, streams and process exit codes.
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOTOOLCHAIN=local")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %s, %v", out, err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(project, ".claude", "skills", "tickets & notes")
	fixtureFile(t, filepath.Join(bundle, "SKILL.md"), "# Tickets\n<!-- review me -->\n")
	fixtureFile(t, filepath.Join(project, ".mcp.json"), `{"mcpServers":{}}`)

	invoke := func(wantCode int, args ...string) (string, string) {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Dir = project
		cmd.Env = append(os.Environ(), "HOME="+project, "USERPROFILE="+project,
			"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var failure *exec.ExitError
		exitCode := 0
		if err != nil {
			if !errors.As(err, &failure) {
				t.Fatal(err)
			}
			exitCode = failure.ExitCode()
		}
		if exitCode != wantCode {
			t.Fatalf("%v: got exit %d, want %d; stdout=%s stderr=%s", args, exitCode, wantCode, stdout.String(), stderr.String())
		}
		return stdout.String(), stderr.String()
	}

	notices, _ := invoke(0, "frameworks", "notices")
	if !strings.Contains(notices, "MITRE") || !strings.Contains(notices, "OWASP") || !strings.Contains(notices, "Apache License") {
		t.Fatal("framework attribution missing from shipped binary")
	}
	htmlPath := filepath.Join(project, "local-report.html")
	out, diagnostic := invoke(0, "addons", "inventory", "--project", ".", "--scope", "project", "--local", "--report-html", htmlPath, "--json")
	inventory := decodeReport(t, out)
	if diagnostic != "" || inventory.Status != "complete" || len(inventory.Items) != 2 || len(inventory.Coverage.Roots) != 2 {
		t.Fatalf("inventory: %+v; diagnostic=%s", inventory, diagnostic)
	}
	skill := inventory.Items[0]
	if skill.Scope != "project" || skill.Harness != "Claude Code" || skill.Usage != "unknown" || skill.ManifestDigest == "" || skill.Findings != 1 || inventory.Items[1].Type != "mcp_declaration" {
		t.Fatalf("bad observations: %+v", inventory.Items)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil || !bytes.Contains(html, []byte("tickets &amp; notes")) || bytes.Contains(html, []byte("tickets & notes")) ||
		bytes.Contains(html, []byte("review me")) || !bytes.Contains(html, []byte("default-src 'none'")) {
		t.Fatalf("unsafe or missing local report: %s (%v)", html, err)
	}
	info, err := os.Stat(htmlPath)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		t.Fatal("report is not private")
	}

	out, diagnostic = invoke(0, "addons", "scan", bundle, "--local", "--json")
	scanned := decodeReport(t, out)
	if diagnostic != "" || scanned.Result == nil || scanned.Result.ManifestDigest != skill.ManifestDigest ||
		len(scanned.Result.Findings) != 1 || scanned.Result.Findings[0].RuleID != "instruction.hidden_text" || strings.Contains(out, "review me") || strings.Contains(out, project) {
		t.Fatalf("bad scan: %s; diagnostic=%s", out, diagnostic)
	}
	reportPath := filepath.Join(project, "scan.json")
	fixtureFile(t, reportPath, out)
	preview, _ := invoke(0, "addons", "submit", reportPath, "--dry-run", "--mode", "findings-only",
		"--environment", "pid_00000000-0000-4000-8000-000000000001")
	if !strings.Contains(preview, "instruction.hidden_text") || strings.Contains(preview, "SKILL.md") || strings.Contains(preview, "tickets") || strings.Contains(preview, "remediation") {
		t.Fatal("sharing preview must contain only the findings projection")
	}
	invoke(10, "addons", "scan", "--local", bundle, "--fail-on", "low")
	invoke(0, "addons", "scan", "--local", "--fail-on", "high", bundle)
	invoke(2, "addons", "scan", bundle, "--local", "--report-html", htmlPath)
	after, err := os.ReadFile(htmlPath)
	if err != nil || !bytes.Equal(after, html) {
		t.Fatal("existing destination was modified")
	}
	out, diagnostic = invoke(2, "addons", "scan", "--local", "--fail-on", "sometimes", bundle)
	if out != "" || diagnostic == "" {
		t.Fatalf("input diagnostics: %s, %s", out, diagnostic)
	}
	out, _ = invoke(3, "addons", "scan", filepath.Join(project, "missing"), "--local", "--json")
	if missing := decodeReport(t, out); missing.Result == nil || missing.Result.Status != "partial" || len(missing.Result.Skipped) == 0 || missing.Result.ManifestDigest != "" {
		t.Fatal("missing inputs must surface incomplete coverage")
	}

	fixtureFile(t, filepath.Join(bundle, "SKILL.md"), "# Locally edited ticket helper\n")
	out, _ = invoke(0, "addons", "scan", bundle, "--local", "--json")
	updated := decodeReport(t, out)
	if updated.Result.ManifestDigest == skill.ManifestDigest || len(updated.Result.Findings) != 0 {
		t.Fatal("local uncommitted change did not produce a fresh manifest and findings")
	}
	// The offline report retains file evidence and editioned references. The
	// explicitly shared wire body keeps the existing, counts-only contract.
	fixtureFile(t, filepath.Join(bundle, "package.json"), `{"dependencies":{"private-demo":"^1.2.0"}}`)
	out, _ = invoke(0, "addons", "scan", bundle, "--local", "--json")
	mapped := decodeReport(t, out).Result
	if mapped.ManifestDigest == updated.Result.ManifestDigest || len(mapped.Findings) != 1 || mapped.Findings[0].FileSHA256 == "" || mapped.Findings[0].Path != "package.json" || len(mapped.Dependencies) != 1 || mapped.Dependencies[0].Version != "" {
		t.Fatalf("edited manifest or unresolved dependency: %+v", mapped)
	}
	found := false
	for _, ref := range mapped.Findings[0].FrameworkEvidence {
		if ref.Framework == "owasp_agentic_top10" && ref.Edition == "2026" && ref.UpstreamID == "ASI04" && ref.EvidenceKind == "static_scan" && ref.RuleVersion == "zasp-static.v2" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing editioned static reference")
	}
	fixtureFile(t, reportPath, out)
	preview, _ = invoke(0, "addons", "submit", reportPath, "--dry-run", "--mode", "findings-only", "--environment", "pid_00000000-0000-4000-8000-000000000001")
	for _, private := range []string{"private-demo", "package.json", "framework_evidence", "ASI04", mapped.Findings[0].FileSHA256} {
		if strings.Contains(preview, private) {
			t.Fatal("leaked local finding field:", private)
		}
	}
	if !strings.Contains(preview, mapped.ManifestDigest) || !strings.Contains(preview, "dependency.unpinned") {
		t.Fatal("missing exact-version projection")
	}
	restrictedProject := filepath.Join(project, "empty")
	if err := os.Mkdir(restrictedProject, 0700); err != nil {
		t.Fatal(err)
	}
	out, _ = invoke(0, "addons", "inventory", "--scope", "project", "--project", restrictedProject, "--local", "--json")
	if empty := decodeReport(t, out); empty.Items == nil || len(empty.Items) != 0 || empty.Coverage.Roots[0].Status != "absent" {
		t.Fatalf("absent optional roots: %s", out)
	}

	// Compare the documented Codex project, ancestor, and user scope without
	// walking above the selected project boundary or merging identical copies.
	repo := filepath.Join(project, "codex-project")
	instructions := "---\nname: ticket-helper\ndescription: Review a ticket draft\n---\n# Draft\n"
	fixtureFile(t, filepath.Join(repo, ".agents", "skills", "helper", "SKILL.md"), instructions)
	fixtureFile(t, filepath.Join(repo, "svc", ".agents", "skills", "helper", "SKILL.md"), instructions)
	fixtureFile(t, filepath.Join(repo, "svc", "component", ".agents", "skills", "helper", "SKILL.md"), instructions+"local edit\n")
	fixtureFile(t, filepath.Join(project, ".agents", "skills", "personal", "SKILL.md"), instructions)
	out, _ = invoke(0, "addons", "inventory", "--local", "--harness", "codex", "--scope", "project", "--project", repo, "--codex-cwd", filepath.Join("svc", "component"), "--json")
	codex := decodeReport(t, out)
	if len(codex.Coverage.Roots) != 3 || len(codex.Items) != 3 || codex.Items[0].ManifestDigest == codex.Items[1].ManifestDigest ||
		codex.Items[1].ManifestDigest != codex.Items[2].ManifestDigest {
		t.Fatalf("incomplete Codex nested inventory: %s", out)
	}
	for _, observed := range codex.Items {
		if observed.Harness != "Codex" || observed.Profile != "codex-local-skills.v1" || observed.Scope != "project" || observed.Usage != "unknown" || observed.Enablement != "unknown" {
			t.Fatal(observed)
		}
	}
	out, _ = invoke(0, "addons", "inventory", "--local", "--harness", "codex", "--scope", "personal", "--json")
	if personal := decodeReport(t, out); len(personal.Items) != 1 || personal.Items[0].Scope != "personal" {
		t.Fatalf("personal Codex inventory: %s", out)
	}
	invoke(2, "addons", "inventory", "--local", "--harness", "codex", "--project", repo, "--codex-cwd", "..")
	invoke(3, "addons", "inventory", "--local", "--harness", "codex", "--project", repo, "--scope", "project", "--codex-cwd", "missing")

	// A selected profile must never import another directory via a link.
	if err := os.Symlink(filepath.Join(project, ".claude"), filepath.Join(restrictedProject, ".claude")); err != nil {
		t.Logf("symlink fixture unavailable: %v", err)
		return
	}
	out, _ = invoke(3, "addons", "inventory", "--scope", "project", "--project", restrictedProject, "--local", "--json")
	if partial := decodeReport(t, out); len(partial.Items) != 0 || partial.Coverage.Roots[0].Status != "partial" || partial.Coverage.Roots[0].Reason == "" {
		t.Fatalf("escaped a selected location: %s", out)
	}
}

func fixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func decodeReport(t *testing.T, output string) localReport {
	t.Helper()
	var report localReport
	if err := json.Unmarshal([]byte(output), &report); err != nil || report.SchemaVersion != "zaspctl.local.v1" || report.Coverage.Mode != "local_only" {
		t.Fatalf("invalid CLI output: %s (%v)", output, err)
	}
	return report
}
