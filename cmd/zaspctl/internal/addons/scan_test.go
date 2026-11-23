package addons

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func skill(t *testing.T) string {
	t.Helper()
	// macOS commonly points /var at /private/var. Select the physical fixture root.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "SKILL.md", "# Ticket helper\n")
	return root
}
func requirePartial(t *testing.T, r Report, why string) {
	t.Helper()
	if r.Status != "partial" || r.ManifestDigest != "" {
		t.Fatalf("expected partial without digest: %+v", r)
	}
	for _, skip := range r.Skipped {
		if skip.Reason == why {
			return
		}
	}
	t.Fatalf("missing reason %q in %v", why, r.Skipped)
}

func TestCanonicalManifestAndStaticAnalysis(t *testing.T) {
	a, b := skill(t), skill(t)
	for _, root := range []string{a, b} {
		write(t, root, "assets/guide.txt", "Read the ticket.")
		write(t, root, "package.json", `{"dependencies":{"example-helper":"^1.2.3","exact":"1.4.0"}}`)
		write(t, root, "requirements.txt", "example==1.2.3\nsecond>=2\n")
	}
	aReport, bReport := Scan(a), Scan(filepath.Join(b, "SKILL.md"))
	if aReport.Status != "complete" || aReport.ManifestDigest == "" || aReport.ManifestDigest != bReport.ManifestDigest {
		t.Fatalf("matching bundles disagree: %+v, %+v", aReport, bReport)
	}
	var findings []string
	for _, f := range aReport.Findings {
		findings = append(findings, f.Path+":"+f.RuleID)
	}
	if want := []string{"package.json:dependency.unpinned", "requirements.txt:dependency.unpinned"}; !slices.Equal(findings, want) {
		t.Fatalf("findings %v", findings)
	}
	if len(aReport.Dependencies) != 4 || aReport.Usage != "unknown" || aReport.AdvisoryStatus != "not_evaluated_no_offline_snapshot" {
		t.Fatalf("coverage: %+v", aReport)
	}
	j1, _ := json.Marshal(aReport)
	j2, _ := json.Marshal(bReport)
	if !bytes.Equal(j1, j2) {
		t.Fatal("report unstable")
	}
	write(t, b, "assets/guide.txt", "Edited locally.")
	if got := Scan(b); got.ManifestDigest == aReport.ManifestDigest || got.Status != "complete" {
		t.Fatalf("edited digest: %+v", got)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(a, "SKILL.md"), 0700); err != nil {
			t.Fatal(err)
		}
		changed := Scan(a)
		if changed.ManifestDigest != aReport.ManifestDigest || !changed.Files[0].Executable {
			t.Fatal("separate executable metadata")
		}
	}
}

func TestCanonicalGolden(t *testing.T) {
	r := Scan(skill(t))
	// Independently build the framing fixture for the one file in this skill.
	pre := []byte("addon-manifest.v1\x00\x00\x00\x00\x08SKILL.md\x00\x00\x00\x00\x00\x00\x00\x10")
	content := sha256.Sum256([]byte("# Ticket helper\n"))
	golden := sha256.Sum256(append(pre, content[:]...))
	if r.ManifestDigest != "sha256:"+hex.EncodeToString(golden[:]) {
		t.Fatalf("unexpected canonical encoding: %+v", r)
	}
}
func TestExclusionsAndUnsupportedRoots(t *testing.T) {
	r := skill(t)
	write(t, r, "private/.env", "SENTINEL_PRIVATE_FILE")
	write(t, r, "nested/private.key", "SENTINEL_PRIVATE_KEY")
	write(t, r, ".git/config", "SENTINEL_PRIVATE_METADATA")
	report := Scan(r)
	requirePartial(t, report, "excluded_private")
	if len(report.Files) != 1 || len(report.Skipped) != 3 {
		t.Fatalf("excluded files: %+v", report)
	}
	encoded, _ := json.Marshal(report)
	if bytes.Contains(encoded, []byte("SENTINEL")) || bytes.Contains(encoded, []byte(r)) {
		t.Fatal("contains a private byte or absolute root")
	}
	empty := t.TempDir()
	requirePartial(t, Scan(filepath.Join(r, "absent")), "missing")
	requirePartial(t, Scan(empty), "missing_entry")
	requirePartial(t, Scan(filepath.Join(r, ".git", "config")), "unsupported_bundle")
}

func TestRootBoundariesAndSymlinks(t *testing.T) {
	r, outside := skill(t), skill(t)
	write(t, outside, "outside", "SENTINEL_OUTSIDE")
	if err := os.Symlink(outside, filepath.Join(r, "linked-dir")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "SKILL.md"), filepath.Join(r, "linked-file")); err != nil {
		t.Fatal(err)
	}
	result := Scan(r)
	requirePartial(t, result, "symlink")
	if len(result.Files) != 1 || len(result.Skipped) != 2 {
		t.Fatalf("link enumeration: %+v", result)
	}
	requirePartial(t, Scan(filepath.Join(r, "linked-dir", "SKILL.md")), "symlink")
	root, err := os.OpenRoot(r)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	requirePartial(t, ScanIn(root, "../elsewhere"), "invalid_path")
	requirePartial(t, ScanIn(root, filepath.Join("linked-dir", "SKILL.md")), "symlink")
}

func TestBoundedAndChangingInputs(t *testing.T) {
	r := skill(t)
	write(t, r, "enormous", strings.Repeat("a", maxFileBytes+1))
	requirePartial(t, Scan(r), "file_size_limit")
	dir, err := os.OpenRoot(r)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	s := newScanner()
	s.seen = maxEntries
	s.walk(dir, "", 0)
	requirePartial(t, s.report, "entry_limit")
	s = newScanner()
	s.used = maxBundleBytes
	original, err := dir.Lstat("SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	s.file(dir, "SKILL.md", "SKILL.md", original)
	requirePartial(t, s.report, "byte_limit")
	s = newScanner()
	s.deadline = time.Now().Add(-time.Second)
	s.walk(dir, "", 0)
	requirePartial(t, s.report, "time_limit")
	write(t, r, "SKILL.md", "# Updated while scanning\n")
	s = newScanner()
	s.file(dir, "SKILL.md", "SKILL.md", original)
	s.finish()
	requirePartial(t, s.report, "changed_during_scan")
}

func TestCaseCollisionsAndNonportableNames(t *testing.T) {
	r := skill(t)
	write(t, r, "Guide", "one")
	write(t, r, "guide", "two")
	if info1, e1 := os.Stat(filepath.Join(r, "Guide")); e1 == nil {
		info2, e2 := os.Stat(filepath.Join(r, "guide"))
		if e2 == nil && os.SameFile(info1, info2) {
			t.Skip("case-insensitive fixture filesystem")
		}
	}
	requirePartial(t, Scan(r), "path_collision")
	if runtime.GOOS != "windows" {
		write(t, r, "unsafe\nname", "one")
		requirePartial(t, Scan(r), "nonportable_name")
	}
}

func TestMCPDeclarationIsNeverInvokedAndArgsOmitted(t *testing.T) {
	r := skill(t)
	flag := filepath.Join(r, "should-not-exist")
	cfg := `{"mcpServers":{"service":{"url":"https://example.invalid/private-name"},"local":{"command":"npx","args":["-y","demo","SENTINEL_ARG"]},"pinned":{"command":"uvx","args":["demo==1.2.3"]}}}`
	write(t, r, ".mcp.json", cfg)
	report := Scan(filepath.Join(r, ".mcp.json"))
	if report.Status != "complete" || len(report.Files) != 1 || len(report.Findings) != 3 {
		t.Fatalf("mcp observations: %+v", report)
	}
	text, _ := json.Marshal(report)
	if bytes.Contains(text, []byte("SENTINEL_ARG")) || bytes.Contains(text, []byte("private-name")) {
		t.Fatal("arguments disclosed")
	}
	write(t, r, "managed-mcp.json", `{"mcpServers":{"test":{"command":"touch","args":[`+strconvJSON(flag)+`]}}}`)
	if got := Scan(filepath.Join(r, "managed-mcp.json")); got.Status != "complete" {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(flag); !os.IsNotExist(err) {
		t.Fatalf("command unexpectedly invoked: %v", err)
	}
	write(t, r, ".mcp.json", "{}")
	requirePartial(t, Scan(filepath.Join(r, ".mcp.json")), "invalid_mcp_declaration")
}

func strconvJSON(v string) string { b, _ := json.Marshal(v); return string(b) }

func TestHardlinkedRegularFileExcluded(t *testing.T) {
	r := skill(t)
	outside := filepath.Join(t.TempDir(), "guide")
	if err := os.WriteFile(outside, []byte("separate private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(r, "linked-guide")); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	result := Scan(r)
	requirePartial(t, result, "unverified_link_count")
	if len(result.Files) != 1 {
		t.Fatalf("expected only entry file: %+v", result)
	}
}

func TestRulesAndBoundedDependencyReports(t *testing.T) {
	r := skill(t)
	write(t, r, "SKILL.md", "# Guide\n<!-- editor note -->")
	write(t, r, "helper.py", "import subprocess\nsubprocess.run(['echo','demo'])\n# requests.get('documented example')\n")
	result := Scan(r)
	if result.Status != "complete" || len(result.Findings) != 2 {
		t.Fatalf("static capabilities: %+v", result)
	}
	write(t, r, "requirements.txt", strings.Repeat("sample==1.2.3\n", maxDependencies+1))
	result = Scan(r)
	requirePartial(t, result, "dependency_limit")
	if len(result.Dependencies) != maxDependencies {
		t.Fatalf("unbounded dependency report: %d", len(result.Dependencies))
	}
}
