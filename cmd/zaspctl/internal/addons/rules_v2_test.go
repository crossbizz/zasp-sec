package addons

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
)

func TestV2CommentViewsPreserveLinesAndStrings(t *testing.T) {
	for _, tc := range []struct{ name, code, kept string }{
		{"mod.py", "'''DROP\nDROP'''\nvalue = \"# KEEP\" # DROP\n", `"# KEEP"`},
		{"test.ts", "/* DROP\nDROP */\nconst t = `https://KEEP/*x*/`; // DROP\n", "`https://KEEP/*x*/`"},
		{"helper.sh", "# DROP\nname='KEEP#x' # DROP\n", "'KEEP#x'"},
		{"helper.ps1", "<# DROP\nDROP #>\n$note = 'KEEP<#x#>' # DROP\n", "'KEEP<#x#>'"},
	} {
		clean, code := scriptViews(tc.name, []byte(tc.code))
		if len(clean) != len(tc.code) || len(code) != len(tc.code) || bytes.Contains(clean, []byte("DROP")) || !bytes.Contains(clean, []byte(tc.kept)) || bytes.Contains(code, []byte("KEEP")) {
			t.Fatalf("%s: clean=%q executable=%q", tc.name, clean, code)
		}
		for i, b := range []byte(tc.code) {
			if (b == '\n') != (clean[i] == '\n') || (b == '\n') != (code[i] == '\n') {
				t.Fatalf("%s: newline offset changed", tc.name)
			}
		}
	}
}

func TestV2ExactManifestAndHistoricalRulesRetainDifferentDecisions(t *testing.T) {
	dir := skill(t)
	write(t, dir, "helper.py", "# Documentation only: subprocess.run('placeholder')\nvalue = 1\n")
	write(t, dir, "package.json", `{"name":"example","license":"MIT","dependencies":{"example":"~1.0.0"}}`)
	newReport, oldReport := Scan(dir), ScanWithRuleset(dir, addonevidence.LegacyRuleset)
	if oldReport.ManifestDigest != newReport.ManifestDigest || newReport.Ruleset != addonevidence.CurrentRuleset || oldReport.Ruleset != addonevidence.LegacyRuleset || len(newReport.Findings) != 1 || len(oldReport.Findings) != 2 {
		t.Fatalf("old=%+v new=%+v", oldReport, newReport)
	}
	if len(newReport.Notices) != 1 || newReport.Notices[0].ID != "advisory.not_evaluated" || len(oldReport.Notices) != 0 {
		t.Fatal("notices changed legacy report or ignored declared license")
	}
	if len(newReport.Findings[0].FrameworkEvidence) == 0 || newReport.Findings[0].FrameworkEvidence[0].RuleVersion != newReport.Ruleset {
		t.Fatal("current-ruleset references not bound")
	}
}

func TestV2MCPAuthMetadataStaysPrivate(t *testing.T) {
	dir := skill(t)
	write(t, dir, ".mcp.json", `{"mcpServers":{"fixture":{"url":"http://safe.invalid","headers":{"Authorization":"SYNTHETIC_PRIVATE"}}}}`)
	r := Scan(dir)
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), "SYNTHETIC_PRIVATE") {
		t.Fatal("MCP header retained")
	}
	for _, f := range r.Findings {
		if f.RuleID == "mcp.unpinned_exec" {
			t.Fatal("declared authorization was ignored")
		}
	}
}
