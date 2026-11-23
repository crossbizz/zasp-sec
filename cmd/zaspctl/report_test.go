package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

func TestOfflineHTMLUsesOnlyBundledPresentation(t *testing.T) {
	var out bytes.Buffer
	if err := htmlTemplate.Execute(&out, newEnvelope("inventory")); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	style := regexp.MustCompile("(?s)<style>(.*?)</style>").FindStringSubmatch(page)
	policy := regexp.MustCompile(`http-equiv="Content-Security-Policy" content="([^"]+)"`).FindStringSubmatch(page)
	if len(style) != 2 || len(policy) != 2 {
		t.Fatal("report lacks its stylesheet or content policy")
	}
	digest := sha256.Sum256([]byte(style[1]))
	expected := "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'; img-src data:; base-uri 'none'; form-action 'none'"
	if html.UnescapeString(policy[1]) != expected {
		t.Fatal("report must allow only its exact embedded stylesheet and embedded image")
	}
	urls := regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllStringSubmatch(page, -1)
	if len(urls) != 1 || !strings.HasPrefix(urls[0][1], "data:image/png;base64,") || strings.Contains(page, "<script") || strings.Contains(style[1], "url(") {
		t.Fatal("unexpected active content or external resource in offline report")
	}
}

func TestOfflineHTMLShowsPartialScansAndExactAdvisories(t *testing.T) {
	report := scanEnvelope(addons.Report{
		Status: "partial", Ruleset: "zasp-static.v2", AdvisoryStatus: "partial_exact_release_coverage",
		Skipped: []addons.Skip{
			{Path: "draft <b> & notes", Reason: "entry_unreadable"},
			{Path: ".", Reason: "unsupported_bundle"},
		},
		AdvisoryCoverage: &addons.AdvisoryCoverage{
			AgeDays: 3, Evaluated: 2, Unresolved: 1, MissingReleases: 1,
			Matches: []addons.AdvisoryMatch{{
				Dependency: addons.Dependency{Name: "example", Version: "1.2.0", Path: "package.json"},
				Advisory:   addons.Advisory{ID: "TEST-42", Severity: "low", FixedVersion: "1.2.1"},
			}},
		},
	})
	var out bytes.Buffer
	if err := htmlTemplate.Execute(&out, report); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, value := range []string{"Static scan partial", "No static rule findings.", "<dt>Skipped entries</dt><dd>2</dd>", "<code>.</code><p>unsupported bundle</p>", "TEST-42", "example@1.2.0", "1.2.1", "Only some exact releases could be evaluated.", "draft &lt;b&gt; &amp; notes", "No data uploaded."} {
		if !strings.Contains(page, value) {
			t.Errorf("missing report field %q", value)
		}
	}
	if strings.Contains(page, "draft <b>") {
		t.Error("file name markup became active report content")
	}
}
