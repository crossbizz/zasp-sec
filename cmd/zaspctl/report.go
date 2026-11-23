package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
)

type coverage struct {
	Mode   string         `json:"mode"`
	Roots  []rootCoverage `json:"roots,omitempty"`
	Limits []string       `json:"limits"`
}

type localReport struct {
	SchemaVersion string         `json:"schema_version"`
	Command       string         `json:"command"`
	Status        string         `json:"status"`
	Coverage      coverage       `json:"coverage"`
	Items         []installation `json:"items,omitzero"`
	Result        *addons.Report `json:"result,omitempty"`
}

func newEnvelope(command string) localReport {
	report := localReport{SchemaVersion: "zaspctl.local.v1", Command: command, Status: "complete",
		Coverage: coverage{Mode: "local_only"}}
	if command == "inventory" {
		report.Items = []installation{}
	}
	return report
}

func scanEnvelope(scan addons.Report) localReport {
	report := newEnvelope("scan")
	report.Status = scan.Status
	report.Coverage.Limits = []string{"Static checks inspect local files only",
		"Usage, runtime behavior and effective permissions are unknown"}
	report.Result = &scan
	return report
}

func writeOutput(w io.Writer, asJSON bool, report localReport) error {
	if asJSON {
		return json.NewEncoder(w).Encode(report)
	}
	_, err := fmt.Fprintln(w, readable(report))
	return err
}

func readable(report localReport) string {
	var text strings.Builder
	fmt.Fprintf(&text, "Local %s: %s\n", report.Command, report.Status)
	if scan := report.Result; scan != nil {
		fmt.Fprintf(&text, "Ruleset: %s\nAdvisory coverage: %s\n", scan.Ruleset, scan.AdvisoryStatus)
		if a := scan.AdvisoryCoverage; a != nil {
			fmt.Fprintf(&text, "Catalog age: %d days. Verified by: %s. Declarations evaluated: %d. Unresolved versions: %d. Absent releases: %d.\n", a.AgeDays, a.Authentication, a.Evaluated, a.Unresolved, a.MissingReleases)
			if a.SignerSHA256 != "" {
				fmt.Fprintf(&text, "Signer %s · %s at %s\n", a.SignerSHA256, a.Source, a.SourceRevision)
			}
			for _, m := range a.Matches {
				fmt.Fprintf(&text, "%s %s: %s@%s (%s)\n", m.Severity, m.ID, m.Dependency.Name, m.Dependency.Version, m.Dependency.Path)
				if m.FixedVersion != "" {
					fmt.Fprintf(&text, "  Reviewed fix: %s\n", m.FixedVersion)
				}
			}
		}
		if scan.ManifestDigest != "" {
			fmt.Fprintf(&text, "Version: %s\n", scan.ManifestDigest)
		}
		if len(scan.Findings) == 0 && (scan.AdvisoryCoverage == nil || len(scan.AdvisoryCoverage.Matches) == 0) {
			fmt.Fprintln(&text, "No findings from this scan.")
		}
		for _, f := range scan.Findings {
			fmt.Fprintf(&text, "%s %s in %s: %s %s\n", f.Severity, f.RuleID, strconv.Quote(f.Path), f.Message, f.Remediation)
			for _, ref := range f.FrameworkEvidence {
				fmt.Fprintf(&text, "  %s %s · %s %s (%s)\n", ref.Framework, ref.Edition, ref.UpstreamID, ref.Title, ref.EvidenceKind)
			}
		}
		for _, n := range scan.Notices {
			fmt.Fprintf(&text, "Notice %s: %s\n", n.ID, n.Message)
		}
		for _, s := range scan.Skipped {
			fmt.Fprintf(&text, "Skipped %s: %s\n", strconv.Quote(s.Path), s.Reason)
		}
	} else {
		for _, root := range report.Coverage.Roots {
			fmt.Fprintf(&text, "%s %s %s: %s", root.Harness, root.Scope, strconv.Quote(root.Path), root.Status)
			if root.Reason != "" {
				fmt.Fprintf(&text, " (%s)", root.Reason)
			}
			fmt.Fprintln(&text)
		}
		for _, item := range report.Items {
			fmt.Fprintf(&text, "%s  %s  %s  %s  %s  %s  findings=%d\n", item.Harness, item.Scope, item.Type,
				strconv.Quote(item.Path), item.Status, item.ManifestDigest, item.Findings)
			if summary := item.DeclarationSummary(); summary != "" {
				fmt.Fprintf(&text, "  %s\n", summary)
			}
			for _, skipped := range item.Skipped {
				fmt.Fprintf(&text, "  Skipped %s: %s\n", strconv.Quote(skipped.Path), skipped.Reason)
			}
		}
	}
	fmt.Fprintln(&text, "Usage unknown. No data uploaded.")
	for _, limit := range report.Coverage.Limits {
		fmt.Fprintln(&text, limit)
	}
	return strings.TrimSpace(text.String())
}

//go:embed report/local.html
var reportHTML string

//go:embed report/local.css
var reportCSS string

// The offline image is a 192×84 raster of public/brand/zasp-wordmark-light.svg.
//
//go:embed report/wordmark.png
var reportWordmark []byte

var htmlTemplate = func() *template.Template {
	// Only bundled assets enter trusted template contexts. All scan data passes
	// through html/template's contextual escaping.
	digest := sha256.Sum256([]byte(reportCSS))
	logo := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(reportWordmark))
	return template.Must(template.New("local").Funcs(template.FuncMap{
		"stylesheet":    func() template.CSS { return template.CSS(reportCSS) },
		"styleHash":     func() string { return base64.StdEncoding.EncodeToString(digest[:]) },
		"wordmark":      func() template.URL { return logo },
		"label":         func(value string) string { return strings.ReplaceAll(value, "_", " ") },
		"advisoryLabel": advisoryStatusLabel,
	}).Parse(reportHTML))
}()

func advisoryStatusLabel(status string) string {
	switch status {
	case "not_evaluated_no_offline_snapshot":
		return "No offline catalog supplied."
	case "evaluated_exact_releases":
		return "Evaluated against exact releases."
	case "partial_exact_release_coverage":
		return "Only some exact releases could be evaluated."
	case "unrated_exact_release_match":
		return "An exact release matched an advisory with unknown severity."
	case "stale_snapshot":
		return "The supplied advisory catalog is stale."
	default:
		return status
	}
}

func writeHTML(path string, report localReport) error {
	// Never replace a user's existing file or follow an existing destination symlink.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := htmlTemplate.Execute(file, report); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	return file.Close()
}
