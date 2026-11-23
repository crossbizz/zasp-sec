package main

import (
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

var htmlTemplate = template.Must(template.New("local").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'">
<title>Zasp local {{.Command}}</title></head><body>
<h1>Zasp local {{.Command}}</h1><p>Coverage: <strong>{{.Status}}</strong>. Usage unknown. No data uploaded.</p>
{{if .Result}}{{with .Result}}<p>Ruleset: {{.Ruleset}}. Advisory coverage: {{.AdvisoryStatus}}.</p>
{{with .AdvisoryCoverage}}<p>Catalog age {{.AgeDays}} days. Verified by {{.Authentication}}. Declarations evaluated {{.Evaluated}}. Unresolved versions {{.Unresolved}}. Releases absent {{.MissingReleases}}.{{if .SignerSHA256}} Signer <code>{{.SignerSHA256}}</code>. {{.Source}} at <code>{{.SourceRevision}}</code>.{{end}}</p>
{{if .Matches}}<ul>{{range .Matches}}<li>{{.Severity}} {{.ID}} in {{.Dependency.Name}}@{{.Dependency.Version}} ({{.Dependency.Path}}){{with .FixedVersion}}. Reviewed fix: {{.}}{{end}}</li>{{end}}</ul>{{end}}{{end}}
{{if .ManifestDigest}}<p>Version: <code>{{.ManifestDigest}}</code></p>{{end}}
{{if .Notices}}<h2>Package and coverage notices</h2><ul>{{range .Notices}}<li>{{.ID}} · {{.Message}}</li>{{end}}</ul>{{end}}<h2>Static rule findings</h2>{{if .Findings}}<ul>{{range .Findings}}<li><strong>{{.Severity}} · {{.RuleID}}</strong> in <code>{{.Path}}</code>. {{.Message}} {{.Remediation}}{{if .FrameworkEvidence}}<ul>{{range .FrameworkEvidence}}<li>{{.Framework}} {{.Edition}} · {{.UpstreamID}} {{.Title}} ({{.EvidenceKind}})</li>{{end}}</ul>{{end}}</li>{{end}}</ul>{{else}}<p>No static rule findings.</p>{{end}}
{{if .Skipped}}<h2>Skipped files</h2><ul>{{range .Skipped}}<li><code>{{.Path}}</code> — {{.Reason}}</li>{{end}}</ul>{{end}}
{{end}}{{else}}
<h2>Locations checked</h2><ul>{{range .Coverage.Roots}}<li>{{.Harness}} · {{.Scope}} <code>{{.Path}}</code> — {{.Status}} {{.Reason}}</li>{{end}}</ul>
<h2>Observed add-ons</h2>{{if .Items}}<table><thead><tr><th>Harness</th><th>Scope</th><th>Type</th><th>Location</th><th>Scan</th><th>Version</th><th>Findings</th></tr></thead><tbody>
{{range .Items}}<tr><td>{{.Harness}}</td><td>{{.Scope}}</td><td>{{.Type}}{{with .DeclarationSummary}}<br>{{.}}{{end}}</td><td>{{.Path}}</td><td>{{.Status}}{{range .Skipped}}<br>{{.Path}} — {{.Reason}}{{end}}</td><td><code>{{.ManifestDigest}}</code></td><td>{{.Findings}}</td></tr>{{end}}
</tbody></table>{{else}}<p>No add-ons observed in the selected locations.</p>{{end}}{{end}}
<h2>Scan coverage</h2><ul>{{range .Coverage.Limits}}<li>{{.}}</li>{{end}}</ul></body></html>`))

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
