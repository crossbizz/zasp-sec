package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

func reportCell(s string) string {
	if len(s) > 0 && strings.ContainsRune("=+-@\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}
func renderFrameworkReport(l complianceExportLease, s complianceFrozenSnapshot) (compliancePreparedArtifact, error) {
	var report compliancemap.FrozenReport
	d := json.NewDecoder(bytes.NewReader(s.FrameworkCoverage))
	d.DisallowUnknownFields()
	if d.Decode(&report) != nil || d.Decode(new(any)) != io.EOF || report.Schema != "framework-coverage.v1" || report.Organization != s.Organization || report.Workspace != s.Workspace || report.Environment != s.Environment {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	p := report.Coverage
	q := report.Selector
	if q.Framework == "" || q.Edition == "" || q.Framework != p.Framework || q.Edition != p.Edition || p.Digest == "" || p.Collected.IsZero() || p.Matched != len(p.Items) || p.Total < p.Matched || p.Next != nil || p.Items == nil || report.Evidence == nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	var rows, human bytes.Buffer
	c := csv.NewWriter(&rows)
	write := func(fields ...string) {
		for n := range fields {
			fields[n] = reportCell(fields[n])
		}
		_ = c.Write(fields)
	}
	write("record", "framework", "edition", "control", "title", "applicability", "evidence_kind", "count", "source_kind", "source_id", "rule", "rule_version", "occurred_at", "last_verified_at", "source_digest", "manifest_digest", "verification_status")
	fmt.Fprintf(&human, "%s %s\nCollected %s UTC. %d selected of %d published controls.\nCatalog source digest %s\n", p.Framework, p.Edition, p.Collected.UTC().Format(time.RFC3339), p.Matched, p.Total, p.Digest)
	seen := map[string]bool{}
	for _, row := range p.Items {
		entry := row.Control
		if entry.UpstreamID == "" || seen[entry.UpstreamID] || entry.Framework != p.Framework || entry.Edition != p.Edition || entry.SourceDigest != p.Digest || row.Counts == nil {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		seen[entry.UpstreamID] = true
		status := row.VerificationStatus
		if status == "" {
			status = compliancemap.VerificationFreshness(row.Verified, p.Collected)
		} else if status != "current" && status != "stale" && status != "unknown" {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		stamp := ""
		if row.Verified != nil {
			stamp = row.Verified.UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(&human, "\n%s %s\nApplicability %s. %s\n", entry.UpstreamID, entry.Title, entry.Applicability, entry.Rationale)
		write("control", p.Framework, p.Edition, entry.UpstreamID, entry.Title, entry.Applicability, "", "", "", "", "", "", "", stamp, p.Digest, "", status)
		fmt.Fprintf(&human, "Verification at collection: %s", status)
		if stamp != "" {
			fmt.Fprintf(&human, " (last verified %s)", stamp)
		}
		human.WriteString(".\n")
		if len(row.Counts) == 0 {
			human.WriteString("No qualifying evidence in this Environment.\n")
		}
		kinds := []string{}
		for kind := range row.Counts {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			count := row.Counts[kind]
			if count <= 0 {
				return compliancePreparedArtifact{}, errWorkerExecution
			}
			write("count", p.Framework, p.Edition, entry.UpstreamID, entry.Title, entry.Applicability, kind, strconv.Itoa(count), "", "", "", "", "", stamp, p.Digest, "", status)
			fmt.Fprintf(&human, "%s %d\n", kind, count)
		}
	}
	for _, x := range report.Evidence {
		if !seen[x.Upstream] || x.Framework != p.Framework || x.Edition != p.Edition || x.At.IsZero() || !productIDValid(x.ID) || x.Rule == "" || x.Version == "" || (q.EvidenceKind != "" && x.Kind != q.EvidenceKind) {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		at := x.At.UTC().Format(time.RFC3339Nano)
		write("evidence", p.Framework, p.Edition, x.Upstream, "", "", x.Kind, "", x.Source, x.ID, x.Rule, x.Version, at, "", p.Digest, x.ManifestDigest, "")
		fmt.Fprintf(&human, "\n%s · %s · %s %s · %s (%s), %s\n", x.Upstream, x.Kind, x.Source, x.ID, x.Rule, x.Version, at)
		if x.ManifestDigest != "" {
			fmt.Fprintf(&human, "Manifest %s\n", x.ManifestDigest)
		}
	}
	c.Flush()
	if c.Error() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	return buildSectionPackage(l, s.FrameworkCoverage, rows.Bytes(), human.String())
}
