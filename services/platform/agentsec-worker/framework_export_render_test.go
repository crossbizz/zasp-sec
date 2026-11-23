package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

func TestFrameworkCoverageExportFreezesHistoricalCatalogAndAllFormats(t *testing.T) {
	l := complianceRuntimeLease(t)
	now := time.Date(2023, 1, 3, 12, 0, 0, 0, time.UTC)
	checked := now.Add(-time.Hour)
	const old = "edition-retained-before-upgrade"
	row := compliancemap.CatalogEntry{Framework: "owasp_agentic_top10", Edition: old, UpstreamID: "ASI04", Title: "=Archived control", Kind: "risk", Applicability: "applicable", SourceDigest: "archived-digest"}
	report := compliancemap.FrozenReport{Schema: "framework-coverage.v1", Organization: l.Scope.OrganizationID().String(), Workspace: l.Scope.WorkspaceID().String(), Environment: l.Scope.EnvironmentID().String(), Selector: compliancemap.ReportSelector{Framework: row.Framework, Edition: old}, Coverage: compliancemap.ReportPage{ReportEdition: compliancemap.ReportEdition{Framework: row.Framework, Edition: old, Total: 1, Digest: row.SourceDigest}, Matched: 1, Collected: now, Items: []compliancemap.ReportRow{{Control: row, Counts: map[string]int{"static_scan": 1}, Verified: &checked, VerificationStatus: "current"}}}, Evidence: []compliancemap.ReportEvidence{{Source: "addon_version", ID: l.ExportID, Rule: "dependency.unpinned", Version: "zasp-static.v1", Kind: "static_scan", At: now, Framework: row.Framework, Edition: old, Upstream: row.UpstreamID}}}
	body := func() []byte {
		pack, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := json.Marshal(map[string]any{"mapping_revision": "product-evidence-v1", "snapshot_at": now, "organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "controls": []any{}, "framework_coverage": json.RawMessage(pack)})
		return doc
	}
	a, err := renderComplianceExportPackage(context.Background(), l, body())
	if err != nil {
		t.Fatal(err)
	}
	var formats struct {
		Document json.RawMessage `json:"json"`
		CSV      string          `json:"csv"`
		Human    string          `json:"human"`
	}
	if json.Unmarshal(a.Bytes, &formats) != nil {
		t.Fatal("invalid package")
	}
	for _, out := range [][]byte{formats.Document, []byte(formats.CSV), []byte(formats.Human)} {
		for _, value := range []string{old, row.SourceDigest, l.ExportID, "dependency.unpinned", "current"} {
			if !bytes.Contains(out, []byte(value)) {
				t.Fatalf("archived value %s missing", value)
			}
		}
	}
	if !bytes.Contains([]byte(formats.CSV), []byte("'=Archived control")) {
		t.Fatal("formula-compatible cell")
	}
	report.Environment = l.ExportID
	if _, err = renderComplianceExportPackage(context.Background(), l, body()); err == nil {
		t.Fatal("cross-scope frozen report rendered")
	}
}
