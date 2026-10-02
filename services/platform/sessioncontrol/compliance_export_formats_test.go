package sessioncontrol

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Losing record-level attribution in CSV or text must fail this test.
func TestComplianceExportFormatsRetainEvidenceAttribution(t *testing.T) {
	at := time.Date(2026, 9, 17, 1, 2, 3, 123000000, time.UTC)
	values := []ComplianceEvidence{
		{Control: ComplianceControl{ID: "control-a", Framework: "SOC 2", Name: "Access review", EvidenceIDs: []string{"record-a", "record-b"}, FreshUntil: at}, Freshness: "stale",
			Evidence: []EvidenceRecord{{ID: "record-a", AssetID: "asset-a", Source: "runtime", At: at}, {ID: "record-b", AssetID: "asset-b", Source: "audit", At: at}}},
		{Control: ComplianceControl{ID: "control-b", Framework: "HIPAA", Name: "Safeguards", EvidenceIDs: []string{"absent"}, FreshUntil: at}, Freshness: "missing"},
	}
	result, err := BuildComplianceExport("export-formats", values)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(result.CSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"control_id", "framework", "freshness", "evidence_count", "evidence_id", "asset_id", "source", "at"},
		{"control-a", "SOC 2", "stale", "2", "record-a", "asset-a", "runtime", "2026-09-17T01:02:03.123Z"},
		{"control-a", "SOC 2", "stale", "2", "record-b", "asset-b", "audit", "2026-09-17T01:02:03.123Z"},
		{"control-b", "HIPAA", "missing", "0", "", "", "", ""},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("record attribution lost: %#v", rows)
	}
	for _, token := range []string{"Access review", "record-a", "record-b", "asset-a", "asset-b", "runtime", "audit", "2026-09-17T01:02:03.123Z", "stale", "control-b", "missing", "absent", "does not attest compliance"} {
		if !strings.Contains(result.Human, token) {
			t.Errorf("human report missing %q", token)
		}
	}
	var decoded []ComplianceEvidence
	if err := json.Unmarshal(result.JSON, &decoded); err != nil || !reflect.DeepEqual(decoded, values) {
		t.Fatalf("JSON changed: %v", err)
	}
}

// CSV quoting alone does not prevent spreadsheet formula execution.
func TestComplianceExportCSVNeutralizesFormulaFields(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	result, err := BuildComplianceExport("export-safe", []ComplianceEvidence{{
		Control:   ComplianceControl{ID: "=1+1", Framework: " @SUM(1)", Name: "Review\nforged heading", EvidenceIDs: []string{"+record"}, FreshUntil: at},
		Freshness: "fresh", Evidence: []EvidenceRecord{{ID: "+record", AssetID: "-asset", Source: "\t=1", At: at}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(result.CSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"'=1+1", "' @SUM(1)", "fresh", "1", "'+record", "'-asset", "'\t=1", "2026-09-17T00:00:00Z"}
	if len(rows) != 2 || !reflect.DeepEqual(rows[1], want) {
		t.Fatalf("unsafe CSV: %#v", rows)
	}
	if strings.Contains(result.Human, "Review\nforged heading") {
		t.Fatal("untrusted text created a report line")
	}
	if !strings.Contains(string(result.JSON), "+record") {
		t.Fatal("canonical JSON evidence changed")
	}
}

// A usable report larger than the old disclaimer ceiling must persist intact.
func TestComplianceExportDetailedReportPersistsBeyondDisclaimerSize(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	values := make([]ComplianceEvidence, 40)
	for i := range values {
		values[i] = ComplianceEvidence{Control: ComplianceControl{ID: "control", Framework: "HIPAA", Name: strings.Repeat("Review ", 30), EvidenceIDs: []string{"record"}, FreshUntil: at},
			Freshness: "fresh", Evidence: []EvidenceRecord{{ID: "record", AssetID: "asset", Source: "runtime", At: at}}}
	}
	result, err := BuildComplianceExport("export-detailed", values)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Human) <= 4096 {
		t.Fatalf("report omitted detail: %d bytes", len(result.Human))
	}
	locator := complianceExportLocator(t)
	artifact, err := WriteComplianceExportArtifact(context.Background(), &complianceArtifactStore{}, locator.Scope, locator.Reference, result)
	if err != nil {
		t.Fatal(err)
	}
	var stored complianceExportPackage
	if err := json.Unmarshal(artifact.Body, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Human != result.Human || stored.CSV != string(result.CSV) {
		t.Fatal("stored report lost detail")
	}
}

func TestComplianceExportRefusesOversizedCombinedPackage(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	// Each format is below its own ceiling, but their envelope exceeds 8 MiB.
	values := make([]ComplianceEvidence, 100)
	for i := range values {
		values[i] = ComplianceEvidence{
			Control:   ComplianceControl{ID: strings.Repeat("c", 128), Framework: strings.Repeat("f", 64), Name: strings.Repeat("n", 256), FreshUntil: at},
			Freshness: "fresh", Evidence: make([]EvidenceRecord, 65),
		}
		for j := range values[i].Evidence {
			values[i].Evidence[j] = EvidenceRecord{ID: strings.Repeat("e", 128), AssetID: strings.Repeat("a", 128), Source: strings.Repeat("s", 64), At: at}
		}
	}
	input, err := json.Marshal(values)
	if err != nil || len(input) >= 4*1024*1024 {
		t.Fatalf("fixture exceeds JSON input ceiling: %d %v", len(input), err)
	}
	_, err = BuildComplianceExport("export-large", values)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized package accepted: %v", err)
	}
}

func TestComplianceExportWriterPreservesQuotedLabelsAndRejectsForgedReport(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	value, err := BuildComplianceExport("export-labels", []ComplianceEvidence{{
		Control:   ComplianceControl{ID: "control", Framework: "SOC 2", Name: "Access recertification", EvidenceIDs: []string{"record"}, FreshUntil: at},
		Freshness: "fresh", Evidence: []EvidenceRecord{{ID: "record", AssetID: "asset", Source: "audit", At: at}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	locator := complianceExportLocator(t)
	if _, err := WriteComplianceExportArtifact(context.Background(), &complianceArtifactStore{}, locator.Scope, locator.Reference, value); err != nil {
		t.Errorf("quoted control label rejected as an assurance: %v", err)
	}
	value.Human = "All controls passed."
	store := &complianceArtifactStore{}
	if _, err := WriteComplianceExportArtifact(context.Background(), store, locator.Scope, locator.Reference, value); !errors.Is(err, ErrRejected) || store.calls != 0 {
		t.Errorf("unbound report accepted: calls=%d err=%v", store.calls, err)
	}
}

func TestComplianceExportRejectsUnboundedNestedInput(t *testing.T) {
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"framework", "records", "expected_ids"} {
		t.Run(mode, func(t *testing.T) {
			value := ComplianceEvidence{Control: ComplianceControl{ID: "control", Framework: "SOC 2", Name: "Review", FreshUntil: at}, Freshness: "missing"}
			switch mode {
			case "framework":
				value.Control.Framework = strings.Repeat("x", 65)
			case "records":
				value.Evidence = make([]EvidenceRecord, 101)
				for i := range value.Evidence {
					value.Evidence[i] = EvidenceRecord{ID: "record", AssetID: "asset", Source: "runtime", At: at}
				}
			case "expected_ids":
				value.Control.EvidenceIDs = make([]string, 101)
				for i := range value.Control.EvidenceIDs {
					value.Control.EvidenceIDs[i] = "record"
				}
			}
			if _, err := BuildComplianceExport("export-bounds", []ComplianceEvidence{value}); !errors.Is(err, ErrRejected) {
				t.Fatalf("unbounded %s accepted: %v", mode, err)
			}
		})
	}
}
