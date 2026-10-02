package sessioncontrol

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestComplianceFormatterCapturedAttribution(t *testing.T) {
	// Optional typed attribution must survive every format; unknown raw fields
	// must never be accepted as source metadata.
	var record EvidenceRecord
	if err := json.Unmarshal([]byte(`{"id":"policy-safe","asset_id":"policy-safe","source":"policy","at":"2026-09-18T00:00:00Z","target":{"source_kind":"policy","source_id":"policy-safe","source_version":7},"metadata":{"verification":"definition_only"}}`), &record); err != nil {
		t.Fatal(err)
	}
	value, err := BuildComplianceExport("export-attribution", []ComplianceEvidence{{Control: ComplianceControl{ID: "SOC2-CC6", Framework: "soc2_security", Name: "Access", FreshUntil: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)}, Freshness: "fresh", Evidence: []EvidenceRecord{record}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"json": value.JSON, "csv": value.CSV, "human": []byte(value.Human)} {
		if !bytes.Contains(body, []byte("definition_only")) || !bytes.Contains(body, []byte("source_version")) {
			t.Fatalf("%s lost captured attribution: %s", name, body)
		}
	}
}

func TestComplianceFormatterFrozenContext(t *testing.T) {
	var value ComplianceEvidence
	raw := `{"control":{"id":"soc2_security-policy","framework":"soc2_security","name":"Policy definitions","evidence_ids":[],"fresh_until":"2026-09-19T00:00:00Z"},"evidence":[],"freshness":"missing","snapshot_context":{"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","mapping_revision":"product-evidence-v1","snapshot_at":"2026-09-18T00:00:00Z"}}`
	if json.Unmarshal([]byte(raw), &value) != nil {
		t.Fatal("invalid fixture")
	}
	result, err := BuildComplianceExport("frozen-context", []ComplianceEvidence{value})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"json": result.JSON, "csv": result.CSV, "human": []byte(result.Human)} {
		for _, want := range []string{"pid_10000003-0000-4000-8000-000000000003", "product-evidence-v1", "2026-09-18T00:00:00Z"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Fatalf("%s lost frozen context %s", name, want)
			}
		}
	}
}
