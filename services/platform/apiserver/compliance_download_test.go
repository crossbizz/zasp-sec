package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol"
	"strings"
	"testing"
)

func TestCompliancePersistedAttributionAndHistoricalBytes(t *testing.T) {
	_, db, reader, id := complianceHTTPFixture(t)
	original := string(db.artifact.Body)
	contextJSON := `{"organization_id":"` + id.Scope.OrganizationID().String() + `","workspace_id":"` + id.Scope.WorkspaceID().String() + `","environment_id":"` + id.Scope.EnvironmentID().String() + `","mapping_revision":"product-evidence-v1","snapshot_at":"2026-09-18T00:00:00Z"}`
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"old", original, true},
		{"context", strings.Replace(original, `"freshness":"missing"`, `"freshness":"missing","snapshot_context":`+contextJSON, 1), true},
		{"foreign-context", strings.Replace(original, `"freshness":"missing"`, `"freshness":"missing","snapshot_context":`+strings.Replace(contextJSON, id.Scope.EnvironmentID().String(), id.Scope.WorkspaceID().String(), 1), 1), false},
		{"future-envelope", strings.Replace(original, `"version":1`, `"version":2`, 1), false},
		{"duplicate", strings.Replace(original, `"version":1`, `"version":1,"version":1`, 1), false},
		{"foreign-id", strings.Replace(original, complianceHTTPJobID, id.Scope.OrganizationID().String(), 1), false},
		{"context-null", strings.Replace(original, `"freshness":"missing"`, `"freshness":"missing","snapshot_context":null`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db.artifact.Body = []byte(tc.body)
			db.artifact.Size = int64(len(tc.body))
			db.artifact.SHA256 = sha256.Sum256(db.artifact.Body)
			pin := complianceReadReceipt{Reference: db.artifact.Reference.String(), Version: db.artifact.VersionID, Size: db.artifact.Size, SHA256: hex.EncodeToString(db.artifact.SHA256[:]), ReadExpiresAt: db.readDeadline}
			_, err := readComplianceDownload(context.Background(), reader, *id, complianceHTTPJobID, "human", pin)
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v err=%v", tc.ok, err)
			}
		})
	}
}

// The formatter omits empty allowlisted evidence_ids on findings. That older
// persisted representation must remain readable without a renderer comparison.
func TestCompliancePersistedEmptyFindingReferences(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	v := sessioncontrol.ComplianceEvidence{}
	raw := `{"control":{"id":"c","framework":"SOC 2","name":"Findings","evidence_ids":[],"fresh_until":"2026-09-18T00:00:00Z"},"evidence":[{"id":"` + complianceHTTPJobID + `","asset_id":"` + complianceHTTPJobID + `","source":"finding","at":"2026-09-18T00:00:00Z","target":{"source_kind":"finding","source_id":"` + complianceHTTPJobID + `","source_version":1},"metadata":{"status":"open","severity":"high"}}],"freshness":"fresh"}`
	if json.Unmarshal([]byte(raw), &v) != nil {
		t.Fatal("fixture")
	}
	if !validCompliancePersistedEvidence([]byte("["+raw+"]"), identity) {
		t.Fatal("stored empty finding references rejected")
	}
	var value ComplianceEvidence
	_ = json.Unmarshal([]byte(strings.Replace(compliancePolicyJSON, `"source":"policy"`, `"source":"finding"`, 1)), &value)
	value.Source = "finding"
	value.Metadata = ComplianceMetadata{Status: "open", Severity: "high", EvidenceIDs: []string{}}
	encoded, _ := json.Marshal(compliancePublicRecord(value))
	if !strings.Contains(string(encoded), `"evidence_ids":[]`) {
		t.Fatal("public empty references lost")
	}
}
