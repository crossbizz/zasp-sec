package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentExportStatusLifecycle(t *testing.T) {
	identity, _, pin, _ := agentDownloadFixture(t)
	digest := sha256.Sum256([]byte("controlled browser credential"))
	for _, state := range []string{"pending", "completed", "failed"} {
		t.Run(state, func(t *testing.T) {
			status := SecurityAgentExportStatus{ExportID: pin.Reference, State: state, Phase: "terminal", CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), RetrievalExpiresAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), MappingRevision: "security-agent-run-evidence-v1", CleanupState: "pending", Selection: pin.Binding.Selection}
			if state == "pending" {
				status.Phase = "queued"
			}
			if state == "completed" {
				status.Artifact = &SecurityAgentExportArtifactSummary{SHA256: pin.SHA256, Size: pin.Size}
				now := status.CreatedAt.Add(time.Minute)
				status.SnapshotAt = &now
			}
			if state == "failed" {
				reason := "export_cancelled"
				status.FailureCode = &reason
			}
			raw, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			d := &exportSettlementDatabase{response: raw}
			r, _ := NewSecurityAgentExportsRepository(d)
			got, err := r.Get(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID)
			if err != nil || got.State != state || got.ExportID != pin.Reference || got.CleanupState != "pending" {
				t.Fatalf("status refused: %+v %v", got, err)
			}
			if d.statement != `SELECT public.zasp_sa_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)` || len(d.args) != 10 {
				t.Fatalf("wrong status SQL: %s", d.statement)
			}
			want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), pin.Binding.RunID, pin.Binding.StepID, identity.PrincipalID.String(), digest[:], identity.CSRFToken, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}
			for i, v := range want {
				if i == 6 {
					if !bytes.Equal(d.args[i].([]byte), digest[:]) {
						t.Fatal("credential lost")
					}
					continue
				}
				if d.args[i] != v {
					t.Fatalf("arg%d mismatch", i)
				}
			}
		})
	}
}

// A private locator, ambiguous field, malformed source binding or invalid
// lifecycle must never escape the repository as public status.
func TestSecurityAgentExportStatusRefusesMalformedPayloads(t *testing.T) {
	identity, _, pin, _ := agentDownloadFixture(t)
	digest := sha256.Sum256([]byte("controlled browser credential"))
	const valid = `{"export_id":"pid_20000001-0000-4000-8000-000000000001","state":"pending","phase":"queued","failure_code":null,"created_at":"2026-09-19T00:00:00Z","retrieval_expires_at":"2026-09-20T00:00:00Z","mapping_revision":"security-agent-run-evidence-v1","snapshot_at":null,"cleanup_state":"retained","selection":[{"source_kind":"finding","source_id":"pid_20000004-0000-4000-8000-000000000004","source_version":7,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"artifact":null}`
	for _, tc := range []struct{ name, old, replacement string }{
		{"private locator", `"artifact":null`, `"artifact":null,"key":"private/key"`},
		{"duplicate state", `"state":"pending"`, `"state":"pending","state":"completed"`},
		{"terminal pending", `"phase":"queued"`, `"phase":"terminal"`},
		{"null selection", `"selection":[{"source_kind":"finding","source_id":"pid_20000004-0000-4000-8000-000000000004","source_version":7,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`, `"selection":null`},
		{"invalid version", `"source_version":7`, `"source_version":0`},
		{"duplicate version", `"source_version":7`, `"source_version":7,"source_version":8`},
		{"unknown selection field", `"source_version":7`, `"source_version":7,"key":"private"`},
		{"bad association", `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, `bad`},
		{"unknown cleanup", `"cleanup_state":"retained"`, `"cleanup_state":"unknown"`},
		{"unknown failure", `"failure_code":null`, `"failure_code":"unknown"`},
		{"zero snapshot", `"snapshot_at":null`, `"snapshot_at":"0001-01-01T00:00:00Z"`},
		{"private artifact field", `"artifact":null`, `"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"version":"private-version"}`},
		{"empty artifact", `"artifact":null`, `"artifact":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &exportSettlementDatabase{response: json.RawMessage(strings.Replace(valid, tc.old, tc.replacement, 1))}
			r, _ := NewSecurityAgentExportsRepository(db)
			got, err := r.Get(context.Background(), identity, digest[:], pin.Binding.RunID, pin.Binding.StepID)
			if err == nil || got.ExportID != "" {
				t.Fatalf("malformed status exposed: %+v %v", got, err)
			}
		})
	}
}
