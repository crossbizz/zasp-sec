package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLinkedRedTeamFinishRepository(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	run := "pid_99000001-0000-4000-8000-000000000001"
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + run
	input := RedTeamRunCompletion{RunID: run, Worker: "linked-worker", LeaseToken: strings.Repeat("a", 32), InputDigest: sha256.Sum256([]byte("input")), Verdict: "pass", Objective: "Evaluate curated categories: prompt_injection", Behavior: "1 of 1 curated security checks passed; 0 exposed unsafe behavior.", Evidence: []string{"prompt_injection: protected"}, EvidenceReference: "s3://zasp-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "immutable-output", EvidenceChecksum: bytes.Repeat([]byte{0xab}, 32), EvidenceSizeBytes: 1024, InputArtifact: &RedTeamArtifactReference{Reference: "s3://zasp-evidence/" + strings.TrimSuffix(key, run) + "pid_99000002-0000-4000-8000-000000000002", VersionID: "immutable-input", SHA256: strings.Repeat("cd", 32), SizeBytes: 512}}
	now := time.Now().UTC()
	input.EvidenceArtifact = []byte(`{"schema_version":"red-team-evidence-bundle-v2"}`)
	artifactDigest := sha256.Sum256(input.EvidenceArtifact)
	input.EvidenceChecksum = artifactDigest[:]
	input.EvidenceSizeBytes = int64(len(input.EvidenceArtifact))
	result := RedTeamRun{ID: run, Version: 3, DefinitionID: "pid_99000003-0000-4000-8000-000000000003", DefinitionVersion: 1, Status: "complete", Attempt: 1, QueuedAt: now, StartedAt: &now, CompletedAt: &now, Verdict: "pass", EvidenceReference: input.EvidenceReference}
	for _, mode := range []string{"valid", "duplicate", "alias", "null", "wrong_verdict", "wrong_reference", "extra", "missing_input", "missing_artifact", "artifact_digest", "artifact_size", "artifact_json", "artifact_oversize"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(result)
			switch mode {
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"status":"complete"`, `"status":"leased","status":"complete"`, 1))
			case "alias":
				raw = []byte(strings.Replace(string(raw), `"status"`, `"Status"`, 1))
			case "null":
				raw = []byte(strings.Replace(string(raw), `"cancel_requested":false`, `"cancel_requested":null`, 1))
			case "wrong_verdict":
				raw = []byte(strings.Replace(string(raw), `"verdict":"pass"`, `"verdict":"fail"`, 1))
			case "wrong_reference":
				raw = []byte(strings.Replace(string(raw), input.EvidenceReference, "s3://zasp-evidence/other", 1))
			case "extra":
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			}
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamReadySQL: json.RawMessage(`true`), postgresRedTeamPrincipalReadySQL: json.RawMessage(`true`), postgresLinkedRedTeamFinishSQL: raw}}
			repo, err := NewLinkedRedTeamExecutionRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			completion := input
			if mode == "missing_artifact" {
				completion.EvidenceArtifact = nil
			}
			switch mode {
			case "artifact_digest":
				completion.EvidenceArtifact = bytes.Repeat([]byte("x"), len(input.EvidenceArtifact))
			case "artifact_size":
				completion.EvidenceSizeBytes++
			case "artifact_json":
				completion.EvidenceArtifact = []byte(`{broken`)
				hash := sha256.Sum256(completion.EvidenceArtifact)
				completion.EvidenceChecksum = hash[:]
				completion.EvidenceSizeBytes = int64(len(completion.EvidenceArtifact))
			case "artifact_oversize":
				completion.EvidenceArtifact = bytes.Repeat([]byte("x"), (1<<20)+1)
				completion.EvidenceSizeBytes = int64(len(completion.EvidenceArtifact))
			}
			if mode == "missing_input" {
				completion.InputArtifact = nil
			}
			got, err := repo.FinishRedTeamRun(context.Background(), scope, completion)
			if mode == "missing_artifact" && err == nil {
				t.Fatal("completion accepted without exact uploaded artifact bytes")
			}
			if mode != "valid" {
				if err == nil {
					t.Fatalf("invalid %s accepted: %#v", mode, got)
				}
				if (mode == "missing_input" || mode == "missing_artifact" || strings.HasPrefix(mode, "artifact_")) && len(db.callsFor(postgresLinkedRedTeamFinishSQL)) != 0 {
					t.Fatal("missing input reached database")
				}
				return
			}
			if err != nil || got.ID != run || got.Verdict != "pass" {
				t.Fatalf("finish %#v %v", got, err)
			}
			calls := db.callsFor(postgresLinkedRedTeamFinishSQL)
			if len(calls) != 1 || len(calls[0]) != 21 || calls[0][0] != scope.OrganizationID().String() || !bytes.Equal(calls[0][5].([]byte), []byte(input.LeaseToken)) || calls[0][18] != migrations.ProductionSecurityAgentExistingTests().Checksum() || calls[0][19] != migrations.SecurityAgentExistingTestsFingerprint() || !bytes.Equal(calls[0][20].([]byte), input.EvidenceArtifact) {
				t.Fatalf("finish lost scope/raw lease/pins: %#v", calls)
			}
		})
	}
}
