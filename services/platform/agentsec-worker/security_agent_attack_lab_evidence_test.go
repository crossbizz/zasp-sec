package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

func TestAttackLabReconcilerEvidenceOutcomes(t *testing.T) {
	for _, verdict := range []string{"verified", "not_reproduced"} {
		t.Run(verdict, func(t *testing.T) {
			request, sandbox, result := validAttackLabEvidenceWriteFixture(t)
			result.Verdict = verdict
			result.CriterionObserved = verdict == "verified"
			result.CanaryTouched = result.CriterionObserved
			store := &attackLabEvidenceStoreStub{}
			writer, _ := newProductionAttackLabEvidenceWriter(store)
			receipt, err := writer.Write(context.Background(), request, sandbox, result)
			if err != nil {
				t.Fatal(err)
			}
			ref, key, _ := attackLabEvidenceIdentity(request.Scope, request.Run.ID, request.Run.Attempt)
			locator := artifactstore.Locator{Scope: request.Scope, Reference: ref, VersionID: receipt.VersionID}
			artifact := artifactstore.Artifact{Locator: locator, MediaType: "application/json", Body: store.puts[0].Body, Size: receipt.SizeBytes, SHA256: sha256.Sum256(store.puts[0].Body)}
			reader := &existingTestReadOnlyArtifacts{get: func(_ context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
				if l != locator {
					t.Fatal("read unpinned version")
				}
				return artifact, nil
			}, reference: store.ObjectReference}
			yes, no := true, false
			source := attackLabLinkSource{Run: request.Run.SourceRunID, Attempt: 1, Definition: request.Run.DefinitionID, DefinitionVersion: request.Run.DefinitionVersion, Target: request.Run.TargetID, Kind: request.Run.TargetKind}
			snapshot := attackLabLinkSnapshot{scope: request.Scope, Source: source, SourceValid: &yes, Execution: attackLabLinkExecution{Run: request.Run.ID, Attempt: request.Run.Attempt, InputDigest: hex.EncodeToString(request.InputDigest[:]), State: "complete", Verdict: &verdict, CleanupState: "complete", CleanupComplete: &yes, Unknown: &no, Denied: &no, Cancelled: &no, Sandbox: &sandbox.Reference, Artifact: &existingTestSnapshotReceipt{Reference: receipt.Reference, Key: key, VersionID: receipt.VersionID, SHA256: hex.EncodeToString(receipt.Checksum), SizeBytes: receipt.SizeBytes}}}
			proof, pending := verifyAttackLabLink(context.Background(), reader, snapshot)
			want := "attack_lab_not_reproduced_in_bounded_run"
			if verdict == "verified" {
				want = "attack_lab_unsafe_condition_reproduced"
			}
			if pending || proof.Outcome != "needs_human" || proof.Reason != want {
				t.Fatalf("bounded verdict became %s/%s pending=%v", proof.Outcome, proof.Reason, pending)
			}
			for _, mutation := range []string{"cleanup", "unknown", "source", "artifact_version", "artifact_checksum", "artifact_size", "scope", "source_run", "attempt", "input", "criterion_missing", "duplicate"} {
				t.Run(mutation, func(t *testing.T) {
					changed := snapshot
					execCopy := snapshot.Execution
					changed.Execution = execCopy
					body := append([]byte(nil), artifact.Body...)
					old := artifact
					defer func() { artifact = old }()
					switch mutation {
					case "cleanup":
						changed.Execution.CleanupComplete = &no
					case "unknown":
						changed.Execution.Unknown = &yes
					case "source":
						changed.SourceValid = &no
					case "artifact_version":
						artifact.VersionID = "different-version"
					case "artifact_checksum":
						artifact.SHA256 = sha256.Sum256([]byte("wrong"))
					case "artifact_size":
						artifact.Size++
					default:
						var fields map[string]any
						json.Unmarshal(body, &fields)
						switch mutation {
						case "scope":
							fields["organization_id"] = request.Scope.WorkspaceID().String()
						case "source_run":
							fields["source_run_id"] = request.Run.ID
						case "attempt":
							fields["attempt"] = 2
						case "input":
							fields["input_digest"] = hex.EncodeToString(make([]byte, 32))
						case "criterion_missing":
							delete(fields, "criterion_observed")
						}
						body, _ = json.Marshal(fields)
						if mutation == "duplicate" {
							body = append(body[:len(body)-1], []byte(`,"attempt":1}`)...)
						}
						artifact.Body = body
						artifact.Size = int64(len(body))
						artifact.SHA256 = sha256.Sum256(body)
						receiptCopy := *changed.Execution.Artifact
						receiptCopy.SizeBytes = artifact.Size
						receiptCopy.SHA256 = hex.EncodeToString(artifact.SHA256[:])
						changed.Execution.Artifact = &receiptCopy
					}
					got, pending := verifyAttackLabLink(context.Background(), reader, changed)
					if mutation == "cleanup" {
						if !pending {
							t.Fatal("cleanup lag settled")
						}
						return
					}
					if pending || got.Outcome != "inconclusive" {
						t.Fatalf("unproved evidence accepted: %#v pending=%v", got, pending)
					}
				})
			}
		})
	}
}
