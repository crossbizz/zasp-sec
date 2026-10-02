package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestExistingTestComparisonRequiresComparableFailToPass(t *testing.T) {
	for _, name := range []string{"comparable", "mixed", "engine_error", "absent", "still_unsafe", "missing_artifact", "legacy", "endpoint", "configuration", "safety", "credential_binding", "credential_version", "actual_secret_version", "image"} {
		t.Run(name, func(t *testing.T) {
			store, driver, before := fixtureExistingTestEvidence(t, false, name == "mixed")
			_, afterDriver, after := fixtureExistingTestEvidence(t, true, name == "mixed")
			for l, o := range afterDriver.objects {
				driver.objects[l] = o
			}
			baseline := &before
			wantOutcome, wantReason := "remediated", "test_condition_changed"
			switch name {
			case "absent":
				baseline = nil
				wantOutcome, wantReason = "needs_human", "test_baseline_unavailable"
			case "still_unsafe":
				after = before
				baseline = nil
				wantOutcome, wantReason = "needs_human", "test_condition_persists"
			case "missing_artifact":
				before.OutputArtifact.VersionID = "missing"
				wantOutcome, wantReason = "inconclusive", "test_evidence_unavailable"
			case "comparable", "mixed":
			case "engine_error":
				wantOutcome, wantReason = "inconclusive", "test_evaluation_inconclusive"
				after.Verdict = "engine_error"
				after.Observations = nil
				for l, o := range driver.objects {
					if "s3://zasp-evidence/"+l.Key != after.OutputArtifact.Reference {
						continue
					}
					var bundle existingTestEvidenceBundle
					if err := json.Unmarshal(o.Body, &bundle); err != nil {
						t.Fatal(err)
					}
					bundle.Summary.Verdict = "engine_error"
					code := "outcome_unknown"
					bundle.Summary.ErrorCode = &code
					bundle.Summary.Behavior = "The bounded Promptfoo engine did not complete the evaluation."
					bundle.Summary.Evidence = []string{"Promptfoo execution did not complete"}
					bundle.NativeArtifact.NativeOutput = nil
					o.Body, _ = json.Marshal(bundle)
					o.Size = int64(len(o.Body))
					o.SHA256 = sha256.Sum256(o.Body)
					driver.objects[l] = o
					after.OutputArtifact.SHA256 = hex.EncodeToString(o.SHA256[:])
					after.OutputArtifact.SizeBytes = o.Size
				}
			case "legacy":
				wantOutcome, wantReason = "needs_human", "test_baseline_unavailable"
				driver.rewrite(t, &before.InputArtifact, `"schema_version":"red-team-runner-input-v2"`, `"schema_version":"red-team-runner-input-v1"`)
				driver.rewrite(t, &before.InputArtifact, `"runner_image_digest":"sha256:`+strings.Repeat("d", 64)+`",`, ``)
				for l, o := range driver.objects {
					if "s3://zasp-evidence/"+l.Key != before.OutputArtifact.Reference {
						continue
					}
					var bundle existingTestEvidenceBundle
					if err := json.Unmarshal(o.Body, &bundle); err != nil {
						t.Fatal(err)
					}
					bundle.SchemaVersion = "red-team-evidence-bundle-v1"
					bundle.InputArtifact = &before.InputArtifact
					bundle.Summary.SchemaVersion = "red-team-evidence-v1"
					bundle.NativeArtifact.SchemaVersion = "red-team-native-artifact-v1"
					bundle.NativeArtifact.RedactionPolicy = "red-team-artifact-redaction-v1"
					bundle.NativeArtifact.EvaluationIdentity = nil
					bundle.NativeArtifact.NativeOutput.Results.Results[0].Response.LinkedObservation = nil
					bundle.NativeArtifact.NativeOutput.Results.Results[0].TestCase.Assert = nil
					o.Body, _ = json.Marshal(bundle)
					o.Size = int64(len(o.Body))
					o.SHA256 = sha256.Sum256(o.Body)
					driver.objects[l] = o
					before.OutputArtifact.SHA256 = hex.EncodeToString(o.SHA256[:])
					before.OutputArtifact.SizeBytes = o.Size
				}
				before.Observations = nil
			default:
				wantOutcome, wantReason = "needs_human", "test_baseline_unavailable"
				observation := &after.Observations[0]
				old := ""
				replacement := strings.Repeat("f", 64)
				switch name {
				case "endpoint":
					old = `"endpoint_digest":"` + observation.TargetComparison.Endpoint + `"`
					observation.TargetComparison.Endpoint = replacement
					replacement = `"endpoint_digest":"` + replacement + `"`
				case "configuration":
					old = `"configuration_digest":"` + observation.TargetComparison.Configuration + `"`
					observation.TargetComparison.Configuration = replacement
					replacement = `"configuration_digest":"` + replacement + `"`
				case "safety":
					old = `"safety_digest":"` + observation.TargetComparison.Safety + `"`
					observation.TargetComparison.Safety = replacement
					replacement = `"safety_digest":"` + replacement + `"`
				case "credential_binding":
					old = `"credential_binding_digest":"` + observation.TargetComparison.CredentialDigest + `"`
					observation.TargetComparison.CredentialDigest = replacement
					replacement = `"credential_binding_digest":"` + replacement + `"`
				case "credential_version":
					old = `"credential_binding_version":1`
					replacement = `"credential_binding_version":2`
					observation.TargetComparison.CredentialVersion = 2
				case "actual_secret_version":
					old = `"credential_version_digest":"` + observation.CredentialVersionDigest + `"`
					observation.CredentialVersionDigest = replacement
					replacement = `"credential_version_digest":"` + replacement + `"`
				case "image":
					old = `"runner_image_digest":"sha256:` + strings.Repeat("d", 64) + `"`
					replacement = `"runner_image_digest":"sha256:` + replacement + `"`
					oldReceipt, _ := json.Marshal(after.InputArtifact)
					driver.rewrite(t, &after.InputArtifact, old, replacement)
					newReceipt, _ := json.Marshal(after.InputArtifact)
					driver.rewrite(t, &after.OutputArtifact, string(oldReceipt), string(newReceipt))
				}
				driver.rewrite(t, &after.OutputArtifact, old, replacement)
				if _, err := readExistingTestEvidence(context.Background(), store, after); err != nil {
					t.Fatalf("changed but internally valid evaluation rejected: %v", err)
				}
			}
			result := verifyExistingTestComparison(context.Background(), store, baseline, after)
			if result.Outcome != wantOutcome || result.Reason != wantReason {
				t.Fatalf("result=%#v want %s/%s", result, wantOutcome, wantReason)
			}
			if name == "comparable" || name == "mixed" {
				count := 1
				if name == "mixed" {
					count = 2
				}
				if len(result.Checks) != count || result.Checks[0].BeforeProtected || !result.Checks[0].AfterProtected || result.Checks[0].CheckID != "zasp.curated.prompt_injection.v1" || result.Before == nil || result.Before.RunID != before.RunID || result.After == nil || result.After.RunID != after.RunID || result.Digest == "" {
					t.Fatalf("missing bounded before/after proof: %#v", result)
				}
				if name == "mixed" && (!result.Checks[1].BeforeProtected || !result.Checks[1].AfterProtected || result.Checks[1].CheckID != "zasp.curated.tool_abuse.v1") {
					t.Fatal("unchanged protected check not retained")
				}
				again := verifyExistingTestComparison(context.Background(), store, baseline, after)
				body, _ := json.Marshal(result)
				digest := sha256.Sum256(body)
				if again.Digest != result.Digest || result.Digest != hex.EncodeToString(digest[:]) {
					t.Fatal("proof digest not deterministic")
				}
			} else if result.Outcome == "remediated" || len(result.Checks) != 0 {
				t.Fatal("noncomparable evidence claimed change")
			}
		})
	}
}
