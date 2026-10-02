package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A decoder that drops DB attempt identity or permits a substituted claim must
// fail these tests before evidence can reach the artifact verifier.
func TestExistingTestSnapshotBindsClaimAndReadsPersistedEvidence(t *testing.T) {
	store, _, request := fixtureExistingTestEvidence(t)
	raw := fixtureExistingTestSnapshot(t, request)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	got, err := decodeExistingTestSnapshot(raw, request.Scope, snapshotRun, snapshotStep, request.RunID, 2, snapshotGeneration, now)
	if err != nil || got.After == nil || got.After.Attempt != request.Attempt || got.Before != nil || got.State != "complete" || got.OutcomeUnknown {
		t.Fatalf("snapshot lost DB authority: %#v %v", got, err)
	}
	evidence, err := readExistingTestEvidence(context.Background(), store, *got.After)
	if err != nil || evidence.Bundle.Summary.Verdict != "fail" {
		t.Fatalf("decoded receipt cannot verify persisted evidence: %v", err)
	}
}

const snapshotRun = "pid_99400007-0000-4000-8000-000000000007"
const snapshotStep = "pid_99400008-0000-4000-8000-000000000008"

func fixtureExistingTestSnapshot(t *testing.T, r existingTestEvidenceRequest) []byte {
	t.Helper()
	receipt := func(ref any) map[string]any {
		b, _ := json.Marshal(ref)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["key"] = strings.SplitN(strings.TrimPrefix(m["reference"].(string), "s3://"), "/", 2)[1]
		return m
	}
	value := map[string]any{"generation": snapshotGeneration, "version": 2, "lease_expires_at": "2026-09-17T00:01:00Z", "snapshot": map[string]any{
		"schema_version": "security-agent-test-evidence-snapshot-v1", "organization_id": r.Scope.OrganizationID().String(), "workspace_id": r.Scope.WorkspaceID().String(), "environment_id": r.Scope.EnvironmentID().String(), "run_id": snapshotRun, "step_id": snapshotStep, "definition_id": r.DefinitionID, "definition_version": r.DefinitionVersion, "target_id": r.TargetID, "target_kind": r.TargetKind, "categories": r.Categories, "before": nil,
		"after": map[string]any{"run_id": r.RunID, "state": "complete", "attempt": r.Attempt, "input_digest": r.InputDigest, "verdict": r.Verdict, "error_code": nil, "completed_at": "2026-09-16T23:59:00Z", "input_artifact": r.InputArtifact, "output_artifact": receipt(r.OutputArtifact), "observations": r.Observations, "outcome_unknown": false}}}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExistingTestSnapshotRejectsChangedAuthority(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	raw := fixtureExistingTestSnapshot(t, r)
	for _, mutation := range []struct{ name, old, next string }{
		{"generation", snapshotGeneration, "99400010-0000-4000-8000-000000000010"},
		{"version", `"version":2`, `"version":3`},
		{"expiry", `2026-09-17T00:01:00Z`, `2026-09-16T00:01:00Z`},
		{"tenant", r.Scope.OrganizationID().String(), snapshotStep},
		{"parent", snapshotRun, snapshotStep},
		{"step", snapshotStep, snapshotRun},
		{"after_run", r.RunID, snapshotRun},
		{"attempt", `"attempt":1`, `"attempt":0`},
		{"duplicate", `"version":2`, `"version":2,"version":2`},
		{"alias", `"version":2`, `"Version":2`},
		{"unknown_missing", `"outcome_unknown":false,`, ``},
		{"unknown_null", `"outcome_unknown":false`, `"outcome_unknown":null`},
		{"receipt_key", `"key":"organizations/`, `"key":"wrong/`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(string(raw), mutation.old, mutation.next, 1)
			if changed == string(raw) {
				t.Fatal("mutation missed")
			}
			if _, err := decodeExistingTestSnapshot([]byte(changed), r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

func TestExistingTestSnapshotRetainsUnknownAfterLateJournalCompletion(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	var v map[string]any
	_ = json.Unmarshal(fixtureExistingTestSnapshot(t, r), &v)
	a := v["snapshot"].(map[string]any)["after"].(map[string]any)
	a["state"] = "failed"
	a["verdict"] = nil
	a["input_artifact"] = nil
	a["output_artifact"] = nil
	a["error_code"] = "outcome_unknown"
	raw, _ := json.Marshal(v)
	got, err := decodeExistingTestSnapshot(raw, r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))
	if err != nil || !got.OutcomeUnknown || got.State != "failed" || got.After != nil {
		t.Fatalf("late journal completion erased unknown: %#v %v", got, err)
	}
}

func TestExistingTestSnapshotRejectsNullObservations(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	var v map[string]any
	_ = json.Unmarshal(fixtureExistingTestSnapshot(t, r), &v)
	v["snapshot"].(map[string]any)["after"].(map[string]any)["observations"] = nil
	raw, _ := json.Marshal(v)
	if _, err := decodeExistingTestSnapshot(raw, r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("null observations accepted")
	}
}

func TestExistingTestSnapshotPreservesPendingAndUnknown(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	raw := fixtureExistingTestSnapshot(t, r)
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	s := v["snapshot"].(map[string]any)
	a := s["after"].(map[string]any)
	a["state"] = "leased"
	a["verdict"] = nil
	a["completed_at"] = nil
	a["input_artifact"] = nil
	a["output_artifact"] = nil
	a["outcome_unknown"] = true
	b, _ := json.Marshal(v)
	got, err := decodeExistingTestSnapshot(b, r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))
	if err != nil || got.State != "leased" || !got.OutcomeUnknown || got.After != nil {
		t.Fatalf("pending/unknown became verifiable: %#v %v", got, err)
	}
}

func TestExistingTestSnapshotFeedsComparableBaselineToVerifier(t *testing.T) {
	store, driver, before := fixtureExistingTestEvidence(t)
	_, afterDriver, after := fixtureExistingTestEvidence(t, true)
	for l, o := range afterDriver.objects {
		driver.objects[l] = o
	}
	var current, prior map[string]any
	_ = json.Unmarshal(fixtureExistingTestSnapshot(t, after), &current)
	_ = json.Unmarshal(fixtureExistingTestSnapshot(t, before), &prior)
	current["snapshot"].(map[string]any)["before"] = prior["snapshot"].(map[string]any)["after"]
	raw, _ := json.Marshal(current)
	got, err := decodeExistingTestSnapshot(raw, after.Scope, snapshotRun, snapshotStep, after.RunID, 2, snapshotGeneration, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))
	if err != nil || got.Before == nil || got.After == nil {
		t.Fatalf("baseline unavailable: %#v %v", got, err)
	}
	proof := verifyExistingTestComparison(context.Background(), store, got.Before, *got.After)
	if proof.Outcome != "remediated" || proof.Reason != "test_condition_changed" || proof.Before.RunID != before.RunID || proof.After.RunID != after.RunID || len(driver.reads) != 4 {
		t.Fatalf("baseline not retained through verification: %#v reads=%d", proof, len(driver.reads))
	}
}
