package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const snapshotGeneration = "99400009-0000-4000-8000-000000000009"

func TestExistingTestGenerationReceiptShapes(t *testing.T) {
	store, _, evidence := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	claim := existingTestClaim{scope: evidence.Scope, run: snapshotRun, step: snapshotStep, testRun: evidence.RunID, version: 2, generation: snapshotGeneration, token: [32]byte{1}, worker: "generation-client", expires: now.Add(time.Minute)}
	snapshot, err := decodeExistingTestSnapshot(fixtureExistingTestSnapshot(t, evidence), evidence.Scope, snapshotRun, snapshotStep, evidence.RunID, 2, snapshotGeneration, now)
	if err != nil {
		t.Fatal(err)
	}
	proof := verifyExistingTestComparison(context.Background(), store, nil, evidence)
	for _, operation := range []string{"claim", "heartbeat", "release", "cancel", "snapshot", "settle"} {
		for _, shape := range []string{"valid", "missing", "null", "zero", "malformed", "uppercase", "alias", "duplicate"} {
			t.Run(operation+"/"+shape, func(t *testing.T) {
				value := map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "version": 2, "generation": snapshotGeneration, "lease_expires_at": "2026-09-17T00:00:30Z"}
				switch operation {
				case "claim":
					value["organization_id"], value["workspace_id"], value["environment_id"], value["test_run_id"] = evidence.Scope.OrganizationID().String(), evidence.Scope.WorkspaceID().String(), evidence.Scope.EnvironmentID().String(), evidence.RunID
				case "release":
					delete(value, "lease_expires_at")
					value["version"], value["state"], value["next_check_at"] = 3, "pending", "2026-09-17T00:00:30Z"
				case "cancel":
					value = map[string]any{"generation": snapshotGeneration, "test_run_id": evidence.RunID, "state": "queued", "changed": false, "cancellation_outcome": nil}
				case "snapshot":
					value = map[string]any{}
					if err := json.Unmarshal(fixtureExistingTestSnapshot(t, evidence), &value); err != nil {
						t.Fatal(err)
					}
				case "settle":
					value = map[string]any{"generation": snapshotGeneration, "run_id": snapshotRun, "step_id": snapshotStep, "reconcile_version": 3, "state": "needs_human", "step_state": "succeeded", "effect_state": "succeeded", "outcome": proof.Outcome, "reason": proof.Reason, "proof_sha256": proof.Digest}
				}
				switch shape {
				case "missing":
					delete(value, "generation")
				case "null":
					value["generation"] = nil
				case "zero":
					value["generation"] = "00000000-0000-0000-0000-000000000000"
				case "malformed":
					value["generation"] = "not-a-uuid"
				case "uppercase":
					value["generation"] = "AAAAAAAA-0000-4000-8000-000000000001"
				case "alias":
					delete(value, "generation")
					value["Generation"] = snapshotGeneration
				}
				raw, _ := json.Marshal(value)
				if shape == "duplicate" {
					raw = []byte(strings.Replace(string(raw), `"generation":`, `"generation":"`+snapshotGeneration+`","generation":`, 1))
				}
				if operation == "claim" {
					raw = append(append([]byte("["), raw...), ']')
				}
				calls := 0
				db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) { calls++; return raw, nil }}
				client, _ := newExistingTestClient(db, claim.worker, func() time.Time { return now })
				var callErr error
				switch operation {
				case "claim":
					_, callErr = client.Claim(context.Background(), evidence.Scope, 30, 1)
				case "heartbeat":
					_, callErr = client.Heartbeat(context.Background(), claim, 30)
				case "release":
					_, callErr = client.Release(context.Background(), claim, 30)
				case "cancel":
					callErr = client.CancelStopped(context.Background(), claim)
				case "snapshot":
					_, callErr = decodeExistingTestSnapshot(raw, evidence.Scope, snapshotRun, snapshotStep, evidence.RunID, 2, snapshotGeneration, now)
				case "settle":
					request, prepareErr := client.PrepareSettlement(claim, snapshot, proof)
					if prepareErr != nil {
						t.Fatal(prepareErr)
					}
					_, callErr = client.Settle(context.Background(), request)
				}
				if (callErr == nil) != (shape == "valid") || operation != "snapshot" && calls != 1 {
					t.Fatalf("generation shape=%s calls=%d err=%v", shape, calls, callErr)
				}
			})
		}
	}
}

func TestExistingTestGenerationFencesMaximumVersionRelease(t *testing.T) {
	_, _, evidence := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, changed := range []bool{false, true} {
		calls := 0
		db := &reconcileQueryFixture{call: func(_ context.Context, q string, args ...any) (json.RawMessage, error) {
			calls++
			if calls == 1 {
				return json.Marshal([]any{map[string]any{"organization_id": args[0], "workspace_id": args[1], "environment_id": args[2], "run_id": snapshotRun, "step_id": snapshotStep, "test_run_id": evidence.RunID, "version": 1000000, "generation": snapshotGeneration, "lease_expires_at": "2026-09-17T00:00:30Z"}})
			}
			if !strings.Contains(q, "reconcile_release(") || len(args) != 12 || args[7] != int64(1000000) || args[8] != snapshotGeneration || args[9] != 30 {
				t.Fatal("maximum release lost generation or changed ownership")
			}
			generation := snapshotGeneration
			if changed {
				generation = "99400010-0000-4000-8000-000000000010"
			}
			return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "version": 1000000, "generation": generation, "state": "pending", "next_check_at": "2026-09-17T00:00:30Z"})
		}}
		client, _ := newExistingTestClient(db, "generation-client", func() time.Time { return now })
		claims, err := client.Claim(context.Background(), evidence.Scope, 30, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("maximum generation claim rejected: %v", err)
		}
		_, err = client.Release(context.Background(), claims[0], 30)
		if (err != nil) != changed || calls != 2 {
			t.Fatalf("maximum generation release: calls=%d changed=%t err=%v", calls, changed, err)
		}
	}
}

func TestExistingTestGenerationBindsMaximumSettlement(t *testing.T) {
	store, _, evidence := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	raw := []byte(strings.Replace(string(fixtureExistingTestSnapshot(t, evidence)), `"version":2`, `"version":1000000`, 1))
	snapshot, err := decodeExistingTestSnapshot(raw, evidence.Scope, snapshotRun, snapshotStep, evidence.RunID, 1000000, snapshotGeneration, now)
	if err != nil {
		t.Fatal(err)
	}
	claim := existingTestClaim{scope: evidence.Scope, run: snapshotRun, step: snapshotStep, testRun: evidence.RunID, version: 1000000, generation: snapshotGeneration, token: [32]byte{1}, worker: "generation-client", expires: now.Add(time.Minute)}
	proof := verifyExistingTestComparison(context.Background(), store, nil, evidence)
	wrongGeneration := false
	db := &reconcileQueryFixture{call: func(_ context.Context, q string, args ...any) (json.RawMessage, error) {
		if !strings.Contains(q, "reconcile_settle(") || len(args) != 13 || args[7] != int64(1000000) || args[8] != snapshotGeneration {
			t.Fatal("settlement lost generation")
		}
		generation := snapshotGeneration
		if wrongGeneration {
			generation = "99400010-0000-4000-8000-000000000010"
		}
		return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "generation": generation, "reconcile_version": 1000000, "state": "needs_human", "step_state": "succeeded", "effect_state": "succeeded", "outcome": proof.Outcome, "reason": proof.Reason, "proof_sha256": proof.Digest})
	}}
	client, _ := newExistingTestClient(db, claim.worker, func() time.Time { return now })
	request, err := client.PrepareSettlement(claim, snapshot, proof)
	if err != nil {
		t.Fatalf("maximum settlement preparation refused: %v", err)
	}
	if _, err = client.Settle(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err = client.Settle(context.Background(), request); err != nil {
		t.Fatalf("saved generation replay refused: %v", err)
	}
	wrongGeneration = true
	if _, err = client.Settle(context.Background(), request); err == nil {
		t.Fatal("another generation acknowledged settlement")
	}
}
