package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Changing the source snapshot, proof bytes, ownership tuple or receipt digest
// must prevent the worker from acknowledging settlement. The DB remains the
// authority on whether an expired request is an exact replay.
func TestExistingTestSettlementClientExactRequestAndReplay(t *testing.T) {
	store, _, r := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	raw := fixtureExistingTestSnapshot(t, r)
	snapshot, err := decodeExistingTestSnapshot(raw, r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, now)
	if err != nil {
		t.Fatal(err)
	}
	proof := verifyExistingTestComparison(context.Background(), store, nil, r)
	proofBytes, _ := json.Marshal(proof)
	outcome, reason := proof.Outcome, proof.Reason
	digest := sha256.Sum256(proofBytes)
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(raw, &envelope)
	claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, expires: now.Add(time.Minute), worker: "settlement-client", token: [32]byte{1}}
	var previous []any
	calls := 0
	db := &reconcileQueryFixture{call: func(_ context.Context, query string, args ...any) (json.RawMessage, error) {
		calls++
		want := append(claim.args(), string(envelope["snapshot"]), proofBytes, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
		if query != "SELECT zasp_production_security_agent_existing_tests_reconcile_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)" || !reflect.DeepEqual(args, want) {
			t.Fatal("changed settlement authority or proof bytes")
		}
		if previous != nil && !reflect.DeepEqual(previous, args) {
			t.Fatal("lost-response replay changed request")
		}
		previous = args
		return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "state": "needs_human", "step_state": "succeeded", "effect_state": "succeeded", "outcome": outcome, "reason": reason, "proof_sha256": hex.EncodeToString(digest[:]), "generation": snapshotGeneration, "reconcile_version": 3})
	}}
	client, _ := newExistingTestClient(db, "settlement-client", func() time.Time { return now })
	request, err := client.PrepareSettlement(claim, snapshot, proof)
	if err != nil {
		t.Fatal(err)
	}
	// Neither subsequent caller mutation nor lease expiry may alter saved bytes.
	for i := range raw {
		raw[i] = 'x'
	}
	proof.Reason = "changed"
	if _, err = client.Settle(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err = client.Settle(context.Background(), request); err != nil {
		t.Fatalf("exact replay unavailable: %v", err)
	}
	if calls != 2 {
		t.Fatal("missing guarded settlement")
	}
}

func TestExistingTestSettlementClientRefusesCorruptReceipt(t *testing.T) {
	store, _, r := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	snapshot, _ := decodeExistingTestSnapshot(fixtureExistingTestSnapshot(t, r), r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, now)
	proof := verifyExistingTestComparison(context.Background(), store, nil, r)
	claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, expires: now.Add(time.Minute), worker: "settlement-client", token: [32]byte{1}}
	for _, field := range []string{"run_id", "step_id", "state", "step_state", "effect_state", "outcome", "reason", "proof_sha256", "reconcile_version", "duplicate", "null", "false_remediation", "false_verified", "stopped_success"} {
		t.Run(field, func(t *testing.T) {
			db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
				v := map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "state": "needs_human", "step_state": "succeeded", "effect_state": "succeeded", "outcome": proof.Outcome, "reason": proof.Reason, "proof_sha256": proof.Digest, "generation": snapshotGeneration, "reconcile_version": 3}
				if field == "reconcile_version" {
					v[field] = 2
				} else if field != "duplicate" && field != "null" {
					v[field] = "invalid"
				}
				b, _ := json.Marshal(v)
				if field == "false_remediation" || field == "false_verified" || field == "stopped_success" {
					delete(v, field)
					if field == "false_remediation" {
						v["state"] = "remediated"
					}
					if field == "false_verified" {
						v["effect_state"] = "verified"
					}
					if field == "stopped_success" {
						v["state"] = "cancelled"
					}
					b, _ = json.Marshal(v)
				}
				if field == "duplicate" {
					b = []byte(strings.Replace(string(b), `"run_id":`, `"run_id":"`+snapshotRun+`","run_id":`, 1))
				}
				if field == "null" {
					b = []byte("null")
				}
				return b, nil
			}}
			client, _ := newExistingTestClient(db, "settlement-client", func() time.Time { return now })
			request, err := client.PrepareSettlement(claim, snapshot, proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.Settle(context.Background(), request); err == nil {
				t.Fatal("corrupt settlement acknowledged")
			}
		})
	}
}

func TestExistingTestSettlementClientRefusesInvalidPreparation(t *testing.T) {
	store, _, r := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	for _, mutation := range []string{"expired", "foreign_worker", "step", "version", "no_source", "digest", "schema", "outcome", "empty_reason", "oversized"} {
		t.Run(mutation, func(t *testing.T) {
			snapshot, _ := decodeExistingTestSnapshot(fixtureExistingTestSnapshot(t, r), r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, now)
			proof := verifyExistingTestComparison(context.Background(), store, nil, r)
			claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, expires: now.Add(time.Minute), worker: "settlement-client", token: [32]byte{1}}
			switch mutation {
			case "expired":
				claim.expires = now
			case "foreign_worker":
				claim.worker = "another-worker"
			case "step":
				claim.step = snapshotRun
			case "version":
				claim.version = 3
			case "no_source":
				snapshot.source = ""
			case "digest":
				proof.Digest = strings.Repeat("0", 64)
			case "schema":
				proof.SchemaVersion = "unknown"
			case "outcome":
				proof.Outcome = "unknown"
			case "empty_reason":
				proof.Reason = ""
			case "oversized":
				proof.Reason = strings.Repeat("x", 65536)
			}
			if mutation != "digest" {
				b, _ := json.Marshal(proof)
				d := sha256.Sum256(b)
				proof.Digest = hex.EncodeToString(d[:])
			}
			db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
				t.Fatal("invalid preparation touched DB")
				return nil, nil
			}}
			client, _ := newExistingTestClient(db, "settlement-client", func() time.Time { return now })
			if _, err := client.PrepareSettlement(claim, snapshot, proof); err == nil {
				t.Fatal("invalid settlement prepared")
			}
		})
	}
}

func TestExistingTestSettlementClientUnknownEffectAndPreservedHistory(t *testing.T) {
	_, _, r := fixtureExistingTestEvidence(t)
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	snapshot, _ := decodeExistingTestSnapshot(fixtureExistingTestSnapshot(t, r), r.Scope, snapshotRun, snapshotStep, r.RunID, 2, snapshotGeneration, now)
	claim := existingTestClaim{scope: r.Scope, run: snapshotRun, step: snapshotStep, testRun: r.RunID, version: 2, generation: snapshotGeneration, expires: now.Add(time.Minute), worker: "settlement-client", token: [32]byte{1}}
	for _, test := range []struct {
		reason, parent, step, effect string
		want                         bool
	}{
		{"test_outcome_unknown", "inconclusive", "inconclusive", "succeeded", false},
		{"test_outcome_unknown", "inconclusive", "inconclusive", "unknown_outcome", true},
		{"test_outcome_unknown", "cancelled", "cancelled", "known_failure", true},
		{"test_evidence_unavailable", "inconclusive", "inconclusive", "succeeded", true},
		{"test_evidence_unavailable", "failed", "failed", "known_failure", true},
	} {
		t.Run(test.reason+"/"+test.effect+"/"+test.parent, func(t *testing.T) {
			proof := existingTestVerification{SchemaVersion: "security-agent-test-verification-v1", Outcome: "inconclusive", Reason: test.reason}
			b, _ := json.Marshal(proof)
			d := sha256.Sum256(b)
			proof.Digest = hex.EncodeToString(d[:])
			db := &reconcileQueryFixture{call: func(context.Context, string, ...any) (json.RawMessage, error) {
				return json.Marshal(map[string]any{"run_id": snapshotRun, "step_id": snapshotStep, "state": test.parent, "step_state": test.step, "effect_state": test.effect, "outcome": proof.Outcome, "reason": proof.Reason, "proof_sha256": proof.Digest, "generation": snapshotGeneration, "reconcile_version": 3})
			}}
			client, _ := newExistingTestClient(db, "settlement-client", func() time.Time { return now })
			request, err := client.PrepareSettlement(claim, snapshot, proof)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Settle(context.Background(), request)
			if (err == nil) != test.want {
				t.Fatalf("receipt accepted=%t want=%t", err == nil, test.want)
			}
		})
	}
}
