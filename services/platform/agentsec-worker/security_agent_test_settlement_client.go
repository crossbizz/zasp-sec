package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Keep an immutable request across lost acknowledgements. Only the database
// can distinguish an expired first submission from an exact settled replay.
type existingTestSettlementRequest struct {
	claim                                    existingTestClaim
	snapshot, proof, digest, outcome, reason string
}

type existingTestSettlementReceipt struct {
	Generation  string `json:"generation"`
	Run         string `json:"run_id"`
	Step        string `json:"step_id"`
	State       string `json:"state"`
	StepState   string `json:"step_state"`
	EffectState string `json:"effect_state"`
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason"`
	Digest      string `json:"proof_sha256"`
	Version     int64  `json:"reconcile_version"`
}

func (c *existingTestClient) PrepareSettlement(claim existingTestClaim, snapshot existingTestSnapshot, proof existingTestVerification) (existingTestSettlementRequest, error) {
	fail := func() (existingTestSettlementRequest, error) {
		return existingTestSettlementRequest{}, errRuntimeUnavailable
	}
	if !c.valid(claim) {
		return fail()
	}
	// Revalidate the saved envelope, not mutable decoded request fields.
	if _, err := decodeExistingTestSnapshot([]byte(snapshot.source), claim.scope, claim.run, claim.step, claim.testRun, claim.version, claim.generation, c.now()); err != nil {
		return fail()
	}
	var envelope struct {
		Snapshot json.RawMessage `json:"snapshot"`
	}
	if json.Unmarshal([]byte(snapshot.source), &envelope) != nil {
		return fail()
	}
	body, err := json.Marshal(proof)
	if err != nil || len(body) > 65536 || proof.SchemaVersion != "security-agent-test-verification-v1" || !stringInWorker(proof.Outcome, "remediated", "needs_human", "inconclusive", "failed", "cancelled") || proof.Reason == "" {
		return fail()
	}
	digest := sha256.Sum256(body)
	encoded := hex.EncodeToString(digest[:])
	if proof.Digest != encoded {
		return fail()
	}
	return existingTestSettlementRequest{claim: claim, snapshot: string(envelope.Snapshot), proof: string(body), digest: encoded, outcome: proof.Outcome, reason: proof.Reason}, nil
}

func (c *existingTestClient) Settle(ctx context.Context, request existingTestSettlementRequest) (existingTestSettlementReceipt, error) {
	fail := func() (existingTestSettlementReceipt, error) {
		return existingTestSettlementReceipt{}, errRuntimeUnavailable
	}
	if c == nil || request.claim.worker != c.worker || request.snapshot == "" || request.proof == "" || request.digest == "" {
		return fail()
	}
	args := append(request.claim.args(), request.snapshot, []byte(request.proof))
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)", args...)
	var receipt existingTestSettlementReceipt
	if err != nil || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &receipt) != nil || receipt.Generation != request.claim.generation || receipt.Run != request.claim.run || receipt.Step != request.claim.step || receipt.Version != min(request.claim.version+1, 1000000) || receipt.Digest != request.digest || receipt.Outcome != request.outcome || receipt.Reason != request.reason {
		return fail()
	}
	if !stringInWorker(receipt.State, "remediated", "needs_human", "inconclusive", "failed", "cancelled") || !stringInWorker(receipt.StepState, "succeeded", "inconclusive", "failed", "cancelled") || !stringInWorker(receipt.EffectState, "verified", "succeeded", "unknown_outcome", "known_failure") {
		return fail()
	}
	// Stopped parents and terminal steps/effects can be preserved, but cannot
	// turn a non-remediation proof into remediation or a verified effect.
	if receipt.State == "remediated" && receipt.Outcome != "remediated" ||
		receipt.StepState == "succeeded" && (!stringInWorker(receipt.Outcome, "remediated", "needs_human") || receipt.State != receipt.Outcome) ||
		receipt.EffectState == "verified" && (receipt.Outcome != "remediated" || receipt.State != "remediated") ||
		receipt.EffectState == "succeeded" && (stringInWorker(receipt.Outcome, "failed", "cancelled") || receipt.State == "remediated") {
		return fail()
	}
	if receipt.Reason == "test_outcome_unknown" && !stringInWorker(receipt.EffectState, "unknown_outcome", "known_failure") {
		return fail()
	}
	return receipt, nil
}
