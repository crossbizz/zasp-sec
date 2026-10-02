package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// ReconcileOne processes at most one tenant-scoped link. It has no target
// execution authority. A 30s operation budget fits inside the renewed 60s lease;
// the caller's polling loop supplies fairness and backoff between invocations.
func (c *existingTestClient) ReconcileOne(ctx context.Context, scope domain.Scope, store existingTestArtifactReader) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(store) {
		return errRuntimeUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	claims, err := c.Claim(work, scope, 60, 1)
	if err != nil {
		return errRuntimeUnavailable
	}
	if len(claims) == 0 {
		return nil
	}
	claim, err := c.Heartbeat(work, claims[0], 60)
	if err != nil {
		return errRuntimeUnavailable
	}
	if err := c.CancelStopped(work, claim); err != nil {
		return errRuntimeUnavailable
	}
	snapshot, err := c.Evidence(work, claim)
	if err != nil {
		return errRuntimeUnavailable
	}
	release := func() error { _, err := c.Release(work, claim, 30); return err }
	if snapshot.State == "queued" || snapshot.State == "retryable" {
		return release()
	}
	proof := existingTestVerification{SchemaVersion: "security-agent-test-verification-v1"}
	switch {
	case snapshot.OutcomeUnknown || snapshot.State == "leased":
		// SQL alone decides whether a leased execution has expired and has a
		// journal. Live or journal-free execution cannot settle via this proof.
		proof.Outcome, proof.Reason = "inconclusive", "test_outcome_unknown"
	case snapshot.State == "failed":
		proof.Outcome, proof.Reason = "failed", "test_run_failed"
	case snapshot.State == "cancelled":
		proof.Outcome, proof.Reason = "cancelled", "test_run_cancelled"
	case snapshot.State == "complete" && snapshot.After != nil:
		proof = verifyExistingTestComparison(work, store, snapshot.Before, *snapshot.After)
	default:
		return errRuntimeUnavailable
	}
	if work.Err() != nil {
		return errRuntimeUnavailable
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return errRuntimeUnavailable
	}
	digest := sha256.Sum256(body)
	proof.Digest = hex.EncodeToString(digest[:])
	request, err := c.PrepareSettlement(claim, snapshot, proof)
	if err != nil {
		return errRuntimeUnavailable
	}
	if _, err = c.Settle(work, request); err == nil {
		return nil
	}
	// One bounded retry keeps exact bytes/ownership after a potentially lost
	// acknowledgement. Never execute another test or recompute its evidence.
	if work.Err() != nil {
		return errRuntimeUnavailable
	}
	if _, err = c.Settle(work, request); err == nil {
		return nil
	}
	if snapshot.State == "leased" && work.Err() == nil {
		return release()
	}
	return errRuntimeUnavailable
}
