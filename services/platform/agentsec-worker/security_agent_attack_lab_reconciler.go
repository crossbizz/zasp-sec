package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func (c *attackLabLinkClient) ReconcileOne(ctx context.Context, scope domain.Scope, store existingTestArtifactReader) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(store) {
		return errRuntimeUnavailable
	}
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	claims, err := c.Claim(work, scope)
	if err != nil {
		return err
	}
	if len(claims) == 0 {
		return nil
	}
	claim, err := c.Heartbeat(work, claims[0])
	if err != nil {
		return err
	}
	if err = c.CancelStopped(work, claim); err != nil {
		return err
	}
	snapshot, err := c.Evidence(work, claim)
	if err != nil {
		return err
	}
	proof, pending := verifyAttackLabLink(work, store, snapshot)
	if pending {
		return c.Release(work, claim)
	}
	if work.Err() != nil {
		return errRuntimeUnavailable
	}
	request, err := c.PrepareSettlement(claim, snapshot, proof)
	if err != nil {
		return err
	}
	if c.Settle(work, request) == nil {
		return nil
	}
	// Retry the identical immutable request once. No reread or recomputation can
	// change the receipt after the database committed but its reply was lost.
	if work.Err() != nil {
		return errRuntimeUnavailable
	}
	return c.Settle(work, request)
}
