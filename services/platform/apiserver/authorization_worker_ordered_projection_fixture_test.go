package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Existing native policy fixtures used capture followed by synchronous
// projection. Preparation now waits, so the test's actual registered projector
// must run concurrently, exactly as in the product process. This helper neither
// fabricates projection receipts nor changes the original operation context.
func orderedPolicyFixtureCapture(t *testing.T, ctx context.Context, owner *pgx.Conn, organization string, worker *authorization.WorkerExecutor, operation authorization.WorkerOperation, request json.RawMessage, reconcile orderedPolicyProjectionAttempt) (result error) {
	t.Helper()
	if operation == "ordered68.effect.reserve" {
		return worker.PrepareOrdered68Operation(ctx, operation, request)
	}
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.PrepareOrdered68Operation(bounded, operation, request) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("policy capture worker did not join after cancellation")
				// Preserve ownership through terminal drain, even on a cleanup
				// failure. The outer native observer remains the hard stop.
				<-done
			}
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case result = <-done:
			joined = true
			return result
		case <-bounded.Done():
			return bounded.Err()
		case <-ticker.C:
			var pending bool
			if err := owner.QueryRow(bounded, `SELECT desired<>applied FROM zasp_authorization79.organizations WHERE organization_id=$1`, organization).Scan(&pending); err != nil {
				return err
			}
			if pending {
				if err := orderedPolicyProjectUntilApplied(bounded, reconcile); err != nil {
					return err
				}
			}
		}
	}
}
