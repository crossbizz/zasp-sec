package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Consume genuine WorkerExecutor decisions without changing their signatures
// or TTL. The organization lock is acquired only after both source reads and
// FGA Checks finish; no SQL transaction spans the authorization RPCs.
func discovery72ProofLockWait(t *testing.T, ctx context.Context, owner *pgx.Conn, product *temporalDiscoveryProduct, start orchestration.DiscoveryStart, deadline time.Time, forwardLogin, compensationLogin string) {
	t.Helper()
	for _, control := range []struct {
		phase, login string
		executor     *authorization.WorkerExecutor
	}{
		{"prepare_page", forwardLogin, product.authorization.forward},
		{"replay_page", compensationLogin, product.authorization.compensation},
	} {
		func() {
			request, _ := json.Marshal(map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "job_id": start.Ref.RunID, "integration_id": start.IntegrationID, "input_digest": start.InputDigest, "operation": control.phase, "budget_us": deadline.UnixMicro(), "expected": 0, "expected_digest": ""})
			decision, err := control.executor.Authorize(ctx, authorization.WorkerOperation("discovery72."+control.phase), request)
			if err != nil {
				t.Fatal("real lock-wait authorization", control.phase, err)
			}
			// Current production decisions have30s lifetime. Wait31s after receipt
			// so even the latest possible issued timestamp has expired.
			releaseAt := time.Now().Add(31 * time.Second)
			lock, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = lock.Exec(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, start.Ref.OrganizationID); err != nil {
				_ = lock.Rollback(ctx)
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			executeCtx, cancelExecute := context.WithCancel(ctx)
			joined := false
			defer func() {
				cancelExecute()
				cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelCleanup()
				if err := lock.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
					t.Error("lock-wait cleanup rollback", control.phase, err)
				}
				if !joined {
					joinDeadline := time.NewTimer(5 * time.Second)
					defer joinDeadline.Stop()
					select {
					case <-finished:
					case <-joinDeadline.C:
						t.Error("lock-wait Execute did not join after cancellation", control.phase)
					}
				}
			}()
			go func() { _, err := control.executor.Execute(executeCtx, decision); finished <- err }()
			waiting := false
			for limit := time.Now().Add(10 * time.Second); time.Now().Before(limit); {
				if err = lock.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2::integer=ANY(pg_blocking_pids(pid)))`, control.login, int32(owner.PgConn().PID())).Scan(&waiting); err != nil {
					break
				}
				if waiting {
					break
				}
				select {
				case <-time.After(20 * time.Millisecond):
				case <-ctx.Done():
					err = ctx.Err()
				}
				if err != nil {
					break
				}
			}
			if err != nil || !waiting {
				t.Fatal("real proof did not reach org wait before expiry", control.phase, err)
			}
			if remaining := time.Until(releaseAt); remaining > 0 {
				select {
				case <-time.After(remaining):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err = lock.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-finished:
				joined = true
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !errors.Is(err, authorization.ErrDenied) {
				t.Fatal("expired worker proof escaped lock wait", control.phase, err)
			}
			var unchanged bool
			if err = owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE job_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.apply_effects WHERE job_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE job_id=$1 AND state='admitted' AND checkpoint_version=0)`, start.Ref.RunID).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("expired worker decision changed native effects", control.phase, err)
			}
			if control.phase == "replay_page" {
				fresh, err := control.executor.Authorize(ctx, "discovery72.replay_page", request)
				if err != nil {
					t.Fatal("fresh captured replay authorization", err)
				}
				value, err := control.executor.Execute(ctx, fresh)
				var receipt struct {
					Found bool `json:"found"`
				}
				if err != nil || json.Unmarshal(value, &receipt) != nil || receipt.Found {
					t.Fatal("fresh captured replay was blanket-denied or invented a receipt", err)
				}
			}
			t.Log("real worker decision expired after observed org-lock wait; no effect:", control.phase)
		}()
	}
}
