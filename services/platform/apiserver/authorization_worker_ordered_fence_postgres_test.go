package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7WorkerOrdered68PlanningFences(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "fences")
}

// Actual captured compensation metadata is signed with its registered fixture
// key. All native effect work is rollback-only; no synthetic audit/allow rows.
func assertOrdered68PlanningFences(t *testing.T, ctx context.Context, owner *pgx.Conn, start json.RawMessage) {
	t.Helper()
	var q map[string]any
	if json.Unmarshal(start, &q) != nil {
		t.Fatal("start identity")
	}
	delete(q, "input_digest")
	q["operation"], q["payload"] = "reconcile", map[string]any{}
	request, _ := json.Marshal(q)
	cfg := owner.Config().Copy()
	cfg.User = "temporal_compensation_test_login"
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(context.Background())
	blocker, err := pgx.ConnectConfig(ctx, owner.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	for _, control := range []string{"expiry-after-wait", "organization-before-parent"} {
		var facts json.RawMessage
		if err := comp.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning68_source('reconcile',$1::jsonb)`, request).Scan(&facts); err != nil {
			t.Fatal("actual captured facts", err)
		}
		now := time.Now().UnixMilli()
		expires := now + 4000
		if control == "organization-before-parent" {
			expires = now + 30000
		}
		body, _ := json.Marshal(map[string]any{"purpose": "captured-compensation", "key_version": key.Version(), "operation": "ordered68.planning.reconcile", "request": nil, "facts": facts, "revision": authorization.Revision{}, "session_user": cfg.User, "issued_at": now, "expires_at": expires})
		mac := hmac.New(sha256.New, key.Verifier())
		_, _ = mac.Write([]byte("zasp-authorization-captured-compensation-v1\x00"))
		_, _ = mac.Write(body)
		envelope, _ := json.Marshal(map[string]any{"body": body, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
		lock, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lock.Exec(ctx, `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`, q["organization_id"]); err != nil {
			_ = lock.Rollback(ctx)
			t.Fatal(err)
		}
		tx, err := comp.Begin(ctx)
		if err != nil {
			_ = lock.Rollback(ctx)
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
			_ = tx.Rollback(ctx)
			_ = lock.Rollback(ctx)
			t.Fatal(err)
		}
		joined := make(chan error, 1)
		go func() {
			var result json.RawMessage
			err := tx.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, request).Scan(&result)
			joined <- err
		}()
		// Observe only this owned application's wait, to avoid timing guesses.
		// The assertion below concerns its row order and proof lifetime, not a
		// PostgreSQL implementation or retry guarantee.
		waitCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		waiting := false
		for waitCtx.Err() == nil {
			var blocked bool
			if err := owner.QueryRow(waitCtx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, comp.PgConn().PID()).Scan(&blocked); err != nil {
				break
			}
			if blocked {
				waiting = true
				break
			}
			select {
			case <-waitCtx.Done():
			case <-time.After(10 * time.Millisecond):
			}
		}
		cancel()
		if !waiting {
			_ = lock.Rollback(ctx)
			callErr := <-joined
			_ = tx.Rollback(ctx)
			t.Fatal("native compensation did not reach controlled lock wait", callErr)
		}
		if control == "expiry-after-wait" {
			delay := time.Until(time.UnixMilli(expires + 50))
			if delay > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(delay):
				}
			}
		} else {
			probe, err := owner.Begin(ctx)
			if err != nil {
				_ = lock.Rollback(ctx)
				<-joined
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, probeErr := probe.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE NOWAIT`, q["run_id"])
			if err := probe.Rollback(ctx); err != nil {
				t.Error("parent probe rollback", err)
			}
			if probeErr != nil {
				var native *pgconn.PgError
				if errors.As(probeErr, &native) && native.Code == "55P03" {
					t.Error("captured compensation holds parent while waiting for organization")
				} else {
					t.Error("unexpected parent lock probe failure", probeErr)
				}
			}
		}
		if err := lock.Rollback(ctx); err != nil {
			_ = blocker.Close(context.Background())
			<-joined
			_ = tx.Rollback(ctx)
			t.Fatal("release controlled organization lock", err)
		}
		callErr := <-joined
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal("rollback native compensation", err)
		}
		if control == "expiry-after-wait" {
			var native *pgconn.PgError
			if !errors.As(callErr, &native) || native.Code != "42501" {
				t.Errorf("expired proof crossed controlled native wait: %v", callErr)
			}
		} else if callErr != nil {
			t.Error("unchanged captured compensation after lock release", callErr)
		}
		var unchanged bool
		if err := owner.QueryRow(ctx, `SELECT state='loaded' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal') FROM zasp_temporal68.planning_jobs WHERE run_id=$1`, q["run_id"]).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("rollback-only fence control changed native intent", err)
		}
		t.Logf("ordered native fence control=%s joined", control)
	}
}
