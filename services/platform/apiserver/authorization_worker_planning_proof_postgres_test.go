package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type workerPlanningTransactionSource interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// These independently authenticated fixture proofs exercise the installed SQL
// consumer, not only the Go operation classifier. Every attempt rolls back.
func assertWorkerPlanningProofBindings(t *testing.T, ctx context.Context, f findingResponseFixture, forward *authorization.WorkerExecutor, compensationPool *pgxpool.Pool, key, compensationKey *authorization.WorkerKey, request, otherRequest json.RawMessage) {
	t.Helper()
	var identity map[string]any
	if err := json.Unmarshal(request, &identity); err != nil {
		t.Fatal(err)
	}
	run := identity["run_id"].(string)
	for _, role := range []struct {
		name string
		db   workerPlanningTransactionSource
	}{{"executor", f.executor}, {"compensation", compensationPool}} {
		for _, statement := range []string{`SELECT zasp_temporal78.context($1,$2,$3,$4)`, `SELECT zasp_temporal78.run_context($1,$2,$3,$4)`} {
			tx, err := role.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, statement, f.o, f.w, f.e, run).Scan(&result)
			var refusal *pgconn.PgError
			if !errors.As(err, &refusal) || refusal.Code != "42501" {
				t.Errorf("%s alternate context read did not refuse with 42501: %v", role.name, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	var facts json.RawMessage
	var principal string
	if err := f.executor.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning78_source('load',$1::jsonb),session_user`, request).Scan(&facts, &principal); err != nil {
		t.Fatal(err)
	}
	revision, err := forward.Revision(ctx, f.o)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, code string }{
		{"wrong purpose", "42501"}, {"wrong phase", "42501"}, {"wrong principal", "42501"}, {"expired", "42501"}, {"non-null request", "42501"},
		{"wrong canonical digest", "40001"}, {"wrong job digest", "40001"}, {"other task", "40001"}, {"changed target", "40001"}, {"changed revision", "40001"},
		{"repeatable read", "25001"}, {"serializable", "25001"}, {"state repeatable read", "25001"}, {"recovery serializable", "25001"}, {"compensation forward call", "42501"},
		{"canonical formatting", ""},
	} {
		t.Run("planning proof "+test.name, func(t *testing.T) {
			now := time.Now().UnixMilli()
			purpose := "worker-forward"
			signing := key
			body := map[string]any{"purpose": purpose, "key_version": key.Version(), "operation": "finding.planning.load", "request": nil, "facts": facts, "revision": revision, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
			query := `SELECT zasp_temporal78.plan($1::jsonb)`
			actual := request
			isolation := pgx.ReadCommitted
			var db workerPlanningTransactionSource = f.executor
			switch test.name {
			case "wrong purpose":
				purpose, signing = "captured-compensation", compensationKey
				body["purpose"], body["key_version"] = purpose, signing.Version()
			case "wrong phase":
				body["operation"] = "finding.planning.state"
			case "wrong principal":
				body["session_user"] = "finding78_compensation"
			case "expired":
				body["issued_at"], body["expires_at"] = now-30000, now-1
			case "non-null request":
				body["request"] = request
			case "wrong canonical digest", "wrong job digest", "changed target":
				var changed map[string]any
				if err := json.Unmarshal(facts, &changed); err != nil {
					t.Fatal(err)
				}
				field := map[string]string{"wrong canonical digest": "request_digest", "wrong job digest": "job_digest", "changed target": "finding_id"}[test.name]
				changed[field] = strings.Repeat("0", 64)
				body["facts"] = changed
			case "other task":
				actual = otherRequest
			case "changed revision":
				changed := revision
				changed.Generation++
				body["revision"] = changed
			case "repeatable read":
				isolation = pgx.RepeatableRead
			case "serializable":
				isolation = pgx.Serializable
			case "state repeatable read":
				isolation, query = pgx.RepeatableRead, `SELECT zasp_temporal78.planning_state($1::jsonb)`
			case "recovery serializable":
				db, isolation, query = compensationPool, pgx.Serializable, `SELECT zasp_authorization80_worker.planning78_recovery($1::jsonb)`
			case "compensation forward call":
				db = compensationPool
			case "canonical formatting":
				var formatted bytes.Buffer
				if err := json.Indent(&formatted, request, "", "  "); err != nil {
					t.Fatal(err)
				}
				actual = formatted.Bytes()
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, signing.Verifier())
			_, _ = mac.Write([]byte("zasp-authorization-" + purpose + "-v1\x00"))
			_, _ = mac.Write(raw)
			envelope, _ := json.Marshal(map[string]any{"body": raw, "version": signing.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
			tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, query, actual).Scan(&result)
			var refusal *pgconn.PgError
			if test.code == "" {
				var job struct {
					State string `json:"state"`
				}
				if err != nil || json.Unmarshal(result, &job) != nil || job.State != "loaded" {
					t.Errorf("canonical JSON did not preserve native digest binding: %v", err)
				}
			} else if !errors.As(err, &refusal) || refusal.Code != test.code {
				t.Errorf("want native refusal %s, got %v", test.code, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	var unchanged bool
	if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='queued' AND version=1)`, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("planner proof attempts changed intent or debt", err)
	}
}
