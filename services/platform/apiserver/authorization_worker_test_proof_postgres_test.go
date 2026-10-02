package apiserver

import (
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

func assertWorkerTest74SourceBindings(t *testing.T, ctx context.Context, owner *pgx.Conn, pool *pgxpool.Pool, key *authorization.WorkerKey, revision authorization.Revision, request json.RawMessage, captured bool) {
	t.Helper()
	phase, purpose, statement := "load", "worker-forward", `SELECT zasp_temporal74.plan($1::jsonb)`
	if captured {
		phase, purpose, statement = "recovery", "captured-compensation", `SELECT zasp_authorization80_worker.planning74_recovery($1::jsonb)`
	}
	var facts json.RawMessage
	var principal, historical string
	if err := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning74_source($1,$2::jsonb),session_user`, phase, request).Scan(&facts, &principal); err != nil {
		t.Fatal("actual74 digest-bound metadata", err)
	}
	if err := owner.QueryRow(ctx, `SELECT encode(h.definition_digest,'hex') FROM zasp_security_agent_definition_versions h JOIN zasp_temporal74.run_owners x ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) WHERE x.run_id=($1::jsonb->>'run_id')`, request).Scan(&historical); err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if json.Unmarshal(facts, &metadata) != nil || len(historical) != 64 || metadata["definition_digest"] != historical {
		t.Fatal("worker74 source omitted exact immutable definition digest")
	}
	for _, field := range []string{"definition_digest", "source_digest", "target_digest", "target_id", "wrong phase", "wrong principal", "repeatable read", "serializable"} {
		var changed map[string]any
		if json.Unmarshal(facts, &changed) != nil {
			t.Fatal("actual74 metadata decode")
		}
		now := time.Now().UnixMilli()
		body := map[string]any{"purpose": purpose, "key_version": key.Version(), "operation": "test74.planning." + phase, "request": nil, "facts": changed, "revision": revision, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
		code, isolation := "40001", pgx.ReadCommitted
		switch field {
		case "wrong phase":
			body["operation"], code = "test74.planning.state", "42501"
		case "wrong principal":
			body["session_user"], code = "unregistered_test_executor", "42501"
		case "repeatable read":
			isolation, code = pgx.RepeatableRead, "25001"
		case "serializable":
			isolation, code = pgx.Serializable, "25001"
		default:
			changed[field] = strings.Repeat("0", 64)
		}
		raw, _ := json.Marshal(body)
		mac := hmac.New(sha256.New, key.Verifier())
		_, _ = mac.Write([]byte("zasp-authorization-" + purpose + "-v1\x00"))
		_, _ = mac.Write(raw)
		envelope, _ := json.Marshal(map[string]any{"body": raw, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, statement, request).Scan(&result)
		var refusal *pgconn.PgError
		valid := errors.As(err, &refusal) && refusal.Code == code
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !valid {
			t.Fatal("native74 source/phase/isolation proof binding", captured, field, err)
		}
	}
	t.Log("native74 definition/source/target digests, phase, principal and unsupported isolation refuse", "captured", captured)
}
