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

// Catch accepting a valid MAC whose captured source, operation, request,
// session, purpose or effect state is wrong. Every attempt is rolled back.
func assertWorkerTest74EffectBindings(t *testing.T, ctx context.Context, pool *pgxpool.Pool, key *authorization.WorkerKey, revision authorization.Revision, request json.RawMessage, captured bool) {
	t.Helper()
	phase, purpose := "effect.reserve", "worker-forward"
	if captured {
		phase, purpose = "effect.read", "captured-compensation"
	}
	var facts json.RawMessage
	var principal string
	if err := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb),session_user`, phase, request).Scan(&facts, &principal); err != nil {
		t.Fatal("effect proof metadata", err)
	}
	for _, field := range []string{"unchanged control", "definition_digest", "source_digest", "target_digest", "request_digest", "child_run_id", "step", "effect", "input", "revision", "phase", "purpose", "principal", "expired", "key", "repeatable read", "serializable"} {
		if captured && field == "revision" {
			continue // Captured settlement deliberately does not require current projection.
		}
		var changed map[string]any
		if json.Unmarshal(facts, &changed) != nil {
			t.Fatal("effect metadata decode")
		}
		now := time.Now().UnixMilli()
		body := map[string]any{"purpose": purpose, "key_version": key.Version(), "operation": "test74." + phase, "request": nil, "facts": changed, "revision": revision, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
		code, isolation := "40001", pgx.ReadCommitted
		switch field {
		case "unchanged control":
			code = ""
		case "phase":
			body["operation"], code = "test74.linked.read", "42501"
		case "purpose":
			body["purpose"], code = "api-identity", "42501"
		case "principal":
			body["session_user"], code = "unregistered_effect_executor", "42501"
		case "expired":
			body["issued_at"], body["expires_at"], code = now-31000, now-1000, "42501"
		case "key":
			body["key_version"], code = strings.Repeat("0", 64), "42501"
		case "revision":
			body["revision"] = map[string]any{}
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
		err = tx.QueryRow(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, request).Scan(&result)
		var refusal *pgconn.PgError
		valid := errors.As(err, &refusal) && refusal.Code == code
		if code == "" {
			var receipt map[string]any
			state := "reserved"
			if captured {
				state = "started"
			}
			valid = err == nil && json.Unmarshal(result, &receipt) == nil && receipt["state"] == state
		}
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !valid {
			t.Fatal("native effect proof binding", captured, field, err)
		}
	}
	t.Log("actual74 unchanged manual envelope accepted then effect proof mutations/isolation refused", "captured", captured)
}

func assertWorkerTest74EffectCatalog(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	for _, statement := range []string{
		`CREATE OR REPLACE FUNCTION zasp_temporal74.effect(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.linked(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.test_state(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_effect(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_effect_source(phase text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.require_test74_effect(phase text,q jsonb) RETURNS void LANGUAGE plpgsql AS $$BEGIN RETURN;END$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_effect(jsonb) TO zasp_temporal_executor`,
		`REVOKE EXECUTE ON FUNCTION zasp_temporal74.effect(jsonb) FROM zasp_temporal_executor`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.invocation(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.adapter74_source(phase text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.require_adapter74(phase text,q jsonb) RETURNS void LANGUAGE plpgsql AS $$BEGIN RETURN;END$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.adapter_key_ready(p text,v text) RETURNS boolean LANGUAGE sql AS $$SELECT true$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.adapter_revision(o text) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_private_facts(boolean,jsonb,boolean,jsonb) TO zasp_red_team_adapter`,
		`REVOKE EXECUTE ON FUNCTION zasp_temporal74.invocation(jsonb) FROM zasp_red_team_adapter`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_complete(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_completion_source(phase text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_captured_parent(text,text,text,text,text,text) TO zasp_temporal_compensation`,
		`REVOKE EXECUTE ON FUNCTION zasp_authorization80_worker.test74_complete(jsonb) FROM zasp_temporal_compensation`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal("owned effect catalog mutation", err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready() AND NOT zasp_temporal74.current_ready() AND NOT zasp_temporal78.current_ready() AND NOT zasp_authorization80_temporal.ready()`).Scan(&refused)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil || !refused {
			t.Fatal("effect replacement or ACL accepted by predecessor chain", err)
		}
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal74.current_ready() AND zasp_temporal78.current_ready() AND zasp_authorization80_temporal.ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("legitimate effect predecessor chain after rollback", err)
	}
}
