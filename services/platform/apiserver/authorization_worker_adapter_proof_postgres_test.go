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
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// An unchanged manually signed control must reach the actual native consumer
// before any mutated envelope earns a refusal result. Every attempt rolls back.
func assertWorkerAdapterProofBindings(t *testing.T, ctx context.Context, conn *pgx.Conn, request json.RawMessage, revision authorization.Revision, captured bool, completedReceipt ...bool) {
	t.Helper()
	phase, purpose, seed := "resolve", authorization.WorkerForward, byte(41)
	source, statement := `SELECT zasp_authorization80_worker.adapter74_source($1,$2::jsonb),session_user`, `SELECT zasp_temporal74.invocation($1::jsonb)`
	if captured {
		phase, purpose, seed = "complete", authorization.CapturedCompensation, 73
		source = `SELECT zasp_authorization80_worker.test74_completion_source($1,$2::jsonb),session_user`
		statement = `SELECT zasp_authorization80_worker.test74_complete($1::jsonb)`
	}
	receiptOnly := len(completedReceipt) == 1 && completedReceipt[0]
	if receiptOnly {
		if !captured {
			t.Fatal("receipt proof must use compensation")
		}
		phase = "receipt"
		source = `SELECT zasp_authorization80_worker.test74_receipt_source($1,$2::jsonb),session_user`
		statement = `SELECT zasp_authorization80_worker.test74_receipt($1::jsonb)`
	}
	key, _ := authorization.NewWorkerKey(purpose, bytes.Repeat([]byte{seed}, 32))
	var facts json.RawMessage
	var principal string
	if err := conn.QueryRow(ctx, source, phase, request).Scan(&facts, &principal); err != nil {
		t.Fatal("adapter proof source", captured, err)
	}
	fields := []string{"unchanged control", "definition_digest", "source_digest", "target_digest", "request_digest", "child_run_id", "step_id", "effect_key", "generation", "snapshot_digest", "input_digest", "manifest_digest", "body_digest", "revision", "phase", "purpose", "principal", "expired", "key", "repeatable read", "serializable"}
	if captured {
		fields = append(fields, "journal_digest")
	}
	for _, field := range fields {
		if captured && field == "revision" {
			continue
		}
		var changed map[string]any
		if json.Unmarshal(facts, &changed) != nil {
			t.Fatal("adapter source encoding")
		}
		now := time.Now().UnixMilli()
		body := map[string]any{"purpose": purpose, "key_version": key.Version(), "operation": "test74.adapter." + phase, "request": nil, "facts": changed, "revision": revision, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
		code, isolation := "40001", pgx.ReadCommitted
		switch field {
		case "unchanged control":
			code = ""
		case "phase":
			body["operation"], code = "test74.adapter.unsupported", "42501"
		case "purpose":
			body["purpose"], code = "api-identity", "42501"
		case "principal":
			body["session_user"], code = "unregistered_adapter", "42501"
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
		_, _ = mac.Write([]byte("zasp-authorization-" + string(purpose) + "-v1\x00"))
		_, _ = mac.Write(raw)
		envelope, _ := json.Marshal(map[string]any{"body": raw, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, statement, request).Scan(&result)
		var native *pgconn.PgError
		valid := errors.As(err, &native) && native.Code == code
		if code == "" {
			var receipt map[string]any
			valid = err == nil && json.Unmarshal(result, &receipt) == nil
			if captured {
				count := 16
				if receiptOnly {
					count = 19
				}
				valid = valid && len(receipt) == count && receipt["state"] == "completed"
			} else {
				valid = valid && len(receipt) == 5 && receipt["target_id"] != nil
			}
		}
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !valid {
			t.Fatal("adapter proof binding", captured, field, err)
		}
	}
	t.Log("actual adapter unchanged proof control and mutated bindings/isolation", "captured", captured)
}
