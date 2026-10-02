package authorization

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func orderedSigningFixture(t *testing.T) (*WorkerExecutor, WorkerDecision, []byte, policy.GatewayPolicyKeys, ed25519.PrivateKey, time.Time) {
	t.Helper()
	k, err := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &WorkerExecutor{key: k}
	d := WorkerDecision{operation: "ordered68.application.source", request: json.RawMessage(`{"operation":"source","payload":{}}`), envelope: []byte(`{"native_validated":"opaque-original-proof"}`)}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	compiled, err := policy.Compile(policy.Policy{ID: "original-policy", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(d.envelope)
	raw, err := json.Marshal(map[string]any{
		"contract_version": 1, "operation": d.operation, "decision_digest": hex.EncodeToString(digest[:]), "key_id": "gateway-key-1",
		"organization_id": "pid_00000001-0000-4000-8000-000000000001", "workspace_id": "pid_00000001-0000-4000-8000-000000000002", "environment_id": "pid_00000001-0000-4000-8000-000000000003", "device_id": "pid_00000001-0000-4000-8000-000000000004",
		"sequence": 7, "policy_version": 3, "issued_at": now.Unix(), "expires_at": now.Add(time.Minute).Unix(), "failure_mode": "closed", "policies": []policy.CompiledPolicy{compiled},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, d, raw, keys, private, now
}

// The double is only the PostgreSQL transport. These tests consume the real
// signing/verification protocol; native authorization is a separate SQL gate.
type orderedSigningTxFixture struct {
	t        *testing.T
	decision WorkerDecision
	input    []byte
	fail     string
	events   []string
	stored   []byte
	response json.RawMessage
}

func (tx *orderedSigningTxFixture) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.events = append(tx.events, "bind")
	if sql != `SELECT set_config('zasp.worker_proof',$1,true)` || len(args) != 1 || args[0] != string(tx.decision.envelope) {
		tx.t.Fatal("not bound to exact original proof")
	}
	if tx.fail == "bind" {
		return pgconn.CommandTag{}, &pgconn.PgError{Code: "42501"}
	}
	return pgconn.CommandTag{}, nil
}

type orderedSigningRow func(...any) error

func (row orderedSigningRow) Scan(dest ...any) error { return row(dest...) }
func (tx *orderedSigningTxFixture) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	stage := "begin"
	if sql == `SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)` {
		stage = "store"
	} else if sql != `SELECT zasp_authorization80_worker.ordered68_policy_begin($1,$2::jsonb,$3)` {
		tx.t.Fatal("arbitrary signing statement")
	}
	tx.events = append(tx.events, stage)
	if len(args) < 3 || args[0] != string(tx.decision.operation) || !bytes.Equal(args[1].(json.RawMessage), tx.decision.request) || args[2] != "gateway-key-1" {
		tx.t.Fatal("original operation/request/key changed")
	}
	if stage == "store" {
		if len(args) != 6 || !bytes.Equal(args[3].([]byte), tx.input) || args[5] == "" {
			tx.t.Fatal("store lost exact begin input or verification MAC")
		}
		tx.stored = append([]byte(nil), args[4].(json.RawMessage)...)
	}
	return orderedSigningRow(func(dest ...any) error {
		if tx.fail == stage {
			return &pgconn.PgError{Code: "42501"}
		}
		if stage == "begin" {
			*dest[0].(*[]byte) = append([]byte(nil), tx.input...)
		} else {
			response := tx.response
			if response == nil {
				response = json.RawMessage(`{"stored":true}`)
			}
			*dest[0].(*json.RawMessage) = response
		}
		return nil
	})
}

// Native delivery returns its bounded composition, not just the <=1MiB
// signed envelope. Do not silently shrink its retained8MiB response contract.
func TestOrderedSigningRetainsNativeResponseBound(t *testing.T) {
	for _, size := range []int{1024*1024 + 1, 8 * 1024 * 1024, 8*1024*1024 + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			e, d, raw, keys, private, _ := orderedSigningFixture(t)
			response := append([]byte(`{"composition":"`), bytes.Repeat([]byte("x"), size-len(`{"composition":""}`))...)
			response = append(response, []byte(`"}`)...)
			tx := &orderedSigningTxFixture{t: t, decision: d, input: raw, response: response}
			out, err := e.signOrderedPolicyTransaction(context.Background(), tx, d, "gateway-key-1", keys, func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				return policy.SignGatewayPolicyEnvelope(input, private)
			})
			if size <= 8*1024*1024 {
				if err != nil || !bytes.Equal(out, response) {
					t.Fatalf("retained response of%d bytes refused: %v", size, err)
				}
			} else if err == nil || len(out) != 0 || strings.Contains(strings.Join(tx.events, ","), "commit") {
				t.Fatal("oversized native response committed")
			}
		})
	}
}
func (tx *orderedSigningTxFixture) Commit(context.Context) error {
	tx.events = append(tx.events, "commit")
	if tx.fail == "commit" {
		return errors.New("commit failed")
	}
	return nil
}
func (tx *orderedSigningTxFixture) Rollback(ctx context.Context) error {
	tx.events = append(tx.events, "rollback")
	if _, ok := ctx.Deadline(); !ok {
		tx.t.Fatal("rollback is unbounded")
	}
	return nil
}

func TestOrderedSigningFixedTransaction(t *testing.T) {
	for _, name := range []string{"valid", "bind", "begin", "malformed-input", "callback", "store", "commit"} {
		t.Run(name, func(t *testing.T) {
			e, d, raw, keys, private, _ := orderedSigningFixture(t)
			tx := &orderedSigningTxFixture{t: t, decision: d, input: raw, fail: name}
			if name == "malformed-input" {
				tx.input = []byte(`{"policies":null}`)
			}
			calls := 0
			out, err := e.signOrderedPolicyTransaction(context.Background(), tx, d, "gateway-key-1", keys, func(ctx context.Context, in policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				tx.events = append(tx.events, "sign")
				calls++
				if name == "callback" {
					return policy.GatewayPolicyEnvelope{}, errors.New("sign failed")
				}
				return policy.SignGatewayPolicyEnvelope(in, private)
			})
			want := map[string]string{"valid": "bind,begin,sign,store,commit,rollback", "bind": "bind,rollback", "begin": "bind,begin,rollback", "malformed-input": "bind,begin,rollback", "callback": "bind,begin,sign,rollback", "store": "bind,begin,sign,store,rollback", "commit": "bind,begin,sign,store,commit,rollback"}[name]
			if strings.Join(tx.events, ",") != want {
				t.Fatalf("transaction events %v, want %s", tx.events, want)
			}
			if name == "valid" {
				if err != nil || string(out) != `{"stored":true}` || calls != 1 || len(tx.stored) == 0 {
					t.Fatal("valid signed transaction failed", err)
				}
				return
			}
			if err == nil || len(out) != 0 {
				t.Fatal("failed transaction returned success")
			}
		})
	}
}

// Altering input, using an unconfigured key or cancellation must never enter
// the private-key callback. Native authority itself is tested by the SQL group.
func TestOrderedSigningInputBeforePrivateKeyAccess(t *testing.T) {
	for _, name := range []string{"valid", "unknown-key", "wrong-key-id", "wrong-operation", "wrong-decision", "extra", "duplicate", "missing", "null", "fractional-sequence", "zero-sequence", "foreign-binding", "expired", "long-ttl", "bad-policies", "oversized", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			e, d, raw, keys, private, now := orderedSigningFixture(t)
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			keyID := "gateway-key-1"
			switch name {
			case "unknown-key":
				keyID = "gateway-key-2"
				value["key_id"] = keyID
			case "wrong-key-id":
				value["key_id"] = "gateway-key-2"
			case "wrong-operation":
				value["operation"] = "ordered68.cleanup.source"
			case "wrong-decision":
				value["decision_digest"] = strings.Repeat("0", 64)
			case "extra":
				value["secret"] = "forbidden"
			case "missing":
				delete(value, "policies")
			case "null":
				value["policies"] = nil
			case "fractional-sequence":
				value["sequence"] = 1.5
			case "zero-sequence":
				value["sequence"] = 0
			case "foreign-binding":
				value["device_id"] = "foreign"
			case "expired":
				value["expires_at"] = now.Unix()
			case "long-ttl":
				value["expires_at"] = now.Add(25 * time.Hour).Unix()
			case "bad-policies":
				value["policies"] = []map[string]any{{"id": "bad", "rego": "allow := true"}}
			}
			raw, _ = json.Marshal(value)
			if name == "duplicate" {
				raw = append([]byte(`{"sequence":7,`), raw[1:]...)
			}
			if name == "oversized" {
				raw = bytes.Repeat([]byte(" "), 1024*1024+1)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancelled" {
				cancel()
			}
			calls := 0
			out, mac, err := e.signOrderedPolicyInput(ctx, d, raw, keyID, keys, func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				calls++
				return policy.SignGatewayPolicyEnvelope(input, private)
			}, now)
			if name != "valid" {
				if err == nil || calls != 0 || len(out) != 0 || mac != "" {
					t.Fatalf("unsafe input reached key: calls=%d accepted=%t", calls, err == nil)
				}
				return
			}
			if err != nil || calls != 1 || len(out) == 0 {
				t.Fatalf("valid fixed input refused: calls=%d err=%v", calls, err)
			}
			proofHash, inputHash, envelopeHash := sha256.Sum256(d.envelope), sha256.Sum256(raw), sha256.Sum256(out)
			wantMAC := hmac.New(sha256.New, e.key.key[:])
			_, _ = wantMAC.Write([]byte("zasp-authorization-ordered68-policy-store-v1\x00worker-forward\x00" + hex.EncodeToString(proofHash[:]) + "\x00" + hex.EncodeToString(inputHash[:]) + "\x00" + hex.EncodeToString(envelopeHash[:])))
			if mac != hex.EncodeToString(wantMAC.Sum(nil)) {
				t.Fatal("store MAC does not bind exact original decision/input/envelope bytes")
			}
		})
	}
}

// A valid signature for different input is still forbidden; so is a signer
// that mutates the input it receives or returns an untrusted signing identity.
func TestOrderedSigningIndependentlyVerifiesExactOutput(t *testing.T) {
	for _, name := range []string{"valid", "wrong-key", "signature", "sequence", "version", "expiry", "mode", "policies", "mutate-input", "callback-error", "cancelled-after-sign"} {
		t.Run(name, func(t *testing.T) {
			e, d, raw, keys, private, now := orderedSigningFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out, mac, err := e.signOrderedPolicyInput(ctx, d, raw, "gateway-key-1", keys, func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				switch name {
				case "wrong-key":
					private = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
				case "sequence":
					input.Sequence++
				case "version":
					input.PolicyVersion++
				case "expiry":
					input.ExpiresAt = input.ExpiresAt.Add(time.Second)
				case "mode":
					input.FailureMode = "open"
				case "policies", "mutate-input":
					compiled, compileErr := policy.Compile(policy.Policy{ID: "new-policy", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}})
					if compileErr != nil {
						t.Fatal(compileErr)
					}
					if name == "mutate-input" {
						input.Policies[0] = compiled
					} else {
						input.Policies = append(input.Policies, compiled)
					}
				case "callback-error":
					return policy.GatewayPolicyEnvelope{}, errors.New("local signer failed")
				}
				envelope, err := policy.SignGatewayPolicyEnvelope(input, private)
				if name == "signature" {
					envelope.Signature = strings.Repeat("A", 86)
				}
				if name == "cancelled-after-sign" {
					cancel()
				}
				return envelope, err
			}, now)
			if name == "valid" {
				if err != nil || len(out) == 0 || mac == "" {
					t.Fatal("valid signature refused", err)
				}
				return
			}
			if err == nil || len(out) != 0 || mac != "" {
				t.Fatal("untrusted or changed signer output accepted")
			}
		})
	}
}

func TestOrderedSigningPurposeAndOrdinaryExecuteRefusal(t *testing.T) {
	for _, operation := range []WorkerOperation{"ordered68.application.source", "ordered68.delivery.apply.store", "ordered68.cleanup.source", "ordered68.cleanup.renew", "ordered68.delivery.cleanup.store", "ordered68.sql", "ordered68.effect.reserve"} {
		t.Run(string(operation), func(t *testing.T) {
			e, d, raw, keys, private, now := orderedSigningFixture(t)
			d.operation = operation
			var wire map[string]any
			_ = json.Unmarshal(raw, &wire)
			wire["operation"] = operation
			raw, _ = json.Marshal(wire)
			compensation := operation == "ordered68.cleanup.source" || operation == "ordered68.cleanup.renew" || operation == "ordered68.delivery.cleanup.store"
			supported := compensation || operation == "ordered68.application.source" || operation == "ordered68.delivery.apply.store"
			if compensation {
				e.key, _ = NewWorkerKey(CapturedCompensation, bytes.Repeat([]byte{7}, 32))
			}
			calls := 0
			sign := func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
				calls++
				return policy.SignGatewayPolicyEnvelope(input, private)
			}
			out, _, err := e.signOrderedPolicyInput(context.Background(), d, raw, "gateway-key-1", keys, sign, now)
			if (err == nil) != supported || calls != map[bool]int{false: 0, true: 1}[supported] {
				t.Fatal("wrong purpose/literal selection")
			}
			if supported {
				if len(out) == 0 {
					t.Fatal("missing verified output")
				}
				other := CapturedCompensation
				if compensation {
					other = WorkerForward
				}
				e.key, _ = NewWorkerKey(other, bytes.Repeat([]byte{7}, 32))
				calls = 0
				if _, _, err := e.signOrderedPolicyInput(context.Background(), d, raw, "gateway-key-1", keys, sign, now); err == nil || calls != 0 {
					t.Fatal("swapped purpose reached signer")
				}
				// An uninitialized pool would panic if Execute reached BeginTx.
				e.pool = &pgxpool.Pool{}
				if _, err := e.Execute(context.Background(), d); err != ErrInvalid {
					t.Fatal("ordinary Execute accepted signing literal")
				}
			}
		})
	}
}
