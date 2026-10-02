package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Dropping exact begin/store input or MAC binding, accepting a wrong signer,
// or checking proof time/authority only before begin must fail this group.
func TestP7Ordered68SigningAdversarial(t *testing.T) {
	runOrdered68PolicyAcceptance(t, false, false, false, &ordered68PolicyAcceptance{consume: func(f ordered68PolicyAcceptanceContext) {
		w := f.newWorker(f.checker)
		f.start(w)
		q := f.request("source", map[string]any{"device_id": orderedApplicationDevice})
		f.capture(w, "ordered68.application.source", q)
		for _, name := range []string{"unchanged", "input-device", "key-id", "signature-bytes", "mac", "expired-after-begin", "revoked-after-begin"} {
			t.Run(name, func(t *testing.T) {
				f.t = t
				before := f.evidence()
				proof := ordered68ActualSigningProof(f, w, q)
				defer clear(proof)
				if name == "expired-after-begin" {
					// Accepted begin measurements were 674–795ms. Leave setup
					// margin while retaining the original ten-second call budget.
					proof = ordered68ShortProof(t, proof, w.key.Verifier(), 5*time.Second)
					defer clear(proof)
				}
				func() {
					c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
					defer cancel()
					tx, err := f.owner.BeginTx(c, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
					if err != nil {
						t.Fatal("begin transaction", ordered68ErrorClass(err))
					}
					defer ordered68Rollback(t, c, tx)
					if _, err = tx.Exec(c, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{f.login}.Sanitize()); err != nil {
						t.Fatal("set registered session", ordered68ErrorClass(err))
					}
					if _, err = tx.Exec(c, `SELECT set_config('zasp.worker_proof',$1,true)`, string(proof)); err != nil {
						t.Fatal("set actual proof", ordered68ErrorClass(err))
					}
					var input []byte
					if err = tx.QueryRow(c, `SELECT zasp_authorization80_worker.ordered68_policy_begin($1,$2::jsonb,$3)`, "ordered68.application.source", q, "ordered-key-01").Scan(&input); err != nil {
						t.Fatal("actual native signing begin", ordered68ErrorClass(err))
					}
					envelope := ordered68EnvelopeFromNative(t, input, f.private)
					keyID := "ordered-key-01"
					mac := ordered68StoreMAC(proof, input, envelope, w.key.Verifier())
					switch name {
					case "input-device":
						var v map[string]any
						if json.Unmarshal(input, &v) != nil {
							t.Fatal("native input shape")
						}
						v["device_id"] = "pid_8fff0000-0000-4000-8000-000000000099"
						input, _ = json.Marshal(v)
						mac = ordered68StoreMAC(proof, input, envelope, w.key.Verifier())
					case "key-id":
						keyID = "ordered-key-02"
					case "signature-bytes":
						var v map[string]any
						if json.Unmarshal(envelope, &v) != nil {
							t.Fatal("native envelope shape")
						}
						s := v["signature"].(string)
						b := "A"
						if s[:1] == b {
							b = "B"
						}
						v["signature"] = b + s[1:]
						envelope, _ = json.Marshal(v)
						// Preserve the original verification MAC: native SQL must
						// reject changed bytes, not pretend to verify Ed25519 itself.
					case "mac":
						if mac[0] == 'a' {
							mac = "b" + mac[1:]
						} else {
							mac = "a" + mac[1:]
						}
					case "expired-after-begin":
						var wire struct{ Body []byte }
						if json.Unmarshal(proof, &wire) != nil {
							t.Fatal("captured proof")
						}
						var body struct {
							Expires int64 `json:"expires_at"`
						}
						if json.Unmarshal(wire.Body, &body) != nil {
							t.Fatal("captured body")
						}
						remaining := time.Until(time.UnixMilli(body.Expires))
						if remaining <= 0 {
							t.Fatal("proof was not current after successful begin")
						}
						timer := time.NewTimer(remaining + 20*time.Millisecond)
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-c.Done():
							t.Fatal("expiry witness deadline")
						}
						if time.Now().UnixMilli() <= body.Expires {
							t.Fatal("proof not expired at store witness")
						}
					case "revoked-after-begin":
						if _, err = tx.Exec(c, `RESET SESSION AUTHORIZATION`); err != nil {
							t.Fatal("reset fixture session", ordered68ErrorClass(err))
						}
						tag, err := tx.Exec(c, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor)
						if err != nil || tag.RowsAffected() != 1 {
							t.Fatal("exact requester mutation", ordered68ErrorClass(err))
						}
						if _, err = tx.Exec(c, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{f.login}.Sanitize()); err != nil {
							t.Fatal("restore registered session", ordered68ErrorClass(err))
						}
					}
					var result json.RawMessage
					err = tx.QueryRow(c, `SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)`, "ordered68.application.source", q, keyID, input, envelope, mac).Scan(&result)
					if name == "unchanged" {
						if err != nil || !json.Valid(result) {
							t.Fatal("valid native store rollback control", ordered68ErrorClass(err))
						}
						return
					}
					want := "42501"
					if name == "input-device" || name == "key-id" || name == "revoked-after-begin" {
						want = "40001"
					}
					var native *pgconn.PgError
					if !errors.As(err, &native) || native.Code != want {
						t.Fatal("native signing refusal", name, "want", want, "got", ordered68ErrorClass(err))
					}
				}()
				if !bytes.Equal(before, f.evidence()) {
					t.Fatal("signing refusal/rollback altered native evidence")
				}
			})
		}
		for _, name := range []string{"wrong-private-key", "changed-policy", "cancelled-signer"} {
			t.Run(name, func(t *testing.T) {
				f.t = t
				before := f.evidence()
				c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				defer cancel()
				d, err := w.worker.Authorize(c, "ordered68.application.source", q)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				_, err = w.worker.SignOrderedPolicy(c, d, "ordered-key-01", f.keys, func(c context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
					calls++
					key := f.private
					if name == "wrong-private-key" {
						key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
					}
					if name == "changed-policy" {
						input.Policies = append([]policy.CompiledPolicy(nil), input.Policies...)
						input.Policies[0].ID = "changed-policy"
					}
					result, err := policy.SignGatewayPolicyEnvelope(input, key)
					if name == "cancelled-signer" {
						cancel()
					}
					return result, err
				})
				if !errors.Is(err, authorization.ErrInvalid) || calls != 1 || !bytes.Equal(before, f.evidence()) {
					t.Fatal("independent native signer barrier", name, err, calls)
				}
			})
		}
	}})
}

func ordered68ActualSigningProof(f ordered68PolicyAcceptanceContext, w ordered68AcceptanceWorker, q json.RawMessage) []byte {
	f.t.Helper()
	c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	d, err := w.worker.Authorize(c, "ordered68.application.source", q)
	if err != nil {
		f.t.Fatal("real signing authorization", err)
	}
	calls := 0
	_, err = w.worker.SignOrderedPolicy(c, d, "ordered-key-01", f.keys, func(context.Context, policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
		calls++
		return policy.GatewayPolicyEnvelope{}, errors.New("test-only abort after authorized begin")
	})
	if !errors.Is(err, authorization.ErrInvalid) || calls != 1 {
		f.t.Fatal("capture actual authorized begin", err, calls)
	}
	proof := w.trace.take()
	var wire struct{ Body []byte }
	if json.Unmarshal(proof, &wire) != nil || len(wire.Body) == 0 || len(wire.Body) > 32768 {
		f.t.Fatal("actual worker proof bound")
	}
	return proof
}

func ordered68ShortProof(t *testing.T, original, key []byte, lifetime time.Duration) []byte {
	t.Helper()
	var wire struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}
	if json.Unmarshal(original, &wire) != nil {
		t.Fatal("actual proof shape")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(wire.Body, &body) != nil {
		t.Fatal("actual proof body")
	}
	// Preserve every fact/request/revision. Only shorten the genuine fixture
	// proof's validity; the fixture owns the already registered worker key.
	body["expires_at"], _ = json.Marshal(time.Now().Add(lifetime).UnixMilli())
	wire.Body, _ = json.Marshal(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("zasp-authorization-worker-forward-v1\x00"))
	mac.Write(wire.Body)
	wire.MAC = hex.EncodeToString(mac.Sum(nil))
	out, _ := json.Marshal(wire)
	return out
}

func ordered68StoreMAC(proof, input, envelope, key []byte) string {
	digest := func(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("zasp-authorization-ordered68-policy-store-v1\x00worker-forward\x00" + digest(proof) + "\x00" + digest(input) + "\x00" + digest(envelope)))
	return hex.EncodeToString(mac.Sum(nil))
}
func ordered68EnvelopeFromNative(t *testing.T, raw []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	var v struct {
		KeyID    string                  `json:"key_id"`
		O        string                  `json:"organization_id"`
		W        string                  `json:"workspace_id"`
		E        string                  `json:"environment_id"`
		D        string                  `json:"device_id"`
		Sequence uint64                  `json:"sequence"`
		Version  uint64                  `json:"policy_version"`
		Issued   int64                   `json:"issued_at"`
		Expires  int64                   `json:"expires_at"`
		Failure  string                  `json:"failure_mode"`
		Policies []policy.CompiledPolicy `json:"policies"`
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("native begin decoding")
	}
	input := policy.GatewayPolicySigningInput{KeyID: v.KeyID, Binding: policy.GatewayPolicyBinding{OrganizationID: v.O, WorkspaceID: v.W, EnvironmentID: v.E, DeviceID: v.D}, Sequence: v.Sequence, PolicyVersion: v.Version, Now: time.Now().UTC().Truncate(time.Second), IssuedAt: time.Unix(v.Issued, 0).UTC(), ExpiresAt: time.Unix(v.Expires, 0).UTC(), FailureMode: v.Failure, Policies: v.Policies}
	envelope, err := policy.SignGatewayPolicyEnvelope(input, key)
	if err != nil {
		t.Fatal("sign actual native input", err)
	}
	result, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
