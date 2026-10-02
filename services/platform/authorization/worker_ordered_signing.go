package authorization

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// OrderedPolicySigner is a local, bounded key-load/sign operation. The native
// signing transaction must authorize its exact input before calling it.
type OrderedPolicySigner func(context.Context, policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error)

type orderedPolicyTransaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// SignOrderedPolicy is the sole local signing entry. The SQL begin and store
// are fixed, retain one transaction's locks, and consume the original opaque
// decision and request unchanged. No FGA or provider call occurs here.
func (e *WorkerExecutor) SignOrderedPolicy(ctx context.Context, decision WorkerDecision, keyID string, keys policy.GatewayPolicyKeys, sign OrderedPolicySigner) (json.RawMessage, error) {
	purpose, ok := orderedSigningPurpose(decision.operation)
	if e == nil || e.pool == nil || e.key == nil || e.adapter || e.discovery || !ok || e.key.purpose != purpose || ctx == nil || ctx.Err() != nil || sign == nil || !keys.HasKeyID(keyID) || len(decision.envelope) == 0 || len(decision.envelope) > 65536 || len(decision.request) > 32768 || !json.Valid(decision.request) {
		return nil, ErrInvalid
	}
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, workerDatabaseError(err)
	}
	return e.signOrderedPolicyTransaction(ctx, tx, decision, keyID, keys, sign)
}

func (e *WorkerExecutor) signOrderedPolicyTransaction(ctx context.Context, tx orderedPolicyTransaction, decision WorkerDecision, keyID string, keys policy.GatewayPolicyKeys, sign OrderedPolicySigner) (json.RawMessage, error) {
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(decision.envelope)); err != nil {
		return nil, workerDatabaseError(err)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered68_policy_begin($1,$2::jsonb,$3)`, string(decision.operation), decision.request, keyID).Scan(&raw); err != nil {
		return nil, workerDatabaseError(err)
	}
	envelope, mac, err := e.signOrderedPolicyInput(ctx, decision, raw, keyID, keys, sign, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered68_policy_store($1,$2::jsonb,$3,$4::bytea,$5::bytea,$6)`, string(decision.operation), decision.request, keyID, raw, envelope, mac).Scan(&result); err != nil {
		return nil, workerDatabaseError(err)
	}
	// Retained native delivery responses include composition provenance and
	// have an8MiB bound, separate from the signed envelope's1MiB bound.
	if ctx.Err() != nil || len(result) > 8*1024*1024 || !json.Valid(result) || bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
		return nil, ErrInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, workerDatabaseError(err)
	}
	return result, nil
}

// The native begin result is a fixed14-field object. Timestamps are integral
// Unix seconds (the gateway signature format requires whole UTC seconds).
// PostgreSQL's exact JSON bytes, not a Go reserialization, enter the store MAC.
type orderedPolicyInput struct {
	ContractVersion int                     `json:"contract_version"`
	Operation       WorkerOperation         `json:"operation"`
	DecisionDigest  string                  `json:"decision_digest"`
	KeyID           string                  `json:"key_id"`
	OrganizationID  string                  `json:"organization_id"`
	WorkspaceID     string                  `json:"workspace_id"`
	EnvironmentID   string                  `json:"environment_id"`
	DeviceID        string                  `json:"device_id"`
	Sequence        uint64                  `json:"sequence"`
	PolicyVersion   uint64                  `json:"policy_version"`
	IssuedAt        int64                   `json:"issued_at"`
	ExpiresAt       int64                   `json:"expires_at"`
	FailureMode     string                  `json:"failure_mode"`
	Policies        []policy.CompiledPolicy `json:"policies"`
}

func orderedSigningPurpose(operation WorkerOperation) (WorkerPurpose, bool) {
	switch operation {
	case "ordered68.application.source", "ordered68.delivery.apply.store":
		return WorkerForward, true
	case "ordered68.cleanup.source", "ordered68.cleanup.renew", "ordered68.delivery.cleanup.store":
		return CapturedCompensation, true
	default:
		return "", false
	}
}

func (e *WorkerExecutor) signOrderedPolicyInput(ctx context.Context, decision WorkerDecision, raw []byte, keyID string, keys policy.GatewayPolicyKeys, sign OrderedPolicySigner, now time.Time) (json.RawMessage, string, error) {
	purpose, supported := orderedSigningPurpose(decision.operation)
	if e == nil || e.key == nil || !supported || e.key.purpose != purpose || ctx == nil || ctx.Err() != nil || sign == nil || !keys.HasKeyID(keyID) || len(decision.envelope) == 0 {
		return nil, "", ErrInvalid
	}
	raw = append([]byte(nil), raw...)
	input, err := decodeOrderedPolicyInput(raw, decision, keyID, now)
	if err != nil {
		return nil, "", err
	}
	envelope, err := sign(ctx, input)
	if err != nil || ctx.Err() != nil {
		return nil, "", ErrInvalid
	}
	// Decode the retained bytes again so the callback cannot mutate the expected
	// policy slices through the input it received.
	input, err = decodeOrderedPolicyInput(raw, decision, keyID, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return nil, "", err
	}
	verified, err := policy.VerifyGatewayPolicyEnvelope(envelope, keys, input.Binding, input.Now)
	if err != nil || verified.KeyID != input.KeyID || verified.Sequence != input.Sequence || verified.PolicyVersion != input.PolicyVersion || !verified.IssuedAt.Equal(input.IssuedAt) || !verified.ExpiresAt.Equal(input.ExpiresAt) || verified.FailureMode != input.FailureMode {
		return nil, "", ErrInvalid
	}
	sort.Slice(input.Policies, func(i, j int) bool { return input.Policies[i].ID < input.Policies[j].ID })
	expectedPolicies, err := json.Marshal(input.Policies)
	actualPolicies, marshalErr := json.Marshal(verified.Policies)
	if err != nil || marshalErr != nil || !bytes.Equal(expectedPolicies, actualPolicies) {
		return nil, "", ErrInvalid
	}
	encoded, err := json.Marshal(verified)
	if err != nil || len(encoded) > 1024*1024 || ctx.Err() != nil {
		return nil, "", ErrInvalid
	}
	proofDigest, inputDigest, envelopeDigest := sha256.Sum256(decision.envelope), sha256.Sum256(raw), sha256.Sum256(encoded)
	mac := hmac.New(sha256.New, e.key.key[:])
	_, _ = mac.Write([]byte("zasp-authorization-ordered68-policy-store-v1\x00" + string(purpose) + "\x00" + hex.EncodeToString(proofDigest[:]) + "\x00" + hex.EncodeToString(inputDigest[:]) + "\x00" + hex.EncodeToString(envelopeDigest[:])))
	return encoded, hex.EncodeToString(mac.Sum(nil)), nil
}

func decodeOrderedPolicyInput(raw []byte, decision WorkerDecision, keyID string, now time.Time) (policy.GatewayPolicySigningInput, error) {
	var wire orderedPolicyInput
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	shape := json.NewDecoder(bytes.NewReader(raw))
	shape.UseNumber()
	if count, err := orderedSigningJSONValue(shape, 0); err != nil || count != 14 {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	if _, err := shape.Token(); err != io.EOF {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	digest := sha256.Sum256(decision.envelope)
	if wire.ContractVersion != 1 || wire.Operation != decision.operation || wire.DecisionDigest != hex.EncodeToString(digest[:]) || wire.KeyID != keyID || wire.Policies == nil {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	input := policy.GatewayPolicySigningInput{KeyID: keyID, Binding: policy.GatewayPolicyBinding{OrganizationID: wire.OrganizationID, WorkspaceID: wire.WorkspaceID, EnvironmentID: wire.EnvironmentID, DeviceID: wire.DeviceID}, Sequence: wire.Sequence, PolicyVersion: wire.PolicyVersion, Now: now, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(), FailureMode: wire.FailureMode, Policies: wire.Policies}
	if policy.ValidateGatewayPolicySigningInput(input) != nil {
		return policy.GatewayPolicySigningInput{}, ErrInvalid
	}
	return input, nil
}

// Detect duplicate/null fields before typed decoding can discard them. Depth
// and total bytes are bounded; no caller-supplied path or SQL is interpreted.
func orderedSigningJSONValue(decoder *json.Decoder, depth int) (int, error) {
	if depth > 16 {
		return 0, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return 0, ErrInvalid
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return 0, nil
	}
	count := 0
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return 0, ErrInvalid
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return 0, ErrInvalid
			}
			seen[key] = true
			if _, err := orderedSigningJSONValue(decoder, depth+1); err != nil {
				return 0, err
			}
			count++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return 0, ErrInvalid
		}
	case '[':
		for decoder.More() {
			if _, err := orderedSigningJSONValue(decoder, depth+1); err != nil {
				return 0, err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return 0, ErrInvalid
		}
	default:
		return 0, ErrInvalid
	}
	return count, nil
}
