package approvalmaintenance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// Operation is a closed native call, never a SQL string or caller-chosen name.
// NativeCaller must supply the independently registered role, transaction,
// signed forward decision and captured receipt checks. This adapter issues none.
type Operation uint8

const (
	NativeReserve Operation = iota + 1
	NativePauseDenied
	NativeRelease
	NativeBeginDelivery
	NativeBeginSecretFailure
	NativeComplete
	NativeFail
	NativeBeforeSecrets
	NativeBeforeDelivery
	NativeBeforeSecretFailure
)

type NativeCaller interface {
	Invoke(context.Context, Operation, json.RawMessage, []byte) (json.RawMessage, error)
}
type NativeAdapter struct {
	Caller       NativeCaller
	Owner        string
	LeaseSeconds int
	Token        func() (string, error)
}
type nativeReference struct {
	Organization  string `json:"organization_id"`
	Workspace     string `json:"workspace_id"`
	Environment   string `json:"environment_id"`
	Delivery      string `json:"delivery_id"`
	Owner         string `json:"lease_owner"`
	Token         string `json:"lease_token"`
	PayloadDigest string `json:"payload_digest"`
}

func (a NativeAdapter) Reserve(ctx context.Context) (Reservation, bool, error) {
	if !a.valid(ctx) || a.Token == nil {
		return Reservation{}, false, ErrConfiguration
	}
	token, err := a.Token()
	if err != nil || !hex64(token) {
		return Reservation{}, false, ErrUnavailable
	}
	request, _ := json.Marshal(struct {
		Owner   string `json:"owner"`
		Token   string `json:"token"`
		Seconds int    `json:"seconds"`
	}{a.Owner, token, a.LeaseSeconds})
	raw, err := a.Caller.Invoke(ctx, NativeReserve, request, nil)
	if err != nil || ctx.Err() != nil {
		return Reservation{}, false, ErrUnavailable
	}
	var found struct {
		Found bool `json:"found"`
	}
	if exactDecode(raw, &found, "found") == nil && !found.Found {
		return Reservation{}, false, nil
	}
	var wire struct {
		Found     bool            `json:"found"`
		Reference nativeReference `json:"reference"`
		Expires   time.Time       `json:"expires_at"`
	}
	if exactDecode(raw, &wire, "found", "reference", "expires_at") != nil || !wire.Found || !validReference(wire.Reference) || wire.Reference.Owner != a.Owner || wire.Reference.Token != token || wire.Expires.IsZero() {
		return Reservation{}, false, ErrUnavailable
	}
	var refRaw map[string]json.RawMessage
	_ = json.Unmarshal(raw, &refRaw)
	var r nativeReference
	if exactDecode(refRaw["reference"], &r, "organization_id", "workspace_id", "environment_id", "delivery_id", "lease_owner", "lease_token", "payload_digest") != nil {
		return Reservation{}, false, ErrUnavailable
	}
	ref, _ := json.Marshal(wire.Reference)
	return Reservation{string(ref), wire.Expires.UTC()}, true, nil
}
func (a NativeAdapter) PauseDenied(ctx context.Context, r Reservation) error {
	return a.transition(ctx, NativePauseDenied, r, nil, "paused")
}
func (a NativeAdapter) ReleaseUnattempted(ctx context.Context, r Reservation) error {
	return a.transition(ctx, NativeRelease, r, nil, "released")
}
func (a NativeAdapter) Complete(ctx context.Context, r Reservation, t Attempt) error {
	return a.transition(ctx, NativeComplete, r, t.CapturedProof, "delivered")
}
func (a NativeAdapter) Fail(ctx context.Context, r Reservation, t Attempt) error {
	if !a.valid(ctx) || len(t.CapturedProof) == 0 {
		return ErrUnavailable
	}
	raw, err := a.invoke(ctx, NativeFail, r, t.CapturedProof)
	if err != nil {
		return err
	}
	var result struct {
		Transition string `json:"transition"`
	}
	if exactDecode(raw, &result, "transition") != nil || (result.Transition != "retryable" && result.Transition != "exhausted") {
		return ErrUnavailable
	}
	return nil
}
func (a NativeAdapter) BeginAttempt(ctx context.Context, r Reservation, k AttemptKind, proof []byte) (Attempt, error) {
	op := NativeBeginDelivery
	if k == SecretFailureAttempt {
		op = NativeBeginSecretFailure
	} else if k != DeliveryAttempt {
		return Attempt{}, ErrUnavailable
	}
	if len(proof) == 0 || len(proof) > 65536 {
		return Attempt{}, ErrUnavailable
	}
	raw, err := a.invoke(ctx, op, r, proof)
	if err != nil {
		return Attempt{}, err
	}
	var result struct {
		Proof   []byte `json:"captured_proof"`
		Created bool   `json:"created"`
	}
	if exactDecode(raw, &result, "captured_proof", "created") != nil || !result.Created || len(result.Proof) == 0 || len(result.Proof) > 65536 {
		return Attempt{}, ErrUnavailable
	}
	return Attempt{append([]byte(nil), result.Proof...)}, nil
}
func (a NativeAdapter) Authorize(ctx context.Context, r Reservation, p Phase) ([]byte, error) {
	var op Operation
	switch p {
	case BeforeSecrets:
		op = NativeBeforeSecrets
	case BeforeDelivery:
		op = NativeBeforeDelivery
	case BeforeSecretFailure:
		op = NativeBeforeSecretFailure
	default:
		return nil, ErrUnavailable
	}
	raw, err := a.invoke(ctx, op, r, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Proof []byte `json:"forward_proof"`
	}
	if exactDecode(raw, &result, "forward_proof") != nil || len(result.Proof) == 0 || len(result.Proof) > 65536 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), result.Proof...), nil
}
func (a NativeAdapter) transition(ctx context.Context, op Operation, r Reservation, proof []byte, want string) error {
	if (op == NativeComplete) && len(proof) == 0 {
		return ErrUnavailable
	}
	raw, err := a.invoke(ctx, op, r, proof)
	if err != nil {
		return err
	}
	var result struct {
		Transition string `json:"transition"`
	}
	if exactDecode(raw, &result, "transition") != nil || result.Transition != want {
		return ErrUnavailable
	}
	return nil
}
func (a NativeAdapter) invoke(ctx context.Context, op Operation, r Reservation, proof []byte) (json.RawMessage, error) {
	if !a.valid(ctx) || len(proof) > 65536 {
		return nil, ErrUnavailable
	}
	var ref nativeReference
	if exactDecode([]byte(r.Reference), &ref, "organization_id", "workspace_id", "environment_id", "delivery_id", "lease_owner", "lease_token", "payload_digest") != nil || !validReference(ref) || ref.Owner != a.Owner || r.ExpiresAt.IsZero() {
		return nil, ErrUnavailable
	}
	raw, err := a.Caller.Invoke(ctx, op, json.RawMessage(r.Reference), proof)
	if err != nil {
		if err == ErrDenied {
			return nil, ErrDenied
		}
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return raw, nil
}
func (a NativeAdapter) valid(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && !missing(a.Caller) && len(a.Owner) >= 3 && len(a.Owner) <= 128 && strings.TrimSpace(a.Owner) == a.Owner && !strings.ContainsAny(a.Owner, "\x00\r\n") && a.LeaseSeconds >= 15 && a.LeaseSeconds <= 60
}
func validReference(r nativeReference) bool {
	return nonemptyID(r.Organization) && nonemptyID(r.Workspace) && nonemptyID(r.Environment) && nonemptyID(r.Delivery) && len(r.Owner) >= 3 && len(r.Owner) <= 128 && strings.TrimSpace(r.Owner) == r.Owner && !strings.ContainsAny(r.Owner, "\x00\r\n") && hex64(r.Token) && strings.HasPrefix(r.PayloadDigest, "sha256:") && hex64(strings.TrimPrefix(r.PayloadDigest, "sha256:"))
}
func nonemptyID(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func hex64(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Check exact case and duplicate keys before typed decoding; encoding/json's
// case-insensitive struct aliases alone would not implement a closed grammar.
func exactDecode(raw []byte, out any, keys ...string) error {
	if len(raw) == 0 || len(raw) > 131072 {
		return ErrUnavailable
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return ErrUnavailable
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		k, ok := key.(string)
		if err != nil || !ok || !allowed[k] || seen[k] {
			return ErrUnavailable
		}
		seen[k] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrUnavailable
		}
	}
	if _, err = dec.Token(); err != nil || len(seen) != len(keys) {
		return ErrUnavailable
	}
	if _, err = dec.Token(); err != io.EOF {
		return ErrUnavailable
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if typed.Decode(out) != nil {
		return ErrUnavailable
	}
	return nil
}
