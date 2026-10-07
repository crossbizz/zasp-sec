package approvalmaintenance

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type nativeRecorder struct {
	ops      []Operation
	requests []string
	proofs   [][]byte
	result   json.RawMessage
	err      error
}

func (n *nativeRecorder) Invoke(_ context.Context, o Operation, q json.RawMessage, p []byte) (json.RawMessage, error) {
	n.ops = append(n.ops, o)
	n.requests = append(n.requests, string(q))
	n.proofs = append(n.proofs, append([]byte(nil), p...))
	return n.result, n.err
}
func fixtureAdapter(n *nativeRecorder) NativeAdapter {
	return NativeAdapter{n, "worker-one", 30, func() (string, error) { return strings.Repeat("a", 64), nil }}
}
func fixtureReference() Reservation {
	b, _ := json.Marshal(nativeReference{"org_one", "workspace_one", "environment_one", "delivery_one", "worker-one", strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)})
	return Reservation{string(b), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func TestNativeAdapterReserveRetainsExactLeaseBinding(t *testing.T) {
	n := &nativeRecorder{}
	a := fixtureAdapter(n)
	r := fixtureReference()
	n.result = json.RawMessage(`{"found":true,"reference":` + r.Reference + `,"expires_at":"2030-01-01T00:00:00Z"}`)
	got, found, err := a.Reserve(context.Background())
	if err != nil || !found || got != r || len(n.ops) != 1 || n.ops[0] != NativeReserve {
		t.Fatalf("exact reservation refused: %v", err)
	}
	for _, bad := range []string{strings.Replace(string(n.result), "worker-one", "other-worker", 1), strings.Replace(string(n.result), strings.Repeat("a", 64), strings.Repeat("c", 64), 1), strings.Replace(string(n.result), `"lease_token"`, `"Lease_Token"`, 1), strings.Replace(string(n.result), `"found":true`, `"found":true,"found":true`, 1), `{"found":false,"reference":{}}`, `{"found":null}`} {
		n.result = json.RawMessage(bad)
		if _, _, err := a.Reserve(context.Background()); err == nil {
			t.Fatal("malformed/foreign reserve accepted")
		}
	}
}
func TestNativeAdapterClosedOperationsAndCapturedFailure(t *testing.T) {
	n := &nativeRecorder{result: json.RawMessage(`{"captured_proof":"Y2FwdHVyZWQtcmVjZWlwdA==","created":true}`)}
	a := fixtureAdapter(n)
	r := fixtureReference()
	proof := []byte("external-native-signed-decision")
	attempted, err := a.BeginAttempt(context.Background(), r, SecretFailureAttempt, proof)
	if err != nil || string(attempted.CapturedProof) != "captured-receipt" || n.ops[0] != NativeBeginSecretFailure || string(n.proofs[0]) != string(proof) {
		t.Fatal("secret failure attempt changed")
	}
	n.result = json.RawMessage(`{"transition":"retryable"}`)
	if a.Fail(context.Background(), r, attempted) != nil || n.ops[1] != NativeFail || string(n.proofs[1]) != "captured-receipt" {
		t.Fatal("captured fail changed")
	}
	n.result = json.RawMessage(`{"transition":"paused"}`)
	if a.PauseDenied(context.Background(), r) != nil || n.ops[2] != NativePauseDenied || len(n.proofs[2]) != 0 {
		t.Fatal("pause consumed forward attempt")
	}
}
func TestNativeAdapterRefusesInputsBeforeNativeCalls(t *testing.T) {
	n := &nativeRecorder{}
	a := fixtureAdapter(n)
	r := fixtureReference()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := a.Reserve(ctx); e == nil {
		t.Fatal("canceled context accepted")
	}
	if a.Complete(context.Background(), r, Attempt{}) == nil {
		t.Fatal("empty captured proof accepted")
	}
	if _, e := a.BeginAttempt(context.Background(), r, AttemptKind(99), []byte("p")); e == nil {
		t.Fatal("unknown operation accepted")
	}
	n.result = json.RawMessage(`{"transition":"released"}`)
	r.Reference = strings.Replace(r.Reference, "worker-one", "foreign-worker", 1)
	if a.ReleaseUnattempted(context.Background(), r) == nil {
		t.Fatal("foreign reservation accepted")
	}
	if len(n.ops) != 0 {
		t.Fatal("invalid input reached native caller")
	}
}
func TestNativeAdapterRejectsAmbiguousAttemptWithoutOtherCall(t *testing.T) {
	n := &nativeRecorder{result: json.RawMessage(`{"captured_proof":"","created":true}`)}
	a := fixtureAdapter(n)
	if _, e := a.BeginAttempt(context.Background(), fixtureReference(), DeliveryAttempt, []byte("proof")); e == nil {
		t.Fatal("empty begin response accepted")
	}
	if len(n.ops) != 1 || n.ops[0] != NativeBeginDelivery {
		t.Fatal("ambiguous begin retried/released")
	}
}
func TestNativeAdapterTypedResultGrammar(t *testing.T) {
	n := &nativeRecorder{}
	a := fixtureAdapter(n)
	r := fixtureReference()
	for _, raw := range []string{`{"Transition":"delivered"}`, `{"transition":"delivered","transition":"delivered"}`, `{"transition":"delivered","other":true}`, `{"transition":"retryable"}`, `{"transition":"delivered"} {}`} {
		n.result = json.RawMessage(raw)
		if a.Complete(context.Background(), r, Attempt{[]byte("receipt")}) == nil {
			t.Fatal("nonclosed complete accepted")
		}
	}
}

func TestNativeAdapterReplayedBeginNeverAuthorizesSend(t *testing.T) {
	n := &nativeRecorder{result: json.RawMessage(`{"captured_proof":"Y2FwdHVyZWQtcmVjZWlwdA==","created":false}`)}
	a := fixtureAdapter(n)
	if _, e := a.BeginAttempt(context.Background(), fixtureReference(), DeliveryAttempt, []byte("proof")); e == nil {
		t.Fatal("replayed receipt became new invocation authority")
	}
	if len(n.ops) != 1 || n.ops[0] != NativeBeginDelivery {
		t.Fatal("ambiguous replay released or retried")
	}
}
